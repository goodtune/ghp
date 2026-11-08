# Git Credential Helper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `ghp auth git-credential` (a git credential helper that mints short-lived, single-repository `gha_`/`ghx_` tokens and caches them under the strongest local key protector) and `ghp auth setup-git` (the server-side bare-name fix it originally included was superseded by #358).

**Architecture:** `internal/securestore` wraps a random data-encryption key (DEK) with one of four protector tiers (tpm > dpapi > keychain > file). `internal/gitcred` holds everything else that is testable without cobra: the git credential protocol, path parsing, the encrypted, file-locked cache, a small ghp API client, app/installation/scope resolution, and `Run`, which executes one helper operation and returns an exit code. `cmd/ghp/gitcredential.go` only resolves flags/env, wires the two-phase CLI config loading (non-interactive dotvault), and calls `gitcred.Run`. Task 7 (the server-side bare-name fix) was superseded by #358 on main.

**Tech Stack:** Go (go.mod `go 1.26.0`), cobra, `github.com/google/go-tpm` v0.9.8 (`tpm2`, `tpm2/transport/{linuxtpm,windowstpm,linuxudstpm}`), `golang.org/x/sys` v0.49.0 (`unix.Flock`, `windows.LockFileEx`, `windows.CryptProtectData`), `crypto/aes` + `crypto/cipher` (GCM), `/usr/bin/security` on macOS, `swtpm` in CI.

**Spec:** `docs/superpowers/specs/2026-11-08-git-credential-helper-design.md` (binding, as of commit 7f18a35). "§N" below means the spec's Decision N; "§3.4" means step 4 of Decision 3. Read it with this plan.

## Global Constraints

- `CGO_ENABLED=0`, pure Go. Every new file compiles for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64. Build-tagged files come in complete sets (a real file plus a stub) so every package builds on every target.
- No new modules. `github.com/google/go-tpm v0.9.8` and `golang.org/x/sys v0.49.0` move from indirect to direct requirements in the first task that imports each (Task 3 for x/sys, Task 8 for go-tpm); nothing else changes in `go.mod`.
- Compare owner, repository, login, host and app names with `asciiutil.EqualFold`; lower-case with `asciiutil.ToLower`. Never `strings.EqualFold`/`strings.ToLower` on those (#317).
- Never write a token to stderr, logs, errors, or `status` output. `status` shows at most the first 8 characters followed by `...`. Error texts name keys, never values.
- Every helper failure is exactly one stderr line, prefixed `ghp git-credential: `, naming the missing thing and the remedy; `\r` and `\n` inside a message become spaces. Stdout stays empty on failure.
- The cache lock is never held across a network call (§3.4, §3.5, §4).
- Exact values: env vars `GHP_GIT_CM_APP`, `GHP_GIT_CM_TYPE`, `GHP_GIT_CM_SCOPES`, `GHP_GIT_CM_TTL`, `GHP_GIT_CM_CACHE_BACKEND`; flags `--app`, `--type`, `--scopes`, `--ttl`, `--cache-backend`, `--host` (repeatable, default `github.com`); defaults type `agent`, scopes `contents:write`, ttl `1h`, cache backend `auto`; precedence flag > env > default.
- Cache: directory `filepath.Join(filepath.Dir(userCLIConfigPath()), "git-credential")`; files `cache.enc`, `cache.lock`, `tier`; directory `0700`, files `0600` (chmod'ed on every open); writes via temp file + rename; lock timeout `10 s`; `minRemaining = 5m`; envelope `version: 1`; tier order `tpm` > `dpapi` > `keychain` > `file`.
- Cache key = SHA-256 over server URL (trailing `/` trimmed), identity (hex SHA-256 of phase A's `user_token`, else `dotvault`), type, app selector as given, `asciiutil.ToLower(owner/repo)`, and the normalised **requested** scopes.
- `session_id` is `git-credential:<hostname>`, truncated to 128 bytes on a UTF-8 boundary. Username is `x-access-token`. Output never contains `quit=true`.
- macOS keychain service name `ghp-git-credential`; the secret goes to `/usr/bin/security -i` on stdin, never in argv.
- Shell quoter for the gitconfig helper line: a word is unchanged only when it matches `^[A-Za-z0-9@%+=:,./_-]+$`, else it is single-quoted with `'` escaped as `'\''`; values containing `\n`, `\r` or NUL are rejected.
- Tests: colocated, table-driven with `t.Run`, `httptest` fakes for every HTTP API, no real TPM/keychain/DPAPI except the gated swtpm test (`GHP_TEST_SWTPM`, `GHP_TEST_SWTPM_CTRL`) and platform-native unit tests that run only on their own OS.
- Never `git add -A`; every commit step lists its files.

## Review Focus

1. **Windows git or a proxy wrapper sends CRLF line endings.** The request must parse exactly as with LF. Test: `TestParseRequest/crlf` (Task 2).
2. **Path that is percent-encoded, has spaces, `..`, or more than two segments** (`own%2Fer/repo.git`, `../x.git`, `o/r.git/info/refs`). The first two must be refused before any API call; the third must take the first two segments. Test: `TestParseTarget` (Task 2), `TestRun_GetBadPath` (Task 5).
3. **Two git processes race: one `erase`s a stale token while another has already minted a fresh one under the same key.** The fresh entry must survive. Test: `TestRun_EraseKeepsNewerToken` (Task 5).
4. **The `tier` file is empty, has a trailing newline, or holds garbage.** `"file\n"` must read as `file`; garbage must read as the strongest tier (`tpm`) so it can never permit a downgrade. Test: `TestCache_TierFileParsing` (Task 3).
5. **The cache directory cannot be created (HOME on a read-only mount, or a file where the directory should be).** `get` must still print a freshly minted token, warn once, exit 0. Test: `TestRun_GetCacheUnusableStillReturnsToken` (Task 5).

## Dependencies

| Wave | Tasks (hard dependencies) |
|---|---|
| 1 | T1, T2, T7 |
| 2 | T3 (T1, T2), T4 (T2) |
| 3 | T5 (T3, T4), T8 (T1) |
| 4 | T6 (T5), T9 (T8) |
| 5 | T10 (T6, T9) |
| 6 | T11 (T10) |
| 7 | T12 (T8, T11) |
| 8 | T13 (T11) |

## File Structure

```
internal/securestore/
  securestore.go        KeyProtector, Tier, Protectors (ordering, Available, Select, AvailableAtLeast), Strength, errors, Default
  file.go               file tier (wrapped key = DEK)
  tpm.go                tpm tier: probe, seal (Wrap), unseal (Unwrap), error classification, retry
  tpm_open_linux.go     openTPM: /dev/tpmrm0 then /dev/tpm0          (//go:build linux)
  tpm_open_windows.go   openTPM: windowstpm.Open (TBS)                (//go:build windows)
  tpm_open_other.go     openTPM: ErrUnavailable                       (//go:build !linux && !windows)
  dpapi_windows.go      dpapi tier                                    (//go:build windows)
  dpapi_other.go        dpapi stub, always unavailable                (//go:build !windows)
  keychain_darwin.go    keychain tier via /usr/bin/security           (//go:build darwin)
  keychain_other.go     keychain stub, always unavailable             (//go:build !darwin)
  securestore_test.go, tpm_test.go, tpm_swtpm_test.go (//go:build !windows),
  dpapi_windows_test.go, keychain_darwin_test.go
internal/gitcred/
  protocol.go           Request, Credential, ParseRequest, WriteCredential
  target.go             Target, ParseTarget
  cache.go              Entry, KeyInput, CacheKey, IdentityFor, NormalizeScopes, Cache, Session
  lock_unix.go          tryLock/unlock via unix.Flock                 (//go:build unix)
  lock_windows.go       tryLock/unlock via windows.LockFileEx         (//go:build windows)
  client.go             Client, App, Installation, MintRequest, MintedToken, APIError
  resolve.go            Settings, Plan, ParseSettings, Resolve, SelectApp, SelectInstallation, EffectiveScopes
  helper.go             Config, Options, Run (get/store/erase/status/clear), SessionID
  *_test.go             one per source file
cmd/ghp/
  gitcredential.go      git-credential + setup-git cobra commands, flag/env resolution, phase A/B loaders
  gitcredential_test.go
  dotvault.go           + AuthenticateCached in dotvaultReader, applyDotvaultCached, loadCLIConfigCached
  auth.go               warning writer threaded through config loading; register the two subcommands
  main.go               exitCodeError handling
  token.go, apptoken.go asciiutil.EqualFold at three sites
(Task 7, internal/github/app.go, was superseded by #358 on main)
Makefile, .github/workflows/test.yml, docs/features/git-credential-helper.md,
docs/cli/auth.md, docs/cli/index.md, mkdocs.yml, CLAUDE.md
```

---

### Task 1: securestore core and the file tier

**Files:**
- Create: `internal/securestore/securestore.go`, `internal/securestore/file.go`
- Test: `internal/securestore/securestore_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces (package `securestore`):
  ```go
  type KeyProtector interface {
      Name() string
      Wrap(dek []byte) ([]byte, error)
      Unwrap(wrapped []byte) ([]byte, error)
  }
  const (TierTPM = "tpm"; TierDPAPI = "dpapi"; TierKeychain = "keychain"; TierFile = "file"; PreferenceAuto = "auto")
  var (
      ErrUnavailable = errors.New("securestore: protector unavailable")
      ErrUnknownTier = errors.New("securestore: unknown tier")
      ErrForeignKey  = errors.New("securestore: wrapped key was made on another device")
  )
  func Strength(name string) int // tpm 3, dpapi 2, keychain 1, file 0, anything else -1
  type Tier struct {
      Name  string
      Probe func() error                     // nil error = usable now
      Open  func(scope string) KeyProtector  // scope = cache directory path (keychain uses it)
  }
  type Protectors struct{ /* tiers sorted strongest first */ }
  func NewProtectors(tiers ...Tier) *Protectors // sorts by Strength desc; panics on Strength(name) < 0
  func Default() *Protectors                    // this task: NewProtectors(FileTier()); T8 and T9 add tiers
  func FileTier() Tier
  func (p *Protectors) Names() []string
  func (p *Protectors) Available(name string) error                       // ErrUnknownTier, or probe error wrapped with ErrUnavailable
  func (p *Protectors) Open(name, scope string) (KeyProtector, error)       // no probe; ErrUnknownTier
  func (p *Protectors) Select(preference, scope string) (KeyProtector, error) // "" or "auto": first available; else Available(name) then Open
  func (p *Protectors) AvailableAtLeast(minTier, scope string) []KeyProtector // every available tier with Strength >= Strength(minTier) ("" = all), strongest first
  func Available(name string) error                           // Default().Available
  func Select(preference, scope string) (KeyProtector, error) // Default().Select
  ```
  `Select` takes `scope` in addition to the spec's `Select(preference)` because the keychain account is derived from the cache directory.

- [ ] **Step 1: Write the failing tests**

In `securestore_test.go` define a test-only `xorProtector{name string}` (Wrap/Unwrap XOR every byte with `0x5a`, returning a new slice) and `fakeTier(name string, probeErr error) Tier`. Tests:

```go
func TestStrength(t *testing.T) // table: "tpm"→3 "dpapi"→2 "keychain"→1 "file"→0 "vault"→-1 ""→-1
func TestNewProtectors_SortsStrongestFirst(t *testing.T) {
    p := NewProtectors(fakeTier("file", nil), fakeTier("tpm", nil), fakeTier("keychain", nil))
    // p.Names() == []string{"tpm", "keychain", "file"}
}
func TestSelect(t *testing.T) // table over (tiers, preference) → (want name | want errors.Is):
    // auto, tpm probe fails, keychain ok        → "keychain"
    // "" (empty) behaves as auto                → "keychain"
    // "tpm" with failing probe                  → errors.Is(err, ErrUnavailable)
    // "vault"                                   → errors.Is(err, ErrUnknownTier)
    // "file" explicitly, file ok                → "file"
func TestAvailableAtLeast(t *testing.T) // names of the returned protectors:
    // min "keychain"; tpm, keychain fail; file ok → []
    // min "";         tpm fails; keychain, file ok → ["keychain", "file"]
    // min "file";     all ok                       → ["tpm", "keychain", "file"]
    // min "tpm";      all ok                       → ["tpm"]
func TestFileProtector_RoundTrip(t *testing.T) {
    dek := bytes.Repeat([]byte{7}, 32)
    p := FileTier().Open("")
    w, _ := p.Wrap(dek); dek[0] = 9
    // w[0] == 7 (Wrap copied); got, _ := p.Unwrap(w); bytes.Equal(got, w); p.Name() == "file"
    // FileTier().Probe() == nil
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/securestore/ -v`
Expected: FAIL (package does not compile: undefined `NewProtectors`, `Strength`, ...).

- [ ] **Step 3: Implement `securestore.go` and `file.go`**

`Available` wraps probe errors as `fmt.Errorf("%w: %s: %v", ErrUnavailable, name, err)` unless the error already `errors.Is` `ErrUnavailable` (then return it unchanged). `fileProtector.Wrap`/`Unwrap` return copies. Package doc states the file tier protects nothing beyond file permissions.

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/securestore/ -v && go vet ./internal/securestore/`
Expected: PASS, vet clean.

- [ ] **Step 5: Commit**

```bash
git add internal/securestore/securestore.go internal/securestore/file.go internal/securestore/securestore_test.go
git commit -m "feat(securestore): key protector tiers with file fallback"
```

---

### Task 2: git credential protocol and repository target

**Files:**
- Create: `internal/gitcred/protocol.go`, `internal/gitcred/target.go`
- Test: `internal/gitcred/protocol_test.go`, `internal/gitcred/target_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces (package `gitcred`):
  ```go
  type Request struct{ Protocol, Host, Path, Username, Password string }
  func ParseRequest(r io.Reader) (Request, error)
  type Credential struct {
      Username string
      Password string
      Expiry   time.Time // zero → no password_expiry_utc line
  }
  func WriteCredential(w io.Writer, c Credential) error
  type Target struct{ Owner, Repo string }
  func (t Target) FullName() string // "Owner/Repo", case preserved
  var (
      ErrNotHTTPS = errors.New("only https remotes are supported")
      ErrNoPath   = errors.New("git did not send a repository path")
      ErrBadPath  = errors.New("repository path is not owner/repo")
  )
  func ParseTarget(req Request) (Target, error)
  ```

Error texts name only the key, never the value: no `=` → `invalid credential line (no "=")`; NUL → `invalid value for key "path"`; over the limit → `credential request larger than 64 KiB`; `WriteCredential` with `\n`/`\r`/NUL in a value → `invalid value for key "password"`.

- [ ] **Step 1: Write the failing tests**

```go
func TestParseRequest(t *testing.T) // table of name, input, want Request / wantErr:
    // "basic":      "protocol=https\nhost=github.com\npath=goodtune/ghp.git\n\n" → {https, github.com, goodtune/ghp.git}
    // "eof":        same without the trailing blank line                         → same
    // "crlf":       "protocol=https\r\nhost=github.com\r\npath=goodtune/ghp.git\r\n\r\n" → same as basic
    // "stops at blank line": "protocol=https\n\nhost=evil\n"                    → Host == ""
    // "unknown keys ignored": "capability[]=authtype\nwwwauth[]=Basic\nprotocol=https\n" → Protocol "https"
    // "last wins":  "host=a\nhost=b\n"                                           → Host "b"
    // "password":   "username=x-access-token\npassword=gha_x\n"                  → Username, Password set
    // "no equals":  "garbage\n"                                                  → error
    // "nul":        "path=secretvalue\x00\n" → error; err.Error() does not contain "secretvalue"
    // "oversize":   65 KiB of "x=..." lines                                      → error
func TestWriteCredential(t *testing.T) {
    var b bytes.Buffer
    _ = WriteCredential(&b, Credential{Username: "x-access-token", Password: "ghx_abc", Expiry: time.Unix(1767225600, 0)})
    // b.String() == "username=x-access-token\npassword=ghx_abc\npassword_expiry_utc=1767225600\n"
    // zero Expiry → no "password_expiry_utc" line
    // Password "sec\nret" or "sec\x00ret" → error not containing "sec", nothing written
    // output never contains "quit"
}
func TestParseTarget(t *testing.T) // table: Request{Protocol, Path} → Target / error
    // https "goodtune/ghp.git"           → {goodtune ghp}
    // https "/goodtune/ghp.git"          → {goodtune ghp}
    // https "goodtune/ghp"               → {goodtune ghp}
    // https "goodtune/ghp.git/info/refs" → {goodtune ghp}
    // https "GoodTune/GHP.git"           → {GoodTune GHP}  (FullName "GoodTune/GHP")
    // http  "goodtune/ghp.git"           → ErrNotHTTPS
    // https ""                           → ErrNoPath
    // https "goodtune"                   → ErrNoPath
    // https "goodtune/.git"              → ErrBadPath
    // https "../x.git"                   → ErrBadPath
    // https "own%2Fer/repo.git"          → ErrBadPath
    // https "own er/repo.git"            → ErrBadPath
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/gitcred/ -run 'TestParseRequest|TestWriteCredential|TestParseTarget' -v`
Expected: FAIL (undefined symbols).

- [ ] **Step 3: Implement `protocol.go` and `target.go`**

`ParseRequest`: read through `io.LimitReader(r, 64<<10+1)` with `bufio.Scanner`; error if the limit is hit; strip one trailing `\r` per line; stop at the first empty line; split on the first `=`; ignore keys ending in `[]` and unknown keys. `ParseTarget`: require `Protocol == "https"`, trim one leading `/`, split on `/`, need ≥ 2 segments (else `ErrNoPath`), strip one trailing `.git` from the repo, then require each of owner/repo to match `^[A-Za-z0-9._-]+$` and not be `.` or `..` (else `ErrBadPath`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/gitcred/ -run 'TestParseRequest|TestWriteCredential|TestParseTarget' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/gitcred/protocol.go internal/gitcred/target.go internal/gitcred/protocol_test.go internal/gitcred/target_test.go
git commit -m "feat(gitcred): git credential protocol and owner/repo parsing"
```

---

### Task 3: encrypted, locked token cache with tier state

**Files:**
- Create: `internal/gitcred/cache.go`, `internal/gitcred/lock_unix.go`, `internal/gitcred/lock_windows.go`
- Test: `internal/gitcred/cache_test.go`
- Modify: `go.mod`, `go.sum`

**Interfaces:**
- Consumes: Task 1 `securestore.Protectors` (`Available`, `Open`, `AvailableAtLeast`), `Strength`, `ErrUnavailable`, `ErrUnknownTier`, `ErrForeignKey`, `NewProtectors`, `Tier`, `FileTier`.
- Produces (package `gitcred`):
  ```go
  const (
      CacheFileName      = "cache.enc"
      LockFileName       = "cache.lock"
      TierFileName       = "tier"
      MinRemaining       = 5 * time.Minute
      DefaultLockTimeout = 10 * time.Second
      BackendAuto        = "auto"
      BackendNone        = "none"
      MessagePrefix      = "ghp git-credential: "
      IdentityDotvault   = "dotvault"
  )
  var (
      ErrLockTimeout    = errors.New("timed out waiting for the credential cache lock")
      ErrInvalidBackend = errors.New("unknown cache backend")
  )
  type Entry struct {
      Token       string    `json:"token"`
      TokenID     string    `json:"token_id"`
      Type        string    `json:"type"`
      AppRecordID string    `json:"app_record_id,omitempty"`
      AppName     string    `json:"app_name,omitempty"`
      Repository  string    `json:"repository"` // owner/repo as git sent it
      Scopes      string    `json:"scopes"`     // effective, NormalizeScopes form
      ExpiresAt   time.Time `json:"expires_at"`
      MintedAt    time.Time `json:"minted_at"`
      Identity    string    `json:"identity"`
  }
  func (e Entry) Fresh(now time.Time) bool // e.ExpiresAt.Sub(now) > MinRemaining
  type KeyInput struct {
      ServerURL, Identity, Type, App, Repository string
      Scopes string // NormalizeScopes of the REQUESTED scopes (§3.3), never the lowered ones
  }
  func CacheKey(in KeyInput) string                     // hex SHA-256
  func IdentityFor(phaseAUserToken string) string       // hex SHA-256 of the token, or IdentityDotvault when ""
  func NormalizeScopes(scopes map[string]string) string // sorted "perm:level" joined by ","
  type Cache struct {
      Dir         string
      Backend     string                  // "" or "auto", "none", or a tier name
      Protectors  *securestore.Protectors
      LockTimeout time.Duration           // 0 → DefaultLockTimeout
      Stderr      io.Writer               // notices; nil → io.Discard
      Now         func() time.Time        // nil → time.Now
  }
  func (c *Cache) Open() (*Session, error) // takes the lock; Close releases it
  type Session struct{ /* unexported */ }
  func (s *Session) Get(in KeyInput) (Entry, bool)  // miss when absent or Entry.Identity != in.Identity
  func (s *Session) Put(in KeyInput, e Entry)       // stores e with e.Identity = in.Identity, overwriting
  func (s *Session) Delete(in KeyInput) (Entry, bool)
  func (s *Session) Entries() map[string]Entry      // copy, keyed by CacheKey
  func (s *Session) Clear()                         // marks the session cleared; the next Commit removes cache.enc (also when !Readable), keeps tier
  func (s *Session) Commit() error
  func (s *Session) Close() error                   // releases the lock; safe to call twice
  func (s *Session) Backend() string                // envelope tier read or last written; "" when none
  func (s *Session) MinTier() string                // parsed tier file; "" when absent
  func (s *Session) Readable() bool                 // false for BackendNone or when Unwrap failed
  func (s *Session) ReadError() error
  func (s *Session) Path() string                   // filepath.Join(Dir, CacheFileName)
  ```

`CacheKey` hashes, joined by `"\x00"`: `strings.TrimRight(ServerURL, "/")`, `Identity`, `Type`, `App` (selector as given), `asciiutil.ToLower(Repository)`, `Scopes`.

**Envelope** (JSON file `cache.enc`): `{"version":1,"backend":..,"wrapped_key":..,"nonce":..,"ciphertext":..}` (`[]byte` fields, base64 by encoding/json). Ciphertext = AES-256-GCM of `json.Marshal(map[string]Entry)` under the 32-byte DEK, 12-byte random nonce, AAD = `json.Marshal(struct{Version int "json:\"version\""; Backend string "json:\"backend\""; WrappedKey []byte "json:\"wrapped_key\""}{...})`.

**`Open` decision list** (the algorithm; tests below pin each line):
1. Backend `""` → `auto`. Not one of `auto`, `none`, `tpm`, `dpapi`, `keychain`, `file` → `fmt.Errorf("%w %q (want auto, none, tpm, dpapi, keychain or file)", ErrInvalidBackend, b)`.
2. `none` → a session that never reads, writes, or locks; `Readable()` false.
3. Explicit tier X → `Protectors.Available(X)`; error is returned as is.
4. `MkdirAll(Dir, 0700)` then `Chmod(Dir, 0700)`; open `cache.lock` (`O_CREATE|O_RDWR`, `0600`); poll `tryLock` every 25 ms until `LockTimeout` → `fmt.Errorf("%w %s after %s", ErrLockTimeout, lockPath, timeout)`.
5. `os.Lstat` each of `cache.lock`, `cache.enc`, `tier`; `Chmod(0600)` only those whose mode is a regular file (never a directory, never through a symlink).
6. Read `tier`: `TrimSpace`; empty or absent → `""`; `Strength < 0` → `"tpm"`.
7. Read `cache.enc`: absent → no envelope. Unreadable, bad JSON, `version != 1`, or unknown backend → discard (no envelope).
   - 7b. Auto and `Strength(envelope.backend) < Strength(MinTier)` → discard (never used, never rewritten under the weaker tier).
8. Explicit X and envelope backend ≠ X → discard; remember the discarded backend.
9. `Protectors.Open(backend, Dir).Unwrap(wrapped)`: errors wrapping `ErrForeignKey` → discard. Any other error → unreadable: keep `ReadError`, print `ghp git-credential: cannot read the credential cache (<backend>: <err>); continuing without it`. DEK length ≠ 32, GCM failure, or bad entries JSON → discard.

**`Commit` decision list:**
1. `none` → nil. Cleared → remove `cache.enc` (ignore not-exist), return. Not modified → nil. Unreadable → nil (never rewrite).
2. Drop entries with `!ExpiresAt.After(now)`.
3. Choose the protector and DEK:
   - Explicit X → X; if X equals the readable envelope's tier reuse its DEK and wrapped key, else new DEK and `Wrap` (error → `fmt.Errorf("wrapping cache key with %s: %w", X, err)`).
   - Auto with a readable envelope E → for each protector in `AvailableAtLeast(E, Dir)` stronger than E, strongest first: new DEK, `Wrap`; first success wins. None succeeds → keep E, reuse its DEK and wrapped key.
   - Auto with no envelope → for each protector in `AvailableAtLeast(MinTier)`: new DEK, `Wrap`; first success wins (a locked keychain falls through to the next). None → print `ghp git-credential: no cache tier at least as strong as "<MinTier>" is available; token not cached` and return nil.
4. Tier file first (temp + rename, `0600`), before the envelope: explicit → write X; auto → write the chosen tier when `MinTier == ""` or `Strength(chosen) > Strength(MinTier)`.
5. Envelope: `os.CreateTemp(Dir, ".cache-*.tmp")`, `Chmod 0600`, write, `Sync`, close, `os.Rename` to `cache.enc`.
6. Notices: chosen `file` and no previous envelope under `file` in this session (no envelope, a discarded one, or one under another tier) → `ghp git-credential: cache protected by file permissions only; see docs`. After `clear` removes `cache.enc`, the next write prints it again. Explicit X weaker than `<old>` → `ghp git-credential: cache tier lowered from "<old>" to "<X>" at your request`, where `<old>` is the discarded envelope's backend, or `MinTier` when there was no envelope.

- [ ] **Step 1: Write the failing tests**

In `cache_test.go` define a local `xorProtector{name string; wrapErr, unwrapErr error}` (XOR with `0x5a`) and `type fakeTiers struct{ avail map[string]bool; wrapErr, unwrapErr map[string]error }` with `func (f *fakeTiers) protectors() *securestore.Protectors`, building `tpm`, `keychain` and `file` tiers whose `Probe`, `Wrap` and `Unwrap` read the maps at call time (`file` defaults to available). `newCache(t, dir, backend, f)` returns a `*Cache` with a `bytes.Buffer` Stderr and fixed `Now`. `in(repo string)` builds a `KeyInput` with fixed server, identity `"id-a"`, type, scopes.

```go
func TestCacheKey(t *testing.T)
    // same input → same key; changing any one of the 6 fields → different key
    // Repository "GoodTune/GHP" == "goodtune/ghp"; ServerURL "https://g/" == "https://g"
    // {Type:"ab",App:"c"} != {Type:"a",App:"bc"}
func TestIdentityFor(t *testing.T) // "" → "dotvault"; "ghpr_x" → 64 hex chars, not containing "ghpr_x"; stable
func TestNormalizeScopes(t *testing.T) // {"pull_requests":"write","contents":"read"} → "contents:read,pull_requests:write"
func TestEntry_Fresh(t *testing.T)     // expires now+6m → true; now+5m → false; now+4m → false
func TestCache_RoundTrip(t *testing.T)
    // Put entry with every field set; Commit; Close; reopen → Get returns an equal Entry (time.Equal on times), Identity "id-a"
    // tier file == "file"; envelope JSON version 1, backend "file"; raw cache.enc bytes do not contain e.Token
    // unix only: dir mode 0700, cache.enc and tier 0600
func TestCache_IdentityMismatchIsMiss(t *testing.T)
    // Put(in with Identity "id-a"); Get(same input with Identity "id-b") misses
    // package-internal: store an Entry{Identity:"id-a"} under CacheKey(inB) directly → Get(inB) misses
func TestCache_FileTierNotice(t *testing.T)
    // first Commit stderr contains "file permissions only"; reopen, Put, Commit → no new notice
    // reopen, Clear, Commit; reopen, Put, Commit → notice printed again
func TestCache_TamperedEnvelopeDiscarded(t *testing.T)
    // table: flip a ciphertext byte; flip a nonce byte; change wrapped_key; set "version":2; replace file with "{"
    // each: reopen → Readable() true, Get misses, Commit after Put succeeds, tier file unchanged
func TestCache_TierFileParsing(t *testing.T)
    // tier contents "file\n" → MinTier()=="file"; "" → ""; "garbage" → "tpm"
func TestCache_AutoRefusesWeakerTier(t *testing.T)
    // tier "tpm", tpm unavailable, file available, no envelope: Put; Commit → nil
    // cache.enc absent; stderr contains `no cache tier at least as strong as "tpm"`; tier still "tpm"
func TestCache_AutoDiscardsEnvelopeWeakerThanTier(t *testing.T)
    // write under file; overwrite tier with "keychain"; keychain unavailable; reopen → Get misses;
    //   Put; Commit → nil, cache.enc bytes identical to before, stderr contains "no cache tier"
    // make keychain available; reopen; Put; Commit → envelope backend "keychain"
func TestCache_AutoUpgrades(t *testing.T)
    // only file available: Put a; Commit. Make keychain available; reopen; Get(a) hits; Put b; Commit
    // envelope backend "keychain"; tier "keychain"; reopen → a and b both present
func TestCache_WrapFailureFallsThrough(t *testing.T)
    // tpm available with wrapErr, keychain available, no envelope, MinTier "" → envelope backend "keychain"
    // same with tier "tpm" → nothing written, stderr contains "no cache tier"
    // Backend "tpm" (explicit) with wrapErr → Commit returns an error containing "wrapping cache key with tpm"
func TestCache_TierRaisedBeforeEnvelope(t *testing.T)
    // create an EMPTY directory at cache.enc (renaming a file onto a directory fails even when empty); keychain available;
    //   Put; Commit → error (rename fails); tier file == "keychain"
func TestCache_UnwrapFailureNeverRewrites(t *testing.T)
    // envelope under keychain; unwrapErr["keychain"] = errors.New("locked"); reopen
    // Readable() false; ReadError non-nil; Put; Commit → nil; cache.enc bytes identical; stderr contains "cannot read the credential cache"
func TestCache_ForeignKeyDiscards(t *testing.T)
    // unwrapErr["tpm"] = fmt.Errorf("x: %w", securestore.ErrForeignKey) → Readable() true, Get misses, Put+Commit rewrites under tpm
func TestCache_ExplicitBackend(t *testing.T)
    // Backend "tpm", tpm unavailable → Open error, errors.Is(err, securestore.ErrUnavailable)
    // Backend "bogus" → errors.Is(err, ErrInvalidBackend)
    // envelope tpm, Backend "file": Get misses; Put; Commit → backend "file", tier "file",
    //   stderr contains `lowered from "tpm" to "file"`
func TestCache_BackendNone(t *testing.T) // existing envelope; Backend "none": Get misses; Put; Commit; all files byte-identical
func TestCache_ClearKeepsTier(t *testing.T) // Put; Commit; reopen; Clear; Commit → cache.enc absent, tier present
func TestCache_ClearWhenUnreadable(t *testing.T) // unreadable session; Clear; Commit → cache.enc absent
func TestCache_TightensPermissions(t *testing.T)
    // unix only: dir 0755; cache.lock, cache.enc (a valid file-tier envelope) and tier (content "file") all 0644
    // Open alone (no Commit) → dir 0700, all three files 0600
func TestCache_CommitPrunesExpired(t *testing.T) // Put expired (now-1m) and fresh; Commit; reopen → only fresh
func TestCache_LockTimeout(t *testing.T)
    // s1 open; c2 with LockTimeout 100ms → errors.Is(err, ErrLockTimeout); s1.Close(); c2.Open() succeeds
func TestCache_ConcurrentWriters(t *testing.T)
    // 8 goroutines each: Open; Put(in(fmt.Sprint("o/r", i)), fresh); Commit; Close → reopen holds all 8 entries
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/gitcred/ -run 'TestCacheKey|TestIdentityFor|TestNormalizeScopes|TestEntry_Fresh|TestCache_' -v`
Expected: FAIL (undefined symbols).

- [ ] **Step 3: Implement `lock_unix.go` and `lock_windows.go`**

Both define `func tryLock(f *os.File) (bool, error)` and `func unlock(f *os.File) error`. Unix (`//go:build unix`): `unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)`; `EWOULDBLOCK`/`EAGAIN` → `(false, nil)`. Windows: `windows.LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)`; `ERROR_LOCK_VIOLATION` → `(false, nil)`; unlock with `UnlockFileEx`.

- [ ] **Step 4: Implement `cache.go`** following the two decision lists above.

- [ ] **Step 5: Promote x/sys and verify**

Run: `go get golang.org/x/sys@v0.49.0 && go mod tidy && grep -n 'golang.org/x/sys' go.mod`
Expected: `golang.org/x/sys v0.49.0` with no `// indirect`.

- [ ] **Step 6: Run tests and cross-vet**

Run: `CGO_ENABLED=0 go test ./internal/gitcred/ -v && for t in windows/amd64 windows/arm64 darwin/arm64; do GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go vet ./internal/gitcred/ || exit 1; done`
Expected: PASS; vet clean on all three targets.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/gitcred/cache.go internal/gitcred/lock_unix.go internal/gitcred/lock_windows.go internal/gitcred/cache_test.go
git commit -m "feat(gitcred): encrypted token cache with file lock and minimum tier"
```

---

### Task 4: ghp API client, app/installation/scope resolution, ASCII folding in cmd/ghp

**Files:**
- Create: `internal/gitcred/client.go`, `internal/gitcred/resolve.go`
- Test: `internal/gitcred/client_test.go`, `internal/gitcred/resolve_test.go`, `cmd/ghp/token_test.go`
- Modify: `cmd/ghp/token.go:360` (`resolveAppByName`), `cmd/ghp/token.go:434` (`resolveInstallationByLogin`), `cmd/ghp/apptoken.go:84` (installation login match). These are the only `strings.EqualFold` calls in `cmd/ghp`; `resolveDefaultAppID` has none, so the spec's "three `token.go` call sites" are these three. Each becomes `asciiutil.EqualFold`; drop the `strings` import only if it becomes unused.

**Interfaces:**
- Consumes: Task 2 `Target`; `token.ParseScopeString`; `permissions.ForGitHubApp`; `asciiutil.EqualFold`.
- Produces (package `gitcred`):
  ```go
  type Client struct {
      BaseURL string       // trailing "/" trimmed before use
      Token   string       // ghpr_ session token, sent as "Authorization: Bearer <Token>"
      HTTP    *http.Client // nil → &http.Client{Timeout: 30 * time.Second}
  }
  type App struct {
      ID        string `json:"id"`
      Name      string `json:"name"`
      AppID     int64  `json:"app_id"`
      IsDefault bool   `json:"is_default"`
  }
  type Installation struct {
      ID          int64 `json:"id"`
      Account     struct{ Login string `json:"login"` } `json:"account"`
      Permissions map[string]string `json:"permissions"`
  }
  type MintRequest struct {
      Type           string   `json:"type"`
      Repositories   []string `json:"repositories"`
      Scopes         string   `json:"scopes"`
      Duration       string   `json:"duration"`
      SessionID      string   `json:"session_id"`
      AppRecordID    string   `json:"app_record_id,omitempty"`
      InstallationID int64    `json:"installation_id,omitempty"`
  }
  type MintedToken struct {
      Token        string            `json:"token"`
      ID           string            `json:"id"`
      Type         string            `json:"type"`
      Repositories []string          `json:"repositories"`
      Scopes       map[string]string `json:"scopes"`
      ExpiresAt    *time.Time        `json:"expires_at"`
  }
  type APIError struct{ Op string; Status int; Message, RetryAfter string }
  func (e *APIError) Error() string        // "<Op>: server returned <Status>: <Message>"
  func (e *APIError) Is(target error) bool // 401↔ErrUnauthorized, 403↔ErrForbidden, 429↔ErrRateLimited
  var ErrUnauthorized, ErrForbidden, ErrRateLimited error
  func (c *Client) ListApps(ctx context.Context) ([]App, error)                                       // GET /api/apps, 200
  func (c *Client) ListInstallations(ctx context.Context, appRecordID string) ([]Installation, error) // GET /api/apps/{PathEscape(id)}/installations, 200
  func (c *Client) CreateToken(ctx context.Context, req MintRequest) (*MintedToken, error)           // POST /api/tokens, 201
  func (c *Client) RevokeToken(ctx context.Context, id string) error                                 // DELETE /api/tokens/{PathEscape(id)}, 200

  const (TypeAgent = "agent"; TypeProxy = "proxy"; DefaultType = TypeAgent; DefaultScopes = "contents:write"; DefaultTTL = "1h")
  type Settings struct {
      Type, App, Scopes, TTL string // raw values, "" = default
      ScopesExplicit bool           // came from --scopes or GHP_GIT_CM_SCOPES
      AppFromEnv     bool           // App came from GHP_GIT_CM_APP, not --app
      TypeFromFlag   bool           // Type came from --type
  }
  type Plan struct {
      Type           string
      App            string
      Scopes         map[string]string // requested
      ScopesExplicit bool
      TTL            time.Duration
  }
  func ParseSettings(s Settings) (Plan, error)
  type Resolved struct {
      Type           string
      AppRecordID    string
      AppName        string
      InstallationID int64
      Scopes         map[string]string // effective
  }
  func Resolve(ctx context.Context, c *Client, p Plan, t Target) (Resolved, error)
  func SelectApp(apps []App, selector string) (App, error)
  func SelectInstallation(insts []Installation, owner, appName string) (Installation, error)
  func EffectiveScopes(requested, granted map[string]string, explicit bool, owner string) (map[string]string, error)
  const msgAgentForbidden = "the ghp server refused the agent-token request (agent tokens need the ghp admin role); use --type proxy or set GHP_GIT_CM_TYPE=proxy"
  ```

Error text (one line each; tests match the quoted fragments):
- `ParseSettings`: type not agent/proxy → `invalid token type "x" (want agent or proxy)`; proxy with an app → if `AppFromEnv && TypeFromFlag` the app is dropped silently (§2), otherwise `--app is only valid with --type agent`; bad scopes → `invalid scopes: <ParseScopeString error>` (`token.ParseScopeString` logs a slog deprecation warning for deprecated names such as `workflows:read`; this is accepted and documented in Task 13, not suppressed); TTL `never` → `--ttl never is not allowed: cached tokens must expire`; unparsable or ≤ 0 → `invalid --ttl "x"`.
- `SelectApp` (selector matches `ID` or `Name`, both `asciiutil.EqualFold`; empty selector → the `IsDefault` app, else the only app): none → `no GitHub Apps are configured on the ghp server; use --type proxy or ask an admin to add one`; several, no default → `several GitHub Apps are configured and none is the default; set --app or GHP_GIT_CM_APP to one of: a, b`; not found → `GitHub App "x" not found; available apps: a, b`.
- `SelectInstallation`: `GitHub App "NAME" has no installation for "OWNER"; install it there or choose another app with --app`.
- `EffectiveScopes` (levels read=1, write=2, admin=3; each requested `p:l` is checked against every key of `permissions.ForGitHubApp({p: l})`): permission absent → `installation for "OWNER" does not grant <gp>, needed for <p>:<l>`; granted lower and `explicit` → `installation for "OWNER" grants <gp>:<have> but <p>:<l> was requested; lower --scopes or GHP_GIT_CM_SCOPES`; granted lower and defaulted → `p` lowered to the granted level.
- `Resolve`: proxy → `Resolved{Type: proxy, Scopes: p.Scopes}` with no HTTP call. Agent → ListApps → SelectApp → ListInstallations → SelectInstallation(owner = `t.Owner`) → EffectiveScopes. An `ErrForbidden` from either list call → an error whose text is `msgAgentForbidden` and for which `errors.Is(err, ErrForbidden)` still holds.

- [ ] **Step 1: Write the failing tests**

```go
// client_test.go — one httptest server per test, asserting method, path and "Authorization: Bearer ghpr_test"
func TestClient_ListApps(t *testing.T)          // decodes two apps; BaseURL srv.URL+"/" still hits "/api/apps"
func TestClient_ListInstallations(t *testing.T) // path "/api/apps/0b0e.../installations"; Permissions["contents"] == "read"
func TestClient_CreateToken(t *testing.T)
    // agent body decoded into map[string]any: type "agent", repositories ["goodtune/ghp"], scopes "contents:read",
    //   duration "1h0m0s", session_id "git-credential:h", app_record_id, installation_id 42
    // proxy body: keys "app_record_id" and "installation_id" absent
    // 201 response decodes; ExpiresAt equals the RFC3339 value; expires_at null → ExpiresAt == nil
func TestClient_Errors(t *testing.T)
    // table status → sentinel: 401 ErrUnauthorized, 403 ErrForbidden, 429 (Retry-After "1") ErrRateLimited with RetryAfter "1"
    // 400 {"message":"bad"} → Error() contains "bad", Is none of the three
func TestClient_RevokeToken(t *testing.T) // DELETE "/api/tokens/<id>", 200 → nil; 404 → *APIError
// resolve_test.go
func TestParseSettings(t *testing.T)
    // Settings{} → Plan{Type:"agent", App:"", Scopes:{"contents":"write"}, ScopesExplicit:false, TTL:time.Hour}
    // {Type:"proxy", App:"x"} → error contains "--app is only valid"
    // {Type:"proxy", App:"x", AppFromEnv:true, TypeFromFlag:true} → no error, Plan.App == ""
    // {Type:"proxy", App:"x", AppFromEnv:true, TypeFromFlag:false} → error
    // {Type:"bogus"} → contains "invalid token type"; {Scopes:"pulls:write"} → contains "invalid scopes"
    // {TTL:"never"} → contains "never"; {TTL:"0s"} → error; {TTL:"90m"} → TTL 90*time.Minute
    // {Scopes:"contents:read", ScopesExplicit:true} → kept
func TestSelectApp(t *testing.T)
    // "MY-APP" matches Name "my-app"; selector == an ID matches; "" with two apps, one default → default
    // "" with one app, no default → it; no apps → contains "no GitHub Apps"
    // two, no default → contains "none is the default", "a", "b"; "zzz" → contains `"zzz" not found`
    // "ſtaging" (U+017F) does not match "staging"
func TestSelectInstallation(t *testing.T)
    // owner "GoodTune" matches login "goodtune"; "\u212Aube" does not match "kube"
    // missing → contains `"my-app"` and `"goodtune"`
func TestEffectiveScopes(t *testing.T)
    // defaulted contents:write, granted read  → {"contents":"read"}
    // defaulted contents:write, granted write → write; granted admin → write
    // explicit contents:write, granted read   → error contains "contents:read" and "contents:write"
    // contents absent from granted            → error contains "does not grant contents" (explicit and defaulted)
    // explicit workflows:read, granted {"actions":"read"} → {"workflows":"read"}
func TestResolve_Agent(t *testing.T)  // fake API: default app "my-app", installation 42 for "goodtune" with contents:read
                                      // → Resolved{agent, <id>, "my-app", 42, {"contents":"read"}}
func TestResolve_AgentForbidden(t *testing.T) // /api/apps → 403: err contains "--type proxy"; errors.Is(err, ErrForbidden)
func TestResolve_Proxy(t *testing.T)  // handler calls t.Error on any request; Resolved.Type "proxy", Scopes == requested
// cmd/ghp/token_test.go
func TestResolveAppByName_ASCIIFold(t *testing.T)
    // fake /api/apps returns [{id:"a1", name:"staging"}]; resolveAppByName(cfg,"STAGING") == "a1"; "ſtaging" → error
func TestResolveInstallationByLogin_ASCIIFold(t *testing.T)
    // fake installations [{id:7, account:{login:"kube"}}]; "KUBE" → 7; "\u212Aube" → error
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/gitcred/ -run 'TestClient_|TestParseSettings|TestSelect|TestEffectiveScopes|TestResolve_' -v; CGO_ENABLED=0 go test ./cmd/ghp/ -run 'ASCIIFold' -v`
Expected: gitcred FAIL (undefined symbols); cmd/ghp FAIL on the `ſtaging`/Kelvin cases (strings.EqualFold folds them).

- [ ] **Step 3: Implement `client.go`, `resolve.go`; switch the three `cmd/ghp` sites to `asciiutil.EqualFold`**

Client: limit response bodies to 1 MiB; decode `{"message": ...}` into `APIError.Message` on non-success; capture `Retry-After`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/gitcred/ ./cmd/ghp/ && go vet ./internal/gitcred/ ./cmd/ghp/`
Expected: PASS, vet clean.

- [ ] **Step 5: Commit**

```bash
git add internal/gitcred/client.go internal/gitcred/resolve.go internal/gitcred/client_test.go internal/gitcred/resolve_test.go cmd/ghp/token.go cmd/ghp/apptoken.go cmd/ghp/token_test.go
git commit -m "feat(gitcred): ghp API client and app, installation and scope resolution"
```

---

### Task 5: helper `Run` for get, store, erase

**Files:**
- Create: `internal/gitcred/helper.go`
- Test: `internal/gitcred/helper_test.go`

**Interfaces:**
- Consumes: Task 2 (`ParseRequest`, `WriteCredential`, `ParseTarget`, errors), Task 3 (`Cache`, `Session`, `Entry`, `KeyInput`, `IdentityFor`, `NormalizeScopes`, `ErrLockTimeout`, `ErrInvalidBackend`, `MessagePrefix`), Task 4 (`Client`, `Settings`, `ParseSettings`, `Resolve`, sentinels, `msgAgentForbidden`), Task 1 (`securestore.Default`, `ErrUnavailable`, `ErrUnknownTier`).
- Produces:
  ```go
  const Username = "x-access-token"
  const DefaultHost = "github.com"
  type Config struct {
      ServerURL, UserToken string
      Warnings             []string // config-loading warnings, re-emitted one per line with MessagePrefix
  }
  type Options struct {
      Settings     Settings
      Hosts        []string                                  // empty → []string{DefaultHost}
      CacheBackend string                                    // "" → auto
      CacheDir     string                                    // "" → behave as BackendNone
      Hostname     string
      LoadStatic   func() (Config, error)                    // phase A: files + env, never prompts
      LoadAuthed   func(ctx context.Context) (Config, error) // phase B: + dotvault, non-interactive; its error text is printed verbatim
      Protectors   *securestore.Protectors                   // nil → securestore.Default()
      HTTPClient   *http.Client
      LockTimeout  time.Duration
      Now          func() time.Time
  }
  func Run(ctx context.Context, opts Options, op string, stdin io.Reader, stdout, stderr io.Writer) int
  func SessionID(hostname string) string // "git-credential:"+hostname, ≤128 bytes, cut on a rune boundary
  ```
  Task 6 adds `status` and `clear` to the same `Run` switch. `fail(stderr, msg) int` prints `MessagePrefix + msg` with every `\r`/`\n` replaced by a space and returns 1. Phase A's `Config.Warnings` are printed (prefixed) whenever phase A runs.

**`get`** (§3), in order:
1. `ParseRequest` error → `fail("invalid credential request from git")`.
2. `Request.Host` not in `Hosts` (`asciiutil.EqualFold`) → `fail(fmt.Sprintf("host %q is not configured for this helper; add --host %s to the helper line or run ghp auth setup-git --host %s", h, h, h))`.
3. `ParseTarget`: `ErrNoPath` → `git did not send a repository path; run ghp auth setup-git (it sets credential.useHttpPath)`; other errors → their text. Exit 1.
4. `ParseSettings` error → fail with its text.
5. Phase A; its error → fail with its text. If `ServerURL == ""` run phase B now (error → fail with its text); still empty → `fail("not logged in: run ghp auth login")` before touching the cache.
6. Key input `KeyInput{ServerURL (phase A's, else B's), IdentityFor(phaseA.UserToken), Plan.Type, Plan.App, target.FullName(), NormalizeScopes(Plan.Scopes)}` (requested scopes, §3.3).
7. **Read:** `Cache.Open` → `Get` → `Close` immediately. `ErrInvalidBackend`, `ErrUnavailable`, `ErrUnknownTier` → fail with the error text. `ErrLockTimeout` or any other error → print one line `could not use the credential cache (<err>); continuing without it` and disable caching for the rest of this run. A hit with `Fresh(now)` → write the credential, exit 0. If the session is not `Readable()`, disable caching for the rest of this run (step 10 is skipped) so the unreadable-cache notice is printed exactly once.
8. Phase B if not yet run; empty `ServerURL` or `UserToken` → `fail("not logged in: run ghp auth login")`.
9. **Mint with no lock held:** `Resolve` → `CreateToken{Type, Repositories: [FullName], Scopes: NormalizeScopes(effective), Duration: TTL.String(), SessionID(Hostname), AppRecordID, InstallationID}`. `ExpiresAt == nil` → best-effort revoke, `fail("server returned a token with no expiry; refusing to use it")`.
10. **Store** (skipped when caching was disabled in step 7): `Cache.Open` again (re-reads), `Put(in, Entry{Token, TokenID: ID, Type, AppRecordID, AppName, Repository: FullName, Scopes: NormalizeScopes(effective), ExpiresAt: *ExpiresAt, MintedAt: now})` overwriting whatever another process stored, `Commit`, `Close`. Any error here (including `ErrLockTimeout`) → one line `could not save the credential cache: <err>`, still succeed.
11. Write `Credential{Username, Token, *ExpiresAt}`, exit 0.

Error mapping for Resolve/mint errors: `ErrUnauthorized` → `ghp session expired or invalid: run ghp auth login`; `ErrRateLimited` → `ghp server rate limited token creation (20 per minute per IP); retry in <RetryAfter or 60>s`; `ErrForbidden` with type agent → `msgAgentForbidden`; otherwise `err.Error()`.

**`store`**: drain stdin, exit 0, no output. **Unknown op**: exit 0, no output.

**`erase`** (§4, always exit 0): `ParseRequest`, host, target or settings errors → silent exit 0. Phase A (error → silent exit 0); phase B if `ServerURL` empty (error → print it, exit 0). Open the cache (error → one line, exit 0); `Get(in)`; delete only when git sent no password or the password equals the cached token; `Commit`; `Close`. **Then**, with the lock released, revoke the deleted entry's `TokenID` with the user token (phase B if phase A had none); failure → `could not revoke token <first 8 chars>...: <err>`.

- [ ] **Step 1: Write the failing tests**

`helper_test.go` builds `fakeGHP` (httptest) that records every request and serves: `GET /api/apps`, `GET /api/apps/{id}/installations`, `POST /api/tokens` (201, token `fmt.Sprintf("gha_fake%04dabcdefghijklmnopqrstuvwxyz", n)`, id `tok-<n>`, `expires_at` = fake now + 1h), `DELETE /api/tokens/{id}`; per-path status overrides; optional `onMint`/`onRevoke` hooks run inside the handler. `baseOptions(t, srv)` → file-only `securestore.NewProtectors(securestore.FileTier())`, `CacheDir` `t.TempDir()`, `Hostname "testhost"`, `LoadStatic` → `{srv.URL, "ghpr_test", nil}`, `LoadAuthed` counting calls and returning the same, `Now` from a settable variable. `run(t, opts, op, stdin) (stdout, stderr string, code int)`. Standard stdin: `"protocol=https\nhost=github.com\npath=goodtune/ghp.git\n\n"`.

```go
func TestRun_GetMintsAndCaches(t *testing.T)
    // code 0; stdout == "username=x-access-token\npassword=gha_fake0001...\npassword_expiry_utc=<now+1h unix>\n"
    // second get → identical stdout; mints == 1; authedCalls == 1 (phase B ran on the miss only)
func TestRun_GetRemintsInsideMargin(t *testing.T) // now+54m → hit (mints 1); now+56m → mint (mints 2)
func TestRun_GetDoesNotHoldLockDuringMint(t *testing.T)
    // onMint: (&Cache{Dir: opts.CacheDir, Protectors: opts.Protectors, LockTimeout: 100*time.Millisecond}).Open() succeeds; Close
func TestRun_GetIdentitySeparatesSessions(t *testing.T)
    // LoadStatic token "ghpr_a" → mint 1; token "ghpr_b" → mint 2; token "ghpr_a" again → hit (mints 2)
func TestRun_GetAgentSelection(t *testing.T)
    // table over apps and Settings.App: by name "MY-APP", by id, default of two, single without default
    // each: mint body app_record_id == expected id, installation_id == 42, repositories == ["goodtune/ghp"],
    //   session_id == "git-credential:testhost", duration == "1h0m0s", type "agent"
func TestRun_GetNoDefaultAmongTwo(t *testing.T)       // code 1; stderr one line containing "none is the default"; stdout ""
func TestRun_GetNoInstallationForOwner(t *testing.T)  // code 1; stderr contains `no installation for "goodtune"`
func TestRun_GetLowersDefaultedScopes(t *testing.T)   // installation contents:read → mint scopes "contents:read"; 2nd get hits
func TestRun_GetExplicitScopesExceed(t *testing.T)    // ScopesExplicit, contents:write vs read → code 1, mints 0, stderr contains "contents:read"
func TestRun_GetAppsForbiddenSuggestsProxy(t *testing.T) // /api/apps 403 → code 1, stderr contains "--type proxy"
func TestRun_GetProxy(t *testing.T)                   // Type proxy → body type "proxy", no app fields, zero /api/apps requests
func TestRun_GetSessionExpired(t *testing.T)          // mint 401 → stderr == "ghp git-credential: ghp session expired or invalid: run ghp auth login\n"
func TestRun_GetRateLimited(t *testing.T)             // mint 429, Retry-After 1 → stderr contains "rate limited" and "retry in 1s"
func TestRun_GetInvalidRequest(t *testing.T)          // stdin "garbage\n" → stderr == MessagePrefix+"invalid credential request from git\n"; erase with same stdin → code 0, no output
func TestRun_GetHostNotConfigured(t *testing.T)
    // host=gitlab.com → code 1, stderr contains `host "gitlab.com" is not configured`, zero API requests
    // Hosts {"github.com","ghe.example.com"} + host=GHE.example.com → code 0
func TestRun_GetMissingPath(t *testing.T)             // stdin without path → code 1, stderr contains "ghp auth setup-git", zero API requests, stdout ""
func TestRun_GetBadPath(t *testing.T)                 // path "own%2Fer/repo.git" and "../x.git" → code 1, zero API requests, stdout ""
func TestRun_GetNotLoggedIn(t *testing.T)             // both loaders return Config{} → stderr contains "not logged in: run ghp auth login"; CacheDir has no cache.lock
func TestRun_GetPhaseAError(t *testing.T)             // LoadStatic returns errors.New("bad config") → code 1, stderr contains "bad config"
func TestRun_GetPhaseBErrorVerbatim(t *testing.T)     // LoadAuthed returns errors.New("dotvault login required: run `ghp auth status` in a terminal to log in")
                                                      // → code 1, stderr == MessagePrefix + that text + "\n"
func TestRun_FailFlattensNewlines(t *testing.T)       // LoadAuthed error "a\nb\rc" (phase A empty) → stderr == MessagePrefix+"a b c\n"
func TestRun_WarningsReemitted(t *testing.T)          // phase A Warnings ["warning: config file x has insecure permissions"] → stderr has MessagePrefix+"warning: config file x"
func TestRun_GetNullExpiry(t *testing.T)              // expires_at null → code 1, revokes == 1, stderr contains "no expiry"
func TestRun_GetTTLNever(t *testing.T)                // Settings.TTL "never" → code 1, zero API requests
func TestRun_GetLockTimeoutStillReturnsToken(t *testing.T)
    // hold a Session on CacheDir for the whole run; LockTimeout 100ms → code 0, stdout has "password=gha_fake0001",
    //   stderr exactly one line containing "continuing without it"
func TestRun_GetCacheUnusableStillReturnsToken(t *testing.T)
    // CacheDir = path of a regular file + "/sub" → code 0, stdout has password=, stderr one line "could not use the credential cache"
func TestRun_GetUnreadableCacheNoticeOnce(t *testing.T)
    // envelope written under a fake keychain tier (test-local, as in cache_test.go); then its Unwrap fails
    // get → code 0, stdout has "password=", stderr is exactly one line containing "cannot read the credential cache"
    //   (strings.Count(stderr, "\n") == 1); cache.enc bytes unchanged
func TestRun_Store(t *testing.T)                      // code 0, stdout/stderr "", zero API requests
func TestRun_UnknownOp(t *testing.T)                  // "frobnicate" → code 0, stdout/stderr ""
func TestRun_EraseDeletesAndRevokes(t *testing.T)
    // get; erase with password=<token> → code 0, DELETE /api/tokens/tok-1; onRevoke can Open the cache with LockTimeout 100ms
    // next get mints (mints 2)
func TestRun_EraseKeepsNewerToken(t *testing.T)       // get; erase with password=gha_stale → revokes 0; next get hits (mints 1)
func TestRun_EraseRevokeFailure(t *testing.T)         // DELETE → 500: code 0, stderr one line containing "could not revoke token gha_fake..."
func TestRun_NeverLeaksToken(t *testing.T)            // run get, erase, and the 401/429/null-expiry cases; no stderr contains "gha_fake0"
func TestSessionID(t *testing.T)                      // "h" → "git-credential:h"; 200×"a" → len 128; "é" at the cut → utf8.ValidString
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/gitcred/ -run 'TestRun_|TestSessionID' -v`
Expected: FAIL (undefined `Run`, `Options`, `SessionID`).

- [ ] **Step 3: Implement `helper.go`** as specified above.

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/gitcred/ -v && go vet ./internal/gitcred/`
Expected: PASS, vet clean.

- [ ] **Step 5: Commit**

```bash
git add internal/gitcred/helper.go internal/gitcred/helper_test.go
git commit -m "feat(gitcred): credential helper get, store and erase"
```

---

### Task 6: helper `status` and `clear`

**Files:**
- Modify: `internal/gitcred/helper.go`
- Test: `internal/gitcred/helper_test.go`

**Interfaces:**
- Consumes: Task 5 `Run`, `Options`; Task 3 `Session` accessors; Task 1 `Protectors.Names`, `Available`.
- Produces: `Run(ctx, opts, "status", ...)` and `Run(ctx, opts, "clear", ...)`. Both open the cache with `BackendAuto` whatever `Options.CacheBackend` says, with `Cache.Stderr = io.Discard` (the "continuing without it" notice is suppressed; status reports `ReadError` itself), and never write a token to any stream.

**`status`** (never contacts the server, exit 0; exit 1 only when `Open` fails) prints these key/value lines to stdout, labels padded to 16 columns:

```
Cache path:     <dir>/cache.enc
Cache backend:  <Backend() or "none">
Minimum tier:   <MinTier() or "none">
Protection:     <tpm: "sealed by this machine's TPM" | dpapi: "Windows DPAPI (current user)" | keychain: "macOS login keychain" | file: "file permissions only (0600); see docs" | none: "no cache">
Tier tpm:       available | unavailable (<err>)        (one line per Protectors.Names(), strongest first)
Entries:        <N> | unavailable (<ReadError>)
  <repository>  <type>  app=<AppName or "-">  token=<first 8 chars>...  expires=<RFC3339 UTC> (in <rounded minutes>m | expired)
```
Entry lines are sorted by repository, then type.

**`clear`** (exit 0 unless `Open` fails): `Open`, snapshot `Entries()`, `Clear()`, `Commit()`, `Close()`. Then, with the lock released and when the snapshot is non-empty: phase A, then phase B if `UserToken` is empty; loader error or empty config → one stderr line `tokens not revoked: <reason>`; otherwise revoke each, counting successes. Stdout: `Cleared <N> cached credentials; revoked <M>.` (its only line). When the session was unreadable also print to stderr `cache could not be read; removed it without revoking tokens`.

- [ ] **Step 1: Write the failing tests**

```go
func TestRun_StatusShowsEntriesNotTokens(t *testing.T)
    // after a get: stdout contains "Cache backend:  file", "file permissions only", "goodtune/ghp", "agent",
    //   "app=my-app", "token=gha_fake...", "Tier file:      available"; stdout does not contain the full token
func TestRun_StatusSortsEntries(t *testing.T) // gets for goodtune/zeta then goodtune/alpha → "goodtune/alpha" line precedes "goodtune/zeta"
func TestRun_StatusEmpty(t *testing.T)  // fresh dir: "Cache backend:  none", "Minimum tier:   none", "Entries:        0"
func TestRun_StatusNoServer(t *testing.T) // loaders t.Fatal if called; code 0
func TestRun_StatusUnreadableQuiet(t *testing.T) // unreadable envelope: stdout "Entries:        unavailable (", stderr ""
func TestRun_ClearRevokesAndKeepsTier(t *testing.T)
    // gets for goodtune/ghp and goodtune/other; clear → code 0, two DELETEs, stdout == "Cleared 2 cached credentials; revoked 2.\n"
    // onRevoke can Open the cache with LockTimeout 100ms; cache.enc absent; tier file still "file"; next get mints
func TestRun_ClearWithoutServer(t *testing.T) // populate, then loaders return Config{} → code 0, stderr contains "tokens not revoked", cache.enc absent
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/gitcred/ -run 'TestRun_Status|TestRun_Clear' -v`
Expected: FAIL (status/clear fall through to the silent unknown-op path; assertions on stdout fail).

- [ ] **Step 3: Implement `status` and `clear` in `helper.go`.**

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/gitcred/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/gitcred/helper.go internal/gitcred/helper_test.go
git commit -m "feat(gitcred): status and clear operations"
```

---

### Task 7: send GitHub bare repository names for installation tokens (§7)

> Superseded by #358 on main; the task's change was removed in Task 14.

**Files:**
- Modify: `internal/github/app.go` (`GetInstallationToken`, around lines 184-210)
- Test: `internal/github/app_test.go`, `internal/github/registry_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `func bareRepoNames(repos []string) []string` (unexported): `nil` → `nil`; each entry with a `/` becomes `strings.SplitN(r, "/", 2)[1]`; entries without `/` unchanged. `AppRegistry.GetInstallationTokenForApp` delegates to `GetInstallationToken`, so the one change covers both.

- [ ] **Step 1: Write the failing tests**

```go
// app_test.go — copy the server shape of TestAppTokenProvider_TranslatesEnforcementOnlyNames, decode body.Repositories
func TestAppTokenProvider_SendsBareRepositoryNames(t *testing.T)
    // GetInstallationToken(ctx, 123, []string{"goodtune/ghp", "other/tool", "bare"}, {"contents":"read"})
    // body repositories == []string{"ghp", "tool", "bare"}; nil repos → body has no "repositories" key
func TestBareRepoNames(t *testing.T) // nil→nil; {"a/b"}→{"b"}; {"a/b/c"}→{"b/c"}; {"x"}→{"x"}; input slice not modified
// registry_test.go
func TestAppRegistry_GetInstallationTokenForApp_SendsBareRepositoryNames(t *testing.T)
    // app := makeApp("app-1", "A", 1, true); app.BaseURL = srv.URL; r := newTestRegistry(...); r.LoadAll(ctx)
    // r.GetInstallationTokenForApp(ctx, "app-1", 123, []string{"goodtune/ghp"}, nil) → body repositories == ["ghp"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/github/ -run 'BareRepo' -v`
Expected: FAIL (`bareRepoNames` undefined).

- [ ] **Step 3: Implement**: call `repos = bareRepoNames(repos)` at the top of `GetInstallationToken`, before `installationCacheKey`, and leave the caller's slice untouched.

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/github/ ./internal/proxy/ -v 2>&1 | tail -5`
Expected: `ok` for both packages.

- [ ] **Step 5: Commit**

```bash
git add internal/github/app.go internal/github/app_test.go internal/github/registry_test.go
git commit -m "fix(github): send bare repository names when minting installation tokens"
```

---

### Task 8: TPM key protector

**Files:**
- Create: `internal/securestore/tpm.go`, `internal/securestore/tpm_open_linux.go`, `internal/securestore/tpm_open_windows.go`, `internal/securestore/tpm_open_other.go`
- Test: `internal/securestore/tpm_test.go`, `internal/securestore/tpm_swtpm_test.go`
- Modify: `internal/securestore/securestore.go` (`Default` becomes `NewProtectors(TPMTier(), FileTier())`), `go.mod`, `go.sum`

**Interfaces:**
- Consumes: Task 1 `Tier`, `KeyProtector`, `TierTPM`, `ErrUnavailable`, `ErrForeignKey`.
- Produces:
  ```go
  func TPMTier() Tier // tpmTier(openTPM)
  func tpmTier(open func() (transport.TPMCloser, error)) Tier
  func openTPM() (transport.TPMCloser, error)
  func probeTPM(t transport.TPM) error
  func checkTPMProperties(permanent, startupClear uint32) error
  func classifyTPMError(err error) error
  var ErrTPMOwnerAuthSet, ErrTPMLockout, ErrTPMHierarchyDisabled error // each errors.Is ErrUnavailable
  ```

The code below is the reference design (validated to compile with `CGO_ENABLED=0` against go-tpm v0.9.8). Use it as written; adapt only imports and gofmt.

`tpm.go`:
```go
var (
	ErrTPMOwnerAuthSet      = fmt.Errorf("%w: tpm owner hierarchy auth is set; cannot use an empty-auth SRK", ErrUnavailable)
	ErrTPMHierarchyDisabled = fmt.Errorf("%w: tpm storage hierarchy is disabled", ErrUnavailable)
	ErrTPMLockout           = fmt.Errorf("%w: tpm is in dictionary-attack lockout", ErrUnavailable)
)

const (
	tpmaPermanentOwnerAuthSet = 0x1   // TPMA_PERMANENT bit 0
	tpmaPermanentInLockout    = 0x200 // TPMA_PERMANENT bit 9 (bit 10, 0x400, is tpmGeneratedEPS)
	tpmaStartupClearSHEnable  = 0x2   // TPMA_STARTUP_CLEAR bit 1
	tpmBlobVersion            = 1
	tpmBlobTemplate           = "ecc-srk"
)

// tpmBlob is the wrapped key: the sealed object's public and private areas.
// Private is encrypted under the SRK seed, so it is useless on another TPM.
type tpmBlob struct {
	Version  int    `json:"v"`
	Template string `json:"template"`
	Public   []byte `json:"public"`  // tpm2.Marshal(TPM2BPublic)
	Private  []byte `json:"private"` // tpm2.Marshal(TPM2BPrivate)
}

func checkTPMProperties(permanent, startupClear uint32) error {
	switch {
	case permanent&tpmaPermanentOwnerAuthSet != 0:
		return ErrTPMOwnerAuthSet
	case permanent&tpmaPermanentInLockout != 0:
		return ErrTPMLockout
	case startupClear&tpmaStartupClearSHEnable == 0:
		return ErrTPMHierarchyDisabled
	}
	return nil
}

func probeTPM(t transport.TPM) error {
	perm, err := tpmProperty(t, tpm2.TPMPTPermanent)
	if err != nil {
		return err
	}
	sc, err := tpmProperty(t, tpm2.TPMPTStartupClear)
	if err != nil {
		return err
	}
	return checkTPMProperties(perm, sc)
}

func tpmProperty(t transport.TPM, p tpm2.TPMPT) (uint32, error) {
	rsp, err := withRetry(func() (*tpm2.GetCapabilityResponse, error) {
		return tpm2.GetCapability{Capability: tpm2.TPMCapTPMProperties, Property: uint32(p), PropertyCount: 1}.Execute(t)
	})
	if err != nil {
		return 0, fmt.Errorf("tpm GetCapability: %w", err)
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	for _, tp := range props.TPMProperty {
		if tp.Property == p {
			return tp.Value, nil
		}
	}
	return 0, fmt.Errorf("tpm property %v not returned", p)
}

// classifyTPMError maps TPM return codes onto sentinels. tpm2.TPMRC implements
// errors.Is against the base code, so format-1 handle/parameter indices are ignored.
func classifyTPMError(err error) error {
	switch {
	case errors.Is(err, tpm2.TPMRCBadAuth), errors.Is(err, tpm2.TPMRCAuthFail):
		return fmt.Errorf("%w (%v)", ErrTPMOwnerAuthSet, err)
	case errors.Is(err, tpm2.TPMRCHierarchy):
		return fmt.Errorf("%w (%v)", ErrTPMHierarchyDisabled, err)
	case errors.Is(err, tpm2.TPMRCLockout):
		return fmt.Errorf("%w (%v)", ErrTPMLockout, err)
	case errors.Is(err, tpm2.TPMRCIntegrity):
		return fmt.Errorf("%w: tpm rejected the sealed blob (another TPM, or the TPM was cleared): %v", ErrForeignKey, err)
	}
	return err
}

func withRetry[T any](f func() (T, error)) (T, error) {
	for attempt := 1; ; attempt++ {
		v, err := f()
		if err == nil || attempt == 3 || !(errors.Is(err, tpm2.TPMRCRetry) || errors.Is(err, tpm2.TPMRCYielded)) {
			return v, err
		}
		time.Sleep(time.Duration(attempt) * 20 * time.Millisecond)
	}
}

// createSRK creates (never persists) the ECC P-256 SRK in the owner hierarchy.
// Fixed template + fixed hierarchy seed derive the same key every time.
func createSRK(t transport.TPM) (*tpm2.NamedHandle, func(), error) {
	rsp, err := withRetry(func() (*tpm2.CreatePrimaryResponse, error) {
		return tpm2.CreatePrimary{
			PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
		}.Execute(t)
	})
	if err != nil {
		return nil, nil, classifyTPMError(err)
	}
	flush := func() { _, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t) }
	return &tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name}, flush, nil
}

type tpmProtector struct{ open func() (transport.TPMCloser, error) }

func (p *tpmProtector) Name() string { return TierTPM }

func (p *tpmProtector) Wrap(dek []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, errors.New("tpm: data key must be 32 bytes")
	}
	t, err := p.open()
	if err != nil {
		return nil, fmt.Errorf("%w: opening tpm: %v", ErrUnavailable, err)
	}
	defer t.Close()
	parent, flush, err := createSRK(t)
	if err != nil {
		return nil, err
	}
	defer flush()
	sealed := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, UserWithAuth: true, NoDA: true},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull}}),
	}
	rsp, err := withRetry(func() (*tpm2.CreateResponse, error) {
		return tpm2.Create{
			ParentHandle: tpm2.AuthHandle{Handle: parent.Handle, Name: parent.Name, Auth: tpm2.PasswordAuth(nil)},
			InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: dek}),
			}},
			InPublic: tpm2.New2B(sealed),
		}.Execute(t)
	})
	if err != nil {
		return nil, fmt.Errorf("tpm Create: %w", classifyTPMError(err))
	}
	return json.Marshal(tpmBlob{Version: tpmBlobVersion, Template: tpmBlobTemplate,
		Public: tpm2.Marshal(rsp.OutPublic), Private: tpm2.Marshal(rsp.OutPrivate)})
}

func (p *tpmProtector) Unwrap(wrapped []byte) ([]byte, error) {
	var b tpmBlob
	if err := json.Unmarshal(wrapped, &b); err != nil {
		return nil, fmt.Errorf("tpm: decoding wrapped key: %w", err)
	}
	if b.Version != tpmBlobVersion || b.Template != tpmBlobTemplate {
		return nil, fmt.Errorf("%w: tpm blob version %d template %q is not supported", ErrForeignKey, b.Version, b.Template)
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b.Public)
	if err != nil {
		return nil, fmt.Errorf("tpm: decoding public area: %w", err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](b.Private)
	if err != nil {
		return nil, fmt.Errorf("tpm: decoding private area: %w", err)
	}
	t, err := p.open()
	if err != nil {
		return nil, fmt.Errorf("%w: opening tpm: %v", ErrUnavailable, err)
	}
	defer t.Close()
	parent, flush, err := createSRK(t)
	if err != nil {
		return nil, err
	}
	defer flush()
	loaded, err := withRetry(func() (*tpm2.LoadResponse, error) {
		return tpm2.Load{
			ParentHandle: tpm2.AuthHandle{Handle: parent.Handle, Name: parent.Name, Auth: tpm2.PasswordAuth(nil)},
			InPrivate:    *priv,
			InPublic:     *pub,
		}.Execute(t)
	})
	if err != nil {
		return nil, fmt.Errorf("tpm Load: %w", classifyTPMError(err))
	}
	defer func() { _, _ = tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(t) }()
	out, err := withRetry(func() (*tpm2.UnsealResponse, error) {
		return tpm2.Unseal{ItemHandle: tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name, Auth: tpm2.PasswordAuth(nil)}}.Execute(t)
	})
	if err != nil {
		return nil, fmt.Errorf("tpm Unseal: %w", classifyTPMError(err))
	}
	return out.OutData.Buffer, nil
}

func tpmTier(open func() (transport.TPMCloser, error)) Tier {
	return Tier{
		Name: TierTPM,
		Probe: func() error {
			t, err := open()
			if err != nil {
				return fmt.Errorf("%w: opening tpm: %v", ErrUnavailable, err)
			}
			defer t.Close()
			return probeTPM(t)
		},
		Open: func(string) KeyProtector { return &tpmProtector{open: open} },
	}
}

func TPMTier() Tier { return tpmTier(openTPM) }
```

`tpm_open_linux.go` (`//go:build linux`):
```go
// openTPM prefers the kernel resource manager; /dev/tpm0 is exclusive-open and usually root/tss only.
func openTPM() (transport.TPMCloser, error) {
	if t, err := linuxtpm.Open("/dev/tpmrm0"); err == nil {
		return t, nil
	}
	return linuxtpm.Open("/dev/tpm0")
}
```
`tpm_open_windows.go` (`//go:build windows`): `func openTPM() (transport.TPMCloser, error) { return windowstpm.Open() }`.
`tpm_open_other.go` (`//go:build !linux && !windows`): `func openTPM() (transport.TPMCloser, error) { return nil, fmt.Errorf("%w: no TPM transport on this platform", ErrUnavailable) }`.

- [ ] **Step 1: Write the failing tests**

```go
// tpm_test.go
func TestCheckTPMProperties(t *testing.T)
    // (0, 0x2) → nil; (0x1, 0x2) → ErrTPMOwnerAuthSet; (0x200, 0x2) → ErrTPMLockout
    // (0x400, 0x2) → nil  (tpmGeneratedEPS is not lockout); (0, 0) → ErrTPMHierarchyDisabled
    // every non-nil result: errors.Is(err, ErrUnavailable)
func TestClassifyTPMError(t *testing.T)
    // tpm2.TPMRCBadAuth → Is ErrTPMOwnerAuthSet and ErrUnavailable; tpm2.TPMRCIntegrity → Is ErrForeignKey
    // tpm2.TPMRCLockout → Is ErrTPMLockout; errors.New("x") → returned unchanged
func TestTPMTier_OpenFailureUnavailable(t *testing.T) // tpmTier(func(){ return nil, os.ErrNotExist }).Probe() → Is ErrUnavailable
func TestProbeTPM_TransportError(t *testing.T)        // fake transport.TPM whose Send returns errors.New("boom") → probeTPM non-nil
func TestTPMProtector_RejectsBadInput(t *testing.T)
    // Wrap(16 bytes) → error; Unwrap([]byte("{")) → error, not ErrForeignKey
    // Unwrap(json of tpmBlob{Version: 2, Template: "ecc-srk"}) → Is ErrForeignKey, message contains "not supported"
```

```go
// tpm_swtpm_test.go
//go:build !windows

func TestTPMProtector_SWTPM(t *testing.T) {
	sock, ctrl := os.Getenv("GHP_TEST_SWTPM"), os.Getenv("GHP_TEST_SWTPM_CTRL")
	if sock == "" || ctrl == "" {
		t.Skip("GHP_TEST_SWTPM / GHP_TEST_SWTPM_CTRL not set; skipping swtpm seal/unseal test")
	}
	open := func() (transport.TPMCloser, error) { return linuxudstpm.Open(sock) }
	tier := tpmTier(open)
	dek := bytes.Repeat([]byte{0x42}, 32)
	// tier.Probe() == nil;                                   assertNoTransientHandles(t, sock)
	// w1, w2 := tier.Open("").Wrap(dek) twice; !bytes.Equal(w1, w2); assertNoTransientHandles
	// swtpmPowerCycle(t, ctrl, sock)
	// got := tier.Open("").Unwrap(w1) (fresh protector, fresh transport) == dek; assertNoTransientHandles
	// flip a byte inside tpmBlob.Private of w1 → Unwrap error;  assertNoTransientHandles
}

// swtpmPowerCycle sends CMD_INIT (00 00 00 02, flags 00 00 00 00) on the control socket,
// expects a 4-byte all-zero result, then issues TPM2_Startup(CLEAR) on the data socket.
func swtpmPowerCycle(t *testing.T, ctrl, sock string) {
	c, err := net.Dial("unix", ctrl) // t.Fatal on err; defer c.Close()
	// c.Write([]byte{0, 0, 0, 2, 0, 0, 0, 0}); resp := make([]byte, 4); io.ReadFull(c, resp); resp must be all zero
	tpm, err := linuxudstpm.Open(sock) // defer tpm.Close()
	// _, err = tpm2.Startup{StartupType: tpm2.TPMSUClear}.Execute(tpm); err == nil
}

// assertNoTransientHandles: GetCapability{Capability: tpm2.TPMCapHandles, Property: 0x80000000, PropertyCount: 16}
// → rsp.CapabilityData.Data.Handles() → len(Handle) == 0.
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/securestore/ -run 'TPM' -v`
Expected: FAIL (undefined symbols).

- [ ] **Step 3: Implement the four TPM files and add `TPMTier()` to `Default()`.**

- [ ] **Step 4: Promote go-tpm and verify**

Run: `go get github.com/google/go-tpm@v0.9.8 && go mod tidy && grep -n 'google/go-tpm ' go.mod`
Expected: `github.com/google/go-tpm v0.9.8` with no `// indirect`.

- [ ] **Step 5: Run tests and cross-vet**

Run: `CGO_ENABLED=0 go test ./internal/securestore/ -v && for t in windows/amd64 windows/arm64 darwin/arm64; do GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go vet ./internal/securestore/ || exit 1; done`
Expected: PASS with `TestTPMProtector_SWTPM` reported as SKIP; vet clean. On a Linux host with swtpm started by the Task 12 recipe, run with `GHP_TEST_SWTPM=/tmp/swtpm/tpm.sock GHP_TEST_SWTPM_CTRL=/tmp/swtpm/ctrl.sock` and expect PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/securestore/securestore.go internal/securestore/tpm.go internal/securestore/tpm_open_linux.go internal/securestore/tpm_open_windows.go internal/securestore/tpm_open_other.go internal/securestore/tpm_test.go internal/securestore/tpm_swtpm_test.go
git commit -m "feat(securestore): TPM key protector"
```

---

### Task 9: DPAPI and keychain key protectors

**Files:**
- Create: `internal/securestore/dpapi_windows.go`, `internal/securestore/dpapi_other.go`, `internal/securestore/keychain_darwin.go`, `internal/securestore/keychain_other.go`
- Test: `internal/securestore/dpapi_windows_test.go`, `internal/securestore/keychain_darwin_test.go`
- Modify: `internal/securestore/securestore.go` — add `DPAPITier(), KeychainTier()` to the existing `NewProtectors` call in `Default()`, keeping `TPMTier()` (result: `NewProtectors(TPMTier(), DPAPITier(), KeychainTier(), FileTier())`).

**Interfaces:**
- Consumes: Task 1 `Tier`, `ErrUnavailable`, `ErrForeignKey`; Task 8 `TPMTier` in `Default()`.
- Produces:
  ```go
  func DPAPITier() Tier    // every OS; non-windows Probe/Wrap/Unwrap return ErrUnavailable
  func KeychainTier() Tier // every OS; non-darwin Probe/Wrap/Unwrap return ErrUnavailable
  const KeychainService = "ghp-git-credential" // darwin file only
  ```

**DPAPI (windows):** `windows.CryptProtectData(&in, utf16("ghp git-credential cache key"), &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)`, user scope (no `CRYPTPROTECT_LOCAL_MACHINE`), entropy `[]byte("ghp-git-credential-cache-v1")`; copy `unsafe.Slice(out.Data, out.Size)` then `windows.LocalFree`. `Unwrap` mirrors with `CryptUnprotectData`. `Probe` = round-trip of 32 zero bytes.

**Keychain (darwin):** `keychainProtector{account string; run securityRunner}` with `type securityRunner func(ctx context.Context, stdin string, args ...string) ([]byte, error)` and package var `runSecurity securityRunner` that runs `/usr/bin/security` with a 10 s context timeout. On failure it returns `&securityError{Subcommand: <first non-flag arg or "-i">, ExitCode: n, Stderr: trimmed stderr}` whose `Error()` is `security <Subcommand>: exit <n>: <Stderr>`; it never includes stdout or the stdin script. `Open(scope)` sets `account = hex(sha256(scope))` (64 hex chars). `Wrap`: `run(ctx, fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n", KeychainService, account, base64.StdEncoding.EncodeToString(dek)), "-i")`, return `[]byte(account)`. `Unwrap`: require 64 lowercase hex (else error without running anything), `run(ctx, "", "find-generic-password", "-s", KeychainService, "-a", account, "-w")`; a `securityError` with exit code 44 (item not found) → `fmt.Errorf("%w: keychain item not found", ErrForeignKey)` so the cache is discarded; otherwise base64-decode the trimmed output and require 32 bytes. `Probe`: `/usr/bin/security` exists and `run(ctx, "", "show-keychain-info")` (the default keychain; fails while it is locked) succeeds.

- [ ] **Step 1: Write the failing tests**

```go
// keychain_darwin_test.go — swap runSecurity for a recorder
func TestKeychainProtector_SecretNeverInArgv(t *testing.T)
    // Wrap(dek): one call, args == []string{"-i"}, stdin contains "-s ghp-git-credential", "-a "+account, base64(dek)
    // Unwrap(wrapped): recorder returns base64(dek)+"\n"; got == dek; no recorded args contain base64(dek)
func TestKeychainProtector_ErrorsCarryNoSecret(t *testing.T)
    // recorder fails Wrap with the real error shape → err.Error() does not contain base64(dek)
func TestKeychainProtector_ItemNotFoundIsForeign(t *testing.T) // recorder returns &securityError{ExitCode: 44} → errors.Is(err, ErrForeignKey)
func TestKeychainProtector_ProbeUsesShowKeychainInfo(t *testing.T) // recorded args[0] == "show-keychain-info"; recorder error → Probe error
func TestKeychainAccount(t *testing.T)        // same scope → same 64-hex account; different scope → different
func TestKeychainProtector_UnwrapRejectsBadAccount(t *testing.T) // Unwrap([]byte("x; rm -rf")) → error, recorder not called
func TestKeychainProtector_RealKeychain(t *testing.T) // skip unless GHP_TEST_KEYCHAIN=1; real round trip with a t.Name()-derived scope, then delete the item
// dpapi_windows_test.go
func TestDPAPIProtector_RoundTrip(t *testing.T) // Probe nil; Unwrap(Wrap(dek)) == dek; Unwrap(tampered) → error
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/securestore/ -run 'Keychain|DPAPI' -v` (on macOS; elsewhere `GOOS=darwin CGO_ENABLED=0 go vet ./internal/securestore/`)
Expected: FAIL (undefined symbols).

- [ ] **Step 3: Implement the four files and update `Default()`.**

- [ ] **Step 4: Run tests and cross-vet**

Run: `CGO_ENABLED=0 go test ./internal/securestore/ -v && for t in windows/amd64 windows/arm64 darwin/arm64 darwin/amd64 linux/arm64; do GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go vet ./internal/securestore/ || exit 1; done`
Expected: PASS; vet clean on every target (this compiles the windows and darwin test files too).

- [ ] **Step 5: Commit**

```bash
git add internal/securestore/securestore.go internal/securestore/dpapi_windows.go internal/securestore/dpapi_other.go internal/securestore/keychain_darwin.go internal/securestore/keychain_other.go internal/securestore/dpapi_windows_test.go internal/securestore/keychain_darwin_test.go
git commit -m "feat(securestore): DPAPI and macOS keychain key protectors"
```

---

### Task 10: `ghp auth git-credential` command and non-interactive dotvault

**Files:**
- Create: `cmd/ghp/gitcredential.go`
- Test: `cmd/ghp/gitcredential_test.go`, `cmd/ghp/dotvault_test.go`, `cmd/ghp/main_test.go` (`TestHelpOutput_Auth` list)
- Modify: `cmd/ghp/dotvault.go`, `cmd/ghp/auth.go` (warning writer; `cmd.AddCommand(..., newAuthGitCredentialCmd())`), `cmd/ghp/main.go`

**Interfaces:**
- Consumes: Task 5/6 `gitcred.Run`, `Options`, `Config`, `Settings`, `DefaultHost`, `MessagePrefix`; Task 9 `securestore.Default`; `dvclient.ErrLoginRequired`.
- Produces:
  ```go
  // auth.go — thread a warning writer through config loading; existing callers keep os.Stderr
  func loadCLIConfigFileAt(path string, checkPerms bool, warn io.Writer) (*cliConfig, error)
  func loadCLIConfigFileWith(warn io.Writer) (*cliConfig, error) // loadCLIConfigFile() keeps os.Stderr
  func loadCLIConfigWith(warn io.Writer) (*cliConfig, error) // body of today's loadCLIConfig; calls loadCLIConfigFileWith(warn),
                                                             // because the insecure-permissions warning is printed in loadCLIConfigFile (cmd/ghp/auth.go:129), not in loadCLIConfig
  func loadCLIConfig() (*cliConfig, error)                    // loadCLIConfigWith(os.Stderr)
  // dotvault.go
  type dotvaultReader interface {
      Authenticate(ctx context.Context) error
      AuthenticateCached(ctx context.Context) error // never prompts; wraps dvclient.ErrLoginRequired when no cached token works
      ReadUserSecret(ctx context.Context, service, field string) (string, bool, error)
  }
  func (cfg *cliConfig) applyDotvault(ctx context.Context) error       // unchanged behaviour
  func (cfg *cliConfig) applyDotvaultCached(ctx context.Context) error // same validation and field mapping, AuthenticateCached
  func (cfg *cliConfig) resolveDotvault(ctx context.Context, authenticate func(dotvaultReader, context.Context) error) error // shared body; callers pass dotvaultReader.Authenticate / dotvaultReader.AuthenticateCached
  func loadCLIConfigCached(ctx context.Context, warn io.Writer) (*cliConfig, error) // loadCLIConfigWith(warn) + applyDotvaultCached
  // main.go
  type exitCodeError struct{ code int }
  func (e *exitCodeError) Error() string // "exit status <code>"
  // gitcredential.go
  func newAuthGitCredentialCmd() *cobra.Command
  func gitCredentialOptions(cmd *cobra.Command) gitcred.Options
  func gitCredentialCacheDir() string // "" when userCLIConfigPath() == ""
  var gitCredentialProtectors = securestore.Default // tests swap in a file-only set
  ```

`main()`: `var ec *exitCodeError; if errors.As(err, &ec) { os.Exit(ec.code) }` before the existing print. The command: `Use: "git-credential <operation>"`, `Args: cobra.ExactArgs(1)`, `SilenceErrors: true`, `SilenceUsage: true`, flags `--app` (default `""`), `--type` (`agent`), `--scopes` (`contents:write`), `--ttl` (`1h`), `--cache-backend` (`auto`), `--host` (string array, default `["github.com"]`). For each of the first five: the flag value if `cmd.Flags().Changed(name)`, else the env var (`GHP_GIT_CM_APP`, `GHP_GIT_CM_TYPE`, `GHP_GIT_CM_SCOPES`, `GHP_GIT_CM_TTL`, `GHP_GIT_CM_CACHE_BACKEND`) if non-empty, else the default. `ScopesExplicit` = `--scopes` changed or `GHP_GIT_CM_SCOPES` non-empty; `AppFromEnv` = `--app` not changed and `GHP_GIT_CM_APP` non-empty; `TypeFromFlag` = `--type` changed. `Hosts` = the `--host` values. `Hostname` from `os.Hostname()` (`"unknown"` on error). `CacheDir` = `gitCredentialCacheDir()`; `Protectors` = `gitCredentialProtectors()`. `LoadStatic` calls `loadCLIConfigWith(&buf)` and returns `gitcred.Config{ServerURL, UserToken, Warnings: non-empty trimmed lines of buf}`; `LoadAuthed` calls `loadCLIConfigCached(ctx, io.Discard)` (phase A already reported file warnings) and maps `errors.Is(err, dvclient.ErrLoginRequired)` to `errors.New("dotvault login required: run `ghp auth status` in a terminal to log in")`. `RunE`: `code := gitcred.Run(cmd.Context(), opts, args[0], cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())`; non-zero → `&exitCodeError{code}`. `Long` help lists the five operations, the six flags and the five env vars.

- [ ] **Step 1: Write the failing tests**

```go
// dotvault_test.go — fakeReader gains cachedErr error, cachedCalls int, and AuthenticateCached
func TestApplyDotvaultCached_NeverInteractive(t *testing.T) // resolves "vault-tok"; authCalls == 0; cachedCalls == 1
func TestApplyDotvaultCached_LoginRequired(t *testing.T)    // cachedErr = fmt.Errorf("x: %w", dvclient.ErrLoginRequired) → errors.Is(err, dvclient.ErrLoginRequired)
// main_test.go: TestHelpOutput_Auth expects "git-credential" too
// gitcredential_test.go — runGitCredential(t, stdin string, args ...string) (stdout, stderr string, code int)
// executes newRootCmd() with "auth", "git-credential", args...; HOME=t.TempDir(); GHP_SERVER_URL=fake; GHP_USER_TOKEN=ghpr_test;
// the five GHP_GIT_CM_* set to ""; gitCredentialProtectors swapped to file-only
func TestGitCredential_TypePrecedence(t *testing.T)
    // env GHP_GIT_CM_TYPE=proxy, no flag → mint type "proxy"; env proxy + --type agent → "agent"; neither → "agent"
func TestGitCredential_AppPrecedence(t *testing.T)
    // apps "main" (default) and "other": GHP_GIT_CM_APP=other → app_record_id of "other"; plus --app main → "main"
func TestGitCredential_EnvAppIgnoredUnderProxyFlag(t *testing.T)
    // GHP_GIT_CM_APP=other with --type proxy → code 0, mint type "proxy" without app fields
    // --app other --type proxy → code 1, stderr contains "--app is only valid with --type agent"
func TestGitCredential_ScopesFromEnvAreExplicit(t *testing.T)
    // installation contents:read: GHP_GIT_CM_SCOPES=contents:write → code 1; unset → code 0 with scopes "contents:read"
func TestGitCredential_HostFlag(t *testing.T)
    // request host=ghe.example.com without --host → code 1, stderr contains "is not configured for this helper"
    // with --host ghe.example.com → code 0 (and host=github.com then fails: the default list was replaced)
func TestGitCredential_ConfigWarningsPrefixed(t *testing.T)
    // unix only: user config written 0644 → stderr has a line starting "ghp git-credential: warning: config file"
func TestGitCredential_CacheUnderUserConfig(t *testing.T) // after get: $HOME/.config/ghp/git-credential/cache.enc exists
func TestGitCredential_DotvaultLoginRequired(t *testing.T)
    // GHP_USER_TOKEN="", user config with dotvault stanza mapping user_token; fakeReader.cachedErr wraps ErrLoginRequired
    // code 1; stderr == "ghp git-credential: dotvault login required: run `ghp auth status` in a terminal to log in\n"; authCalls == 0
func TestGitCredential_CacheHitSkipsDotvault(t *testing.T)
    // dotvault stanza resolving the token: 1st get → factory called once; 2nd get → factory still called once, same password
func TestGitCredential_UnknownOperation(t *testing.T) // "frobnicate" → code 0, stdout "", stderr ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./cmd/ghp/ -run 'GitCredential|DotvaultCached|TestHelpOutput_Auth' -v`
Expected: FAIL (undefined `newAuthGitCredentialCmd`, `applyDotvaultCached`; help missing `git-credential`).

- [ ] **Step 3: Implement the warning-writer refactor, the dotvault refactor, `exitCodeError`, `gitcredential.go`, and register the command.**

- [ ] **Step 4: Run all CLI tests**

Run: `CGO_ENABLED=0 go test ./cmd/ghp/ && go vet ./cmd/ghp/`
Expected: PASS (existing `TestApplyDotvault_*` and `TestLoadCLIConfig_*` unchanged and green), vet clean.

- [ ] **Step 5: Smoke-test the binary**

Run: `make build && printf 'protocol=https\nhost=github.com\n\n' | env -u GHP_SERVER_URL HOME=$(mktemp -d) ./ghp auth git-credential get; echo "exit=$?"`
Expected: one stderr line containing `ghp auth setup-git`, `exit=1`, nothing on stdout.

- [ ] **Step 6: Commit**

```bash
git add cmd/ghp/gitcredential.go cmd/ghp/gitcredential_test.go cmd/ghp/dotvault.go cmd/ghp/dotvault_test.go cmd/ghp/main.go cmd/ghp/main_test.go cmd/ghp/auth.go
git commit -m "feat(cli): ghp auth git-credential with non-interactive dotvault"
```

---

### Task 11: `ghp auth setup-git`

**Files:**
- Modify: `cmd/ghp/gitcredential.go`, `cmd/ghp/auth.go` (register `newAuthSetupGitCmd()`)
- Test: `cmd/ghp/gitcredential_test.go`, `cmd/ghp/main_test.go` (`TestHelpOutput_Auth` expects `setup-git`)

**Interfaces:**
- Consumes: Task 10 command file and `exitCodeError`; `gitcred.DefaultHost`.
- Produces:
  ```go
  func newAuthSetupGitCmd() *cobra.Command
  func gitCredentialHelperLine(ghp, host, app, tokenType string) (string, error)
  func shellQuote(s string) string
  func ghpCommand() (string, error)
  var osExecutable = os.Executable                             // tests swap
  var runGit = func(ctx context.Context, args ...string) error // exec "git" with args; stderr captured into the error
  ```

`shellQuote(s)`: return `s` unchanged only when it matches `^[A-Za-z0-9@%+=:,./_-]+$`; otherwise `"'" + strings.ReplaceAll(s, "'", `'\''`) + "'"`.

`gitCredentialHelperLine`: any of `ghp`, `host`, `app` containing `\n`, `\r` or NUL → error `<field> contains a newline, carriage return or NUL`. Words: `shellQuote(ghp)`, `auth`, `git-credential`; then `--host`, `shellQuote(host)` when `host` is not `github.com` (`asciiutil.EqualFold`); then `--app`, `shellQuote(app)` when `app != ""`; then `--type proxy` when `tokenType == "proxy"`. Joined by single spaces, prefixed `!`.

`ghpCommand()`: `exe, err := osExecutable()`; if `exec.LookPath("ghp")` succeeds and `filepath.EvalSymlinks` of both paths succeed and are equal → `"ghp"`; otherwise the unresolved `exe`.

Flags: `--host` (string array, default `["github.com"]`), `--app` (default `""`), `--type` (`agent`). `SilenceErrors` and `SilenceUsage` are set so a validation error is printed once by `main`. Validation before any git call: type must be `agent` or `proxy`; `--app` with `--type proxy` → `--app is only valid with --type agent`; each host must match `^[A-Za-z0-9.-]+(:[0-9]+)?$`; `gitCredentialHelperLine` errors (control characters in app, host or exe path) are returned. Per host, exactly:
1. `git config --global --replace-all credential.https://<host>.helper ""`
2. `git config --global --add credential.https://<host>.helper <line>`, where `ghp, err := ghpCommand()` is computed once before the host loop (error returned) and `line, err := gitCredentialHelperLine(ghp, host, app, type)` is computed for every host during validation, before any git call (error returned)
3. `git config --global credential.https://<host>.useHttpPath true`

Stdout per host:
```
Configured https://<host>:
  credential.https://<host>.helper = <line>
  credential.https://<host>.useHttpPath = true
```
then stderr once: `warning: replaced any existing credential helper for <hosts joined by ", "> (for example gh)`.

- [ ] **Step 1: Write the failing tests**

```go
func TestShellQuote(t *testing.T)
    // unchanged: "/usr/local/bin/ghp", "ghp", "my-app", "ghe.example.com:8443", "a@b%c+d=e,f"
    // quoted: "/opt/my tools/ghp" → "'/opt/my tools/ghp'"; `C:\Program Files\ghp.exe` → `'C:\Program Files\ghp.exe'`
    //   "prod;rm -rf ~" → "'prod;rm -rf ~'"; "a&b" → "'a&b'"; "a`b" → "'a`b'"; "a|b" → "'a|b'"
    //   `a"b` → `'a"b'`; "a$b" → "'a$b'"; "it's" → `'it'\''s'`
func TestGitCredentialHelperLine(t *testing.T)
    // ("ghp","github.com","","agent")          → "!ghp auth git-credential"
    // ("ghp","GitHub.com","","agent")          → "!ghp auth git-credential"
    // ("ghp","ghe.example.com","","agent")     → "!ghp auth git-credential --host ghe.example.com"
    // ("/usr/bin/ghp","github.com","my app","agent") → "!/usr/bin/ghp auth git-credential --app 'my app'"
    // ("ghp","github.com","prod;rm -rf ~","agent")   → "!ghp auth git-credential --app 'prod;rm -rf ~'"
    // ("ghp","github.com","","proxy")          → "!ghp auth git-credential --type proxy"
    // app "a\nb", app "a\rb", app "a\x00b", ghp "/x\n/ghp" → error
func TestGhpCommand(t *testing.T) // skip on windows
    // real := tmp/real-ghp (0755 file); osExecutable → real
    // PATH=dirA containing symlink "ghp" → real  → "ghp"
    // PATH=empty dir                              → real (unresolved)
    // osExecutable → link (symlink to real), PATH empty → link, not real
func TestSetupGit_WritesGlobalConfig(t *testing.T)
    // skip if exec.LookPath("git") fails. GIT_CONFIG_GLOBAL=<tmp>/gitconfig pre-seeded with
    //   "[credential \"https://github.com\"]\n\thelper = !gh auth git-credential\n"; GIT_CONFIG_NOSYSTEM=1; HOME=tmp
    // osExecutable → "/opt/my tools/ghp"; PATH = dir of the real git only (no ghp on PATH)
    // run "auth setup-git --host github.com --host ghe.example.com --app my-app"
    // `git config --global --get-all credential.https://github.com.helper` lines ==
    //   ["", "!'/opt/my tools/ghp' auth git-credential --app my-app"]
    // `... credential.https://ghe.example.com.helper` lines ==
    //   ["", "!'/opt/my tools/ghp' auth git-credential --host ghe.example.com --app my-app"]
    // useHttpPath == "true" for both hosts; stdout contains "Configured https://github.com:";
    // stderr contains "replaced any existing credential helper"
func TestSetupGit_Idempotent(t *testing.T)           // run twice → still exactly two helper values per host
func TestSetupGit_AppWithProxyRejected(t *testing.T) // error contains "--app is only valid"; runGit never called
func TestSetupGit_RejectsBadInput(t *testing.T)      // --host "github.com/evil", --host "a b", --app "x\ny" → error; runGit never called
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./cmd/ghp/ -run 'ShellQuote|HelperLine|GhpCommand|SetupGit|TestHelpOutput_Auth' -v`
Expected: FAIL (undefined symbols).

- [ ] **Step 3: Implement `setup-git` and register it.**

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./cmd/ghp/ && go vet ./cmd/ghp/`
Expected: PASS, vet clean.

- [ ] **Step 5: Commit**

```bash
git add cmd/ghp/gitcredential.go cmd/ghp/gitcredential_test.go cmd/ghp/auth.go cmd/ghp/main_test.go
git commit -m "feat(cli): ghp auth setup-git"
```

---

### Task 12: cross-compile vet and swtpm in CI

**Files:**
- Modify: `Makefile`, `.github/workflows/test.yml`

**Interfaces:**
- Consumes: Task 8 `TestTPMProtector_SWTPM` and its `GHP_TEST_SWTPM` / `GHP_TEST_SWTPM_CTRL` gate.
- Produces: `make vet-cross`; `make check` = `test vet vet-cross`.

- [ ] **Step 1: Add the Makefile target**

```make
## vet-cross: go vet for the non-host targets so build-tagged files cannot rot
vet-cross:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go vet ./...
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go vet ./...
```
Add `vet-cross` to `.PHONY` and change `check: test vet` to `check: test vet vet-cross`.

- [ ] **Step 2: Run it**

Run: `make vet-cross`
Expected: exit 0.

- [ ] **Step 3: Add CI steps to the `unit-tests` job, before `Run tests`**

```yaml
      - name: Install swtpm
        run: sudo apt-get update && sudo apt-get install -y swtpm

      - name: Start swtpm
        run: |
          mkdir -p /tmp/swtpm
          swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm \
            --server type=unixio,path=/tmp/swtpm/tpm.sock \
            --ctrl type=unixio,path=/tmp/swtpm/ctrl.sock \
            --flags not-need-init,startup-clear --daemon
```
Give the existing `Run tests` step:
```yaml
        env:
          GHP_TEST_SWTPM: /tmp/swtpm/tpm.sock
          GHP_TEST_SWTPM_CTRL: /tmp/swtpm/ctrl.sock
```
After it add:
```yaml
      - name: Cross-compile vet (windows, darwin)
        run: make vet-cross
```

- [ ] **Step 4: Validate the workflow file**

Run: `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 .github/workflows/test.yml` (or `actionlint` if installed)
Expected: no findings. If a Linux host with swtpm is at hand, run the Start swtpm script and `GHP_TEST_SWTPM=/tmp/swtpm/tpm.sock GHP_TEST_SWTPM_CTRL=/tmp/swtpm/ctrl.sock CGO_ENABLED=0 go test ./internal/securestore/ -run SWTPM -v` → PASS (not SKIP).

- [ ] **Step 5: Commit**

```bash
git add Makefile .github/workflows/test.yml
git commit -m "ci: cross-compile vet and swtpm-backed TPM test"
```

---

### Task 13: documentation

**Files:**
- Create: `docs/features/git-credential-helper.md`
- Modify: `docs/cli/auth.md`, `docs/cli/index.md`, `mkdocs.yml`, `CLAUDE.md`

**Interfaces:**
- Consumes: the behaviour, names and messages fixed in Tasks 1-12. Every flag, env var, file name and message quoted in the docs must match the code; check each by grepping the code before writing it down.
- Produces: user documentation.

- [ ] **Step 1: Write `docs/features/git-credential-helper.md`** with these sections, in order:
  1. **What it does** — git asks, the helper mints a 1h token pinned to the one `owner/repo`, caches it, reuses it until 5 minutes before expiry; the cache is keyed per ghp session identity, so two sessions on one account never share tokens.
  2. **Setup** — `ghp auth login`, then `ghp auth setup-git [--host ...] [--app NAME] [--type proxy]`; show the three config lines it writes; the helper path is the bare word `ghp` when `ghp` on `PATH` is the running binary, else the absolute path; non-default hosts get `--host HOST` baked in; note it replaces any previous helper (for example `gh`) for those hosts.
  3. **Choosing the app and token type** — the five-row table from §2 (setting, flag, env, default) plus `--host`; `GHP_GIT_CM_APP=other git push`; gitconfig variants with `--app`; `GHP_GIT_CM_APP` is ignored when the helper line says `--type proxy`; `--type proxy` for users without the ghp admin role and why pushes are then attributed to them; defaulted scopes lowered to what the installation grants, explicit scopes fail.
  4. **Cache tiers** — tpm > dpapi > keychain > file, where each applies, the minimum-tier rule (`tier` file survives `clear`), `--cache-backend none|<tier>`, the file-tier notice (printed again on the first write after `clear`), and `ghp auth git-credential status` / `clear` with sample `status` output.
  5. **Threat model** — §6 nearly verbatim, including that the file tier is file permissions only.
  6. **Known limitations** — every bullet in §8: clone URLs must end in `.git`; `useHttpPath` required; no LFS; agent tokens admin-only; `ghpr_` session expires in 30 days; git ≥ 2.41 for `password_expiry_utc`; Linux TPM needs the `tss` group; macOS keychain locked in non-GUI sessions (the helper then falls through to the next tier or runs uncached); Windows standard users rely on the TBS allow list, and on Windows the owner hierarchy auth is typically set by provisioning, so the TPM tier is usually unavailable and DPAPI is the effective tier (`status` shows which); a revoked or stale token costs one failed git command; the 20/min token-creation limit applies to cold caches. Add: no Secret Service backend yet (Linux without TPM uses the file tier); `--scopes workflows:read` makes the helper (and the server) log an unprefixed deprecation `WARN` line on stderr on every call; use `actions:read`.

- [ ] **Step 2: Update the other files**
  - `docs/cli/auth.md`: add `### ghp auth git-credential` (synopsis `ghp auth git-credential [flags] <get|store|erase|status|clear>`, flag table including `--host`, link to the feature page) and `### ghp auth setup-git` (synopsis, flags, the exact config commands, the bare-`ghp` rule, the quoting rule).
  - `docs/cli/index.md`: add the five `GHP_GIT_CM_*` rows to the variables table with their defaults.
  - `mkdocs.yml`: under `Features:` add `- Git Credential Helper: features/git-credential-helper.md` after `Webhooks`.
  - `CLAUDE.md` project structure: insert immediately after the line `  docs/           Embedded MkDocs output` the two lines `  gitcred/        git credential helper: protocol, encrypted token cache, ghp API client, app resolution` and `  securestore/    key protectors for the git credential cache (TPM, DPAPI, keychain, file)`.

- [ ] **Step 3: Build the docs**

Run: `uvx --with mkdocs-shadcn==0.10.2 mkdocs build --site-dir "$(mktemp -d)" 2>&1 | grep -iE 'warning|error' | grep -i 'git-credential' ; echo "grep-exit=$?"`
Expected: `grep-exit=1` (no warning or error mentions the new page).

- [ ] **Step 4: Check names against the code**

Run: `for s in GHP_GIT_CM_APP GHP_GIT_CM_TYPE GHP_GIT_CM_SCOPES GHP_GIT_CM_TTL GHP_GIT_CM_CACHE_BACKEND cache.enc cache.lock ghp-git-credential useHttpPath show-keychain-info; do grep -rq "$s" cmd/ghp internal/gitcred internal/securestore || echo "missing in code: $s"; done`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add docs/features/git-credential-helper.md docs/cli/auth.md docs/cli/index.md mkdocs.yml CLAUDE.md
git commit -m "docs: git credential helper"
```

---

## Final verification (after Task 13)

- [ ] Run: `make check && CGO_ENABLED=0 go build ./... && for t in linux/arm64 darwin/amd64 windows/arm64; do GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go build -o /dev/null ./cmd/ghp || exit 1; done`
  Expected: all tests pass, vet clean on host and the three cross targets, the binary builds for the remaining targets.
