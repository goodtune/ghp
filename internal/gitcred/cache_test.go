package gitcred

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/securestore"
)

// testNow is the fixed clock of every test cache.
var testNow = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

// xorProtector is a test-only KeyProtector that XORs every byte with 0x5a.
type xorProtector struct {
	name               string
	wrapErr, unwrapErr error
}

func (x xorProtector) Name() string { return x.name }

func (x xorProtector) Wrap(dek []byte) ([]byte, error) {
	if x.wrapErr != nil {
		return nil, x.wrapErr
	}
	return xorBytes(dek), nil
}

func (x xorProtector) Unwrap(wrapped []byte) ([]byte, error) {
	if x.unwrapErr != nil {
		return nil, x.unwrapErr
	}
	return xorBytes(wrapped), nil
}

func xorBytes(in []byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		out[i] = b ^ 0x5a
	}
	return out
}

// fakeTiers builds tpm, keychain and file tiers whose availability and
// wrap/unwrap errors are read from the maps at call time. file is available
// unless avail["file"] is explicitly false.
type fakeTiers struct {
	mu                 sync.Mutex
	avail              map[string]bool
	wrapErr, unwrapErr map[string]error
}

func newFakeTiers() *fakeTiers {
	return &fakeTiers{
		avail:     map[string]bool{},
		wrapErr:   map[string]error{},
		unwrapErr: map[string]error{},
	}
}

func (f *fakeTiers) set(fn func(f *fakeTiers)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeTiers) tier(name string) securestore.Tier {
	return securestore.Tier{
		Name: name,
		Probe: func() error {
			f.mu.Lock()
			defer f.mu.Unlock()
			ok, set := f.avail[name]
			if !set {
				ok = name == securestore.TierFile
			}
			if !ok {
				return errors.New("not present")
			}
			return nil
		},
		Open: func(string) securestore.KeyProtector {
			f.mu.Lock()
			defer f.mu.Unlock()
			return xorProtector{name: name, wrapErr: f.wrapErr[name], unwrapErr: f.unwrapErr[name]}
		},
	}
}

func (f *fakeTiers) protectors() *securestore.Protectors {
	return securestore.NewProtectors(f.tier(securestore.TierTPM), f.tier(securestore.TierKeychain), f.tier(securestore.TierFile))
}

func newCache(t *testing.T, dir, backend string, f *fakeTiers) *Cache {
	t.Helper()
	return &Cache{
		Dir:        dir,
		Backend:    backend,
		Protectors: f.protectors(),
		Stderr:     &bytes.Buffer{},
		Now:        func() time.Time { return testNow },
	}
}

func stderrOf(c *Cache) string { return c.Stderr.(*bytes.Buffer).String() }

func in(repo string) KeyInput {
	return KeyInput{
		ServerURL:  "https://ghp.example.com",
		Identity:   "id-a",
		Type:       "agent",
		Repository: repo,
		Scopes:     "contents:write",
	}
}

func freshEntry(token string) Entry {
	return Entry{
		Token:      token,
		TokenID:    "tid-" + token,
		Type:       "agent",
		Repository: "goodtune/ghp",
		Scopes:     "contents:write",
		ExpiresAt:  testNow.Add(time.Hour),
		MintedAt:   testNow,
	}
}

func mustOpen(t *testing.T, c *Cache) *Session {
	t.Helper()
	s, err := c.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// putCommit opens c, stores e under in(repo), commits and closes.
func putCommit(t *testing.T, c *Cache, repo string, e Entry) {
	t.Helper()
	s := mustOpen(t, c)
	s.Put(in(repo), e)
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readEnvelope(t *testing.T, dir string) envelope {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(readFile(t, filepath.Join(dir, CacheFileName)), &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	return env
}

func readTier(t *testing.T, dir string) string {
	t.Helper()
	return string(readFile(t, filepath.Join(dir, TierFileName)))
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s exists (err %v), want absent", path, err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", filepath.Base(path), got, want)
	}
}

func TestCacheKey(t *testing.T) {
	base := KeyInput{
		ServerURL:  "https://g",
		Identity:   "id",
		Type:       "agent",
		App:        "my-app",
		Repository: "goodtune/ghp",
		Scopes:     "contents:write",
	}
	if k1, k2 := CacheKey(base), CacheKey(base); k1 != k2 {
		t.Fatal("CacheKey is not stable")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(CacheKey(base)) {
		t.Errorf("CacheKey = %q, want 64 hex chars", CacheKey(base))
	}

	differ := []struct {
		name   string
		mutate func(k *KeyInput)
	}{
		{"server url", func(k *KeyInput) { k.ServerURL = "https://h" }},
		{"identity", func(k *KeyInput) { k.Identity = "other" }},
		{"type", func(k *KeyInput) { k.Type = "proxy" }},
		{"app", func(k *KeyInput) { k.App = "other-app" }},
		{"repository", func(k *KeyInput) { k.Repository = "goodtune/other" }},
		{"scopes", func(k *KeyInput) { k.Scopes = "contents:read" }},
	}
	for _, tt := range differ {
		t.Run("differs on "+tt.name, func(t *testing.T) {
			k := base
			tt.mutate(&k)
			if CacheKey(k) == CacheKey(base) {
				t.Errorf("changing %s did not change the key", tt.name)
			}
		})
	}

	same := []struct {
		name string
		a, b KeyInput
	}{
		{"repository case", KeyInput{Repository: "GoodTune/GHP"}, KeyInput{Repository: "goodtune/ghp"}},
		{"server trailing slash", KeyInput{ServerURL: "https://g/"}, KeyInput{ServerURL: "https://g"}},
	}
	for _, tt := range same {
		t.Run("equal on "+tt.name, func(t *testing.T) {
			if CacheKey(tt.a) != CacheKey(tt.b) {
				t.Errorf("CacheKey(%+v) != CacheKey(%+v)", tt.a, tt.b)
			}
		})
	}

	t.Run("field boundaries", func(t *testing.T) {
		if CacheKey(KeyInput{Type: "ab", App: "c"}) == CacheKey(KeyInput{Type: "a", App: "bc"}) {
			t.Error("fields are not separated")
		}
	})
}

func TestIdentityFor(t *testing.T) {
	if got := IdentityFor(""); got != IdentityDotvault {
		t.Errorf(`IdentityFor("") = %q, want %q`, got, IdentityDotvault)
	}
	got := IdentityFor("ghpr_x")
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(got) {
		t.Errorf("IdentityFor = %q, want 64 hex chars", got)
	}
	if strings.Contains(got, "ghpr_x") {
		t.Error("IdentityFor leaks the token")
	}
	if IdentityFor("ghpr_x") != got {
		t.Error("IdentityFor is not stable")
	}
	if IdentityFor("ghpr_y") == got {
		t.Error("IdentityFor ignores the token")
	}
}

func TestNormalizeScopes(t *testing.T) {
	tests := []struct {
		name   string
		scopes map[string]string
		want   string
	}{
		{"sorted", map[string]string{"pull_requests": "write", "contents": "read"}, "contents:read,pull_requests:write"},
		{"single", map[string]string{"contents": "write"}, "contents:write"},
		{"empty", map[string]string{}, ""},
		{"nil", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeScopes(tt.scopes); got != tt.want {
				t.Errorf("NormalizeScopes = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEntry_Fresh(t *testing.T) {
	tests := []struct {
		name    string
		expires time.Duration
		want    bool
	}{
		{"six minutes", 6 * time.Minute, true},
		{"exactly five minutes", 5 * time.Minute, false},
		{"four minutes", 4 * time.Minute, false},
		{"expired", -time.Minute, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := Entry{ExpiresAt: testNow.Add(tt.expires)}
			if got := e.Fresh(testNow); got != tt.want {
				t.Errorf("Fresh = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCache_RoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "git-credential")
	f := newFakeTiers()
	c := newCache(t, dir, "", f)
	want := Entry{
		Token:       "gha_secret_token_value",
		TokenID:     "tid-1",
		Type:        "agent",
		AppRecordID: "app-rec",
		AppName:     "my-app",
		Repository:  "GoodTune/GHP",
		Scopes:      "contents:write,pull_requests:read",
		ExpiresAt:   testNow.Add(time.Hour),
		MintedAt:    testNow,
		Identity:    "ignored, replaced by Put",
	}
	putCommit(t, c, "GoodTune/GHP", want)

	s := mustOpen(t, newCache(t, dir, "", f))
	got, ok := s.Get(in("goodtune/ghp"))
	if !ok {
		t.Fatal("Get missed after round trip")
	}
	want.Identity = "id-a"
	if !got.ExpiresAt.Equal(want.ExpiresAt) || !got.MintedAt.Equal(want.MintedAt) {
		t.Errorf("times = %v/%v, want %v/%v", got.ExpiresAt, got.MintedAt, want.ExpiresAt, want.MintedAt)
	}
	got.ExpiresAt, got.MintedAt = want.ExpiresAt, want.MintedAt
	if got != want {
		t.Errorf("Get = %+v, want %+v", got, want)
	}
	if s.Backend() != "file" || s.MinTier() != "file" || !s.Readable() || s.ReadError() != nil {
		t.Errorf("Backend/MinTier/Readable/ReadError = %q/%q/%v/%v", s.Backend(), s.MinTier(), s.Readable(), s.ReadError())
	}
	if s.Path() != filepath.Join(dir, CacheFileName) {
		t.Errorf("Path = %q", s.Path())
	}

	if tier := readTier(t, dir); tier != "file" {
		t.Errorf("tier file = %q, want file", tier)
	}
	env := readEnvelope(t, dir)
	if env.Version != 1 || env.Backend != "file" {
		t.Errorf("envelope version/backend = %d/%q", env.Version, env.Backend)
	}
	if bytes.Contains(readFile(t, filepath.Join(dir, CacheFileName)), []byte(want.Token)) {
		t.Error("cache.enc contains the token in clear")
	}
	if runtime.GOOS != "windows" {
		assertMode(t, dir, 0o700)
		assertMode(t, filepath.Join(dir, CacheFileName), 0o600)
		assertMode(t, filepath.Join(dir, TierFileName), 0o600)
	}
}

func TestCache_IdentityMismatchIsMiss(t *testing.T) {
	dir := t.TempDir()
	f := newFakeTiers()
	s := mustOpen(t, newCache(t, dir, "", f))
	inA := in("goodtune/ghp")
	s.Put(inA, freshEntry("a"))
	inB := inA
	inB.Identity = "id-b"
	if _, ok := s.Get(inB); ok {
		t.Error("Get with another identity hit")
	}

	t.Run("entry identity differs from key identity", func(t *testing.T) {
		s.entries[CacheKey(inB)] = Entry{Token: "x", Identity: "id-a", ExpiresAt: testNow.Add(time.Hour)}
		if _, ok := s.Get(inB); ok {
			t.Error("Get returned an entry whose identity differs")
		}
		if _, ok := s.Delete(inB); ok {
			t.Error("Delete returned an entry whose identity differs")
		}
	})
}

func TestSession_DeleteAndEntries(t *testing.T) {
	dir := t.TempDir()
	f := newFakeTiers()
	c := newCache(t, dir, "", f)
	s := mustOpen(t, c)
	s.Put(in("o/a"), freshEntry("a"))
	s.Put(in("o/b"), freshEntry("b"))

	entries := s.Entries()
	if len(entries) != 2 {
		t.Fatalf("Entries len = %d, want 2", len(entries))
	}
	delete(entries, CacheKey(in("o/a")))
	if _, ok := s.Get(in("o/a")); !ok {
		t.Error("Entries returned the internal map, not a copy")
	}

	got, ok := s.Delete(in("o/a"))
	if !ok || got.Token != "a" {
		t.Errorf("Delete = %+v, %v", got, ok)
	}
	if _, ok := s.Delete(in("o/a")); ok {
		t.Error("second Delete hit")
	}
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := mustOpen(t, newCache(t, dir, "", f))
	if _, ok := s2.Get(in("o/a")); ok {
		t.Error("deleted entry survived")
	}
	if _, ok := s2.Get(in("o/b")); !ok {
		t.Error("kept entry lost")
	}
}

func TestCache_FileTierNotice(t *testing.T) {
	dir := t.TempDir()
	f := newFakeTiers()
	const notice = "file permissions only"

	c1 := newCache(t, dir, "", f)
	putCommit(t, c1, "o/r", freshEntry("a"))
	if !strings.Contains(stderrOf(c1), MessagePrefix+"cache protected by "+notice+"; see docs\n") {
		t.Errorf("first write stderr = %q, want the file-tier notice", stderrOf(c1))
	}

	c2 := newCache(t, dir, "", f)
	putCommit(t, c2, "o/r2", freshEntry("b"))
	if strings.Contains(stderrOf(c2), notice) {
		t.Errorf("second write repeated the notice: %q", stderrOf(c2))
	}

	c3 := newCache(t, dir, "", f)
	s := mustOpen(t, c3)
	s.Clear()
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	c4 := newCache(t, dir, "", f)
	putCommit(t, c4, "o/r", freshEntry("c"))
	if !strings.Contains(stderrOf(c4), notice) {
		t.Errorf("write after clear stderr = %q, want the notice again", stderrOf(c4))
	}
}

func TestCache_TamperedEnvelopeDiscarded(t *testing.T) {
	editEnvelope := func(fn func(env *envelope)) func(t *testing.T, path string) {
		return func(t *testing.T, path string) {
			var env envelope
			if err := json.Unmarshal(readFile(t, path), &env); err != nil {
				t.Fatal(err)
			}
			fn(&env)
			b, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, path, string(b))
		}
	}
	tests := []struct {
		name   string
		tamper func(t *testing.T, path string)
	}{
		{"flip ciphertext byte", editEnvelope(func(env *envelope) { env.Ciphertext[0] ^= 1 })},
		{"flip nonce byte", editEnvelope(func(env *envelope) { env.Nonce[0] ^= 1 })},
		{"change wrapped key", editEnvelope(func(env *envelope) { env.WrappedKey[0] ^= 1 })},
		{"short nonce", editEnvelope(func(env *envelope) { env.Nonce = env.Nonce[:4] })},
		{"short wrapped key", editEnvelope(func(env *envelope) { env.WrappedKey = env.WrappedKey[:16] })},
		{"version 2", editEnvelope(func(env *envelope) { env.Version = 2 })},
		{"unknown backend", editEnvelope(func(env *envelope) { env.Backend = "vault" })},
		// The fake keychain unwraps exactly like the fake file tier, so only
		// the AAD detects the relabelled header.
		{"relabelled backend", editEnvelope(func(env *envelope) { env.Backend = "keychain" })},
		{"authentic envelope with a 16-byte key", func(t *testing.T, path string) {
			writeFile(t, path, string(forgeEnvelope(t, make([]byte, 16), map[string]Entry{
				CacheKey(in("o/r")): {Token: "forged", Identity: "id-a", ExpiresAt: testNow.Add(time.Hour)},
			})))
		}},
		{"truncated json", func(t *testing.T, path string) { writeFile(t, path, "{") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			f := newFakeTiers()
			putCommit(t, newCache(t, dir, "", f), "o/r", freshEntry("a"))
			tt.tamper(t, filepath.Join(dir, CacheFileName))

			c := newCache(t, dir, "", f)
			s := mustOpen(t, c)
			if !s.Readable() {
				t.Errorf("Readable() = false, want true (ReadError %v)", s.ReadError())
			}
			if _, ok := s.Get(in("o/r")); ok {
				t.Error("Get hit on a tampered envelope")
			}
			if s.Backend() != "" {
				t.Errorf("Backend() = %q, want empty", s.Backend())
			}
			s.Put(in("o/r"), freshEntry("b"))
			if err := s.Commit(); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if tier := readTier(t, dir); tier != "file" {
				t.Errorf("tier = %q, want file", tier)
			}
			s2 := mustOpen(t, newCache(t, dir, "", f))
			if e, ok := s2.Get(in("o/r")); !ok || e.Token != "b" {
				t.Errorf("rewritten cache Get = %+v, %v", e, ok)
			}
		})
	}
}

// forgeEnvelope builds a correctly authenticated file-tier envelope under
// dek without going through the cache code.
func forgeEnvelope(t *testing.T, dek []byte, entries map[string]Entry) []byte {
	t.Helper()
	plain, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := xorBytes(dek)
	aad, err := json.Marshal(struct {
		Version    int    `json:"version"`
		Backend    string `json:"backend"`
		WrappedKey []byte `json:"wrapped_key"`
	}{1, "file", wrapped})
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	b, err := json.Marshal(envelope{
		Version:    1,
		Backend:    "file",
		WrappedKey: wrapped,
		Nonce:      nonce,
		Ciphertext: gcm.Seal(nil, nonce, plain, aad),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCache_ReadsForgedEnvelope(t *testing.T) {
	// Guards forgeEnvelope: with a 32-byte key the forged envelope is read,
	// so the 16-byte case in TestCache_TamperedEnvelopeDiscarded is
	// rejected for its key length alone.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, CacheFileName), string(forgeEnvelope(t, make([]byte, 32), map[string]Entry{
		CacheKey(in("o/r")): {Token: "forged", Identity: "id-a", ExpiresAt: testNow.Add(time.Hour)},
	})))
	s := mustOpen(t, newCache(t, dir, "", newFakeTiers()))
	if e, ok := s.Get(in("o/r")); !ok || e.Token != "forged" {
		t.Errorf("Get = %+v, %v; want the forged entry", e, ok)
	}
}

func TestCache_TierFileParsing(t *testing.T) {
	tests := []struct {
		name, content, want string
	}{
		{"newline trimmed", "file\n", "file"},
		{"empty", "", ""},
		{"whitespace", " \n", ""},
		{"keychain", "keychain", "keychain"},
		{"garbage", "garbage", "tpm"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, TierFileName), tt.content)
			s := mustOpen(t, newCache(t, dir, "", newFakeTiers()))
			if got := s.MinTier(); got != tt.want {
				t.Errorf("MinTier() = %q, want %q", got, tt.want)
			}
		})
	}
	t.Run("absent", func(t *testing.T) {
		s := mustOpen(t, newCache(t, t.TempDir(), "", newFakeTiers()))
		if got := s.MinTier(); got != "" {
			t.Errorf("MinTier() = %q, want empty", got)
		}
	})
}

func TestCache_AutoRefusesWeakerTier(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, TierFileName), "tpm")
	f := newFakeTiers() // tpm unavailable, file available
	c := newCache(t, dir, "", f)
	putCommit(t, c, "o/r", freshEntry("a"))
	assertAbsent(t, filepath.Join(dir, CacheFileName))
	if want := MessagePrefix + `no cache tier at least as strong as "tpm" is available; token not cached (use --cache-backend <tier> to accept a weaker tier)` + "\n"; !strings.Contains(stderrOf(c), want) {
		t.Errorf("stderr = %q, want %q", stderrOf(c), want)
	}
	if tier := readTier(t, dir); tier != "tpm" {
		t.Errorf("tier = %q, want tpm", tier)
	}
}

func TestCache_AutoDiscardsEnvelopeWeakerThanTier(t *testing.T) {
	dir := t.TempDir()
	f := newFakeTiers()
	putCommit(t, newCache(t, dir, "", f), "o/r", freshEntry("a"))
	before := readFile(t, filepath.Join(dir, CacheFileName))
	writeFile(t, filepath.Join(dir, TierFileName), "keychain")

	c := newCache(t, dir, "", f)
	s := mustOpen(t, c)
	if _, ok := s.Get(in("o/r")); ok {
		t.Error("Get hit on an envelope weaker than the tier")
	}
	s.Put(in("o/r2"), freshEntry("b"))
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(dir, CacheFileName)), before) {
		t.Error("cache.enc was rewritten under a weaker tier")
	}
	if !strings.Contains(stderrOf(c), "no cache tier") {
		t.Errorf("stderr = %q, want the no-tier notice", stderrOf(c))
	}

	f.set(func(f *fakeTiers) { f.avail["keychain"] = true })
	putCommit(t, newCache(t, dir, "", f), "o/r3", freshEntry("c"))
	if env := readEnvelope(t, dir); env.Backend != "keychain" {
		t.Errorf("envelope backend = %q, want keychain", env.Backend)
	}
}

func TestCache_AutoUpgrades(t *testing.T) {
	dir := t.TempDir()
	f := newFakeTiers()
	putCommit(t, newCache(t, dir, "", f), "o/a", freshEntry("a"))

	f.set(func(f *fakeTiers) { f.avail["keychain"] = true })
	c := newCache(t, dir, "", f)
	s := mustOpen(t, c)
	if _, ok := s.Get(in("o/a")); !ok {
		t.Fatal("Get(a) missed before the upgrade")
	}
	s.Put(in("o/b"), freshEntry("b"))
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if s.Backend() != "keychain" || s.MinTier() != "keychain" {
		t.Errorf("after upgrade Backend/MinTier = %q/%q", s.Backend(), s.MinTier())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if env := readEnvelope(t, dir); env.Backend != "keychain" {
		t.Errorf("envelope backend = %q, want keychain", env.Backend)
	}
	if tier := readTier(t, dir); tier != "keychain" {
		t.Errorf("tier = %q, want keychain", tier)
	}
	if strings.Contains(stderrOf(c), "file permissions only") {
		t.Errorf("keychain write printed the file notice: %q", stderrOf(c))
	}

	s2 := mustOpen(t, newCache(t, dir, "", f))
	for _, repo := range []string{"o/a", "o/b"} {
		if _, ok := s2.Get(in(repo)); !ok {
			t.Errorf("Get(%s) missed after the upgrade", repo)
		}
	}
}

func TestCache_WrapFailureFallsThrough(t *testing.T) {
	failingTPM := func() *fakeTiers {
		f := newFakeTiers()
		f.avail["tpm"] = true
		f.avail["keychain"] = true
		f.wrapErr["tpm"] = errors.New("tpm busy")
		return f
	}

	t.Run("auto falls through to keychain", func(t *testing.T) {
		dir := t.TempDir()
		putCommit(t, newCache(t, dir, "", failingTPM()), "o/r", freshEntry("a"))
		if env := readEnvelope(t, dir); env.Backend != "keychain" {
			t.Errorf("envelope backend = %q, want keychain", env.Backend)
		}
		if tier := readTier(t, dir); tier != "keychain" {
			t.Errorf("tier = %q, want keychain", tier)
		}
	})

	t.Run("auto with tier tpm writes nothing", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, TierFileName), "tpm")
		c := newCache(t, dir, "", failingTPM())
		putCommit(t, c, "o/r", freshEntry("a"))
		assertAbsent(t, filepath.Join(dir, CacheFileName))
		if !strings.Contains(stderrOf(c), "no cache tier") {
			t.Errorf("stderr = %q, want the no-tier notice", stderrOf(c))
		}
		if tier := readTier(t, dir); tier != "tpm" {
			t.Errorf("tier = %q, want tpm", tier)
		}
	})

	t.Run("explicit tpm returns the wrap error", func(t *testing.T) {
		dir := t.TempDir()
		s := mustOpen(t, newCache(t, dir, "tpm", failingTPM()))
		s.Put(in("o/r"), freshEntry("a"))
		err := s.Commit()
		if err == nil || !strings.Contains(err.Error(), "wrapping cache key with tpm") {
			t.Errorf("Commit error = %v, want wrapping cache key with tpm", err)
		}
		assertAbsent(t, filepath.Join(dir, CacheFileName))
	})
}

func TestCache_TierRaisedBeforeEnvelope(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, CacheFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	f := newFakeTiers()
	f.avail["keychain"] = true
	s := mustOpen(t, newCache(t, dir, "", f))
	s.Put(in("o/r"), freshEntry("a"))
	if err := s.Commit(); err == nil {
		t.Fatal("Commit onto a directory succeeded")
	}
	if tier := readTier(t, dir); tier != "keychain" {
		t.Errorf("tier = %q, want keychain", tier)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".cache-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("temp files left behind: %v", matches)
	}
}

func TestCache_UnwrapFailureNeverRewrites(t *testing.T) {
	dir := t.TempDir()
	f := newFakeTiers()
	f.avail["keychain"] = true
	putCommit(t, newCache(t, dir, "", f), "o/r", freshEntry("a"))
	before := readFile(t, filepath.Join(dir, CacheFileName))

	f.set(func(f *fakeTiers) { f.unwrapErr["keychain"] = errors.New("locked\r\nin ssh") })
	c := newCache(t, dir, "", f)
	s := mustOpen(t, c)
	if s.Readable() {
		t.Error("Readable() = true after Unwrap failed")
	}
	if s.ReadError() == nil {
		t.Error("ReadError() = nil after Unwrap failed")
	}
	if s.Backend() != "keychain" {
		t.Errorf("Backend() = %q, want keychain", s.Backend())
	}
	if _, ok := s.Get(in("o/r")); ok {
		t.Error("Get hit on an unreadable cache")
	}
	s.Put(in("o/r2"), freshEntry("b"))
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(dir, CacheFileName)), before) {
		t.Error("unreadable cache.enc was rewritten")
	}
	want := MessagePrefix + "cannot read the credential cache (keychain: locked  in ssh); continuing without it (run ghp auth git-credential clear if this persists)\n"
	if got := stderrOf(c); got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
}

func TestCache_ForeignKeyDiscards(t *testing.T) {
	dir := t.TempDir()
	f := newFakeTiers()
	f.avail["tpm"] = true
	putCommit(t, newCache(t, dir, "", f), "o/r", freshEntry("a"))
	before := readFile(t, filepath.Join(dir, CacheFileName))

	f.set(func(f *fakeTiers) { f.unwrapErr["tpm"] = fmt.Errorf("x: %w", securestore.ErrForeignKey) })
	c := newCache(t, dir, "", f)
	s := mustOpen(t, c)
	if !s.Readable() {
		t.Errorf("Readable() = false after a foreign key (ReadError %v)", s.ReadError())
	}
	if _, ok := s.Get(in("o/r")); ok {
		t.Error("Get hit on a foreign envelope")
	}
	s.Put(in("o/r2"), freshEntry("b"))
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(readFile(t, filepath.Join(dir, CacheFileName)), before) {
		t.Error("foreign envelope was not rewritten")
	}
	if env := readEnvelope(t, dir); env.Backend != "tpm" {
		t.Errorf("envelope backend = %q, want tpm", env.Backend)
	}
	if stderrOf(c) != "" {
		t.Errorf("stderr = %q, want empty", stderrOf(c))
	}

	f.set(func(f *fakeTiers) { delete(f.unwrapErr, "tpm") })
	s2 := mustOpen(t, newCache(t, dir, "", f))
	if _, ok := s2.Get(in("o/r2")); !ok {
		t.Error("rewritten entry missing")
	}
}

func TestCache_ExplicitBackend(t *testing.T) {
	t.Run("unavailable tier", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "cache")
		_, err := newCache(t, dir, "tpm", newFakeTiers()).Open()
		if !errors.Is(err, securestore.ErrUnavailable) {
			t.Errorf("Open error = %v, want ErrUnavailable", err)
		}
		assertAbsent(t, dir)
	})

	t.Run("unknown backend", func(t *testing.T) {
		_, err := newCache(t, t.TempDir(), "bogus", newFakeTiers()).Open()
		if !errors.Is(err, ErrInvalidBackend) {
			t.Errorf("Open error = %v, want ErrInvalidBackend", err)
		}
		if err != nil && !strings.Contains(err.Error(), `"bogus" (want auto, none, tpm, dpapi, keychain or file)`) {
			t.Errorf("Open error text = %q", err)
		}
	})

	t.Run("tier known to the backend list but not to this build", func(t *testing.T) {
		_, err := newCache(t, t.TempDir(), "dpapi", newFakeTiers()).Open()
		if !errors.Is(err, securestore.ErrUnknownTier) {
			t.Errorf("Open error = %v, want ErrUnknownTier", err)
		}
	})

	t.Run("lowered at the user's request", func(t *testing.T) {
		dir := t.TempDir()
		f := newFakeTiers()
		f.avail["tpm"] = true
		putCommit(t, newCache(t, dir, "", f), "o/r", freshEntry("a"))

		c := newCache(t, dir, "file", f)
		s := mustOpen(t, c)
		if _, ok := s.Get(in("o/r")); ok {
			t.Error("Get hit on an envelope under another tier")
		}
		s.Put(in("o/r2"), freshEntry("b"))
		if err := s.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if env := readEnvelope(t, dir); env.Backend != "file" {
			t.Errorf("envelope backend = %q, want file", env.Backend)
		}
		if tier := readTier(t, dir); tier != "file" {
			t.Errorf("tier = %q, want file", tier)
		}
		if want := MessagePrefix + `cache tier lowered from "tpm" to "file" at your request` + "\n"; !strings.Contains(stderrOf(c), want) {
			t.Errorf("stderr = %q, want %q", stderrOf(c), want)
		}
	})

	t.Run("lowered from the tier file when there is no envelope", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, TierFileName), "keychain")
		c := newCache(t, dir, "file", newFakeTiers())
		putCommit(t, c, "o/r", freshEntry("a"))
		if !strings.Contains(stderrOf(c), `lowered from "keychain" to "file"`) {
			t.Errorf("stderr = %q, want the lowered notice", stderrOf(c))
		}
	})

	t.Run("same tier reuses the envelope", func(t *testing.T) {
		dir := t.TempDir()
		f := newFakeTiers()
		f.avail["keychain"] = true
		putCommit(t, newCache(t, dir, "keychain", f), "o/a", freshEntry("a"))
		before := readEnvelope(t, dir)

		c := newCache(t, dir, "keychain", f)
		putCommit(t, c, "o/b", freshEntry("b"))
		after := readEnvelope(t, dir)
		if !bytes.Equal(before.WrappedKey, after.WrappedKey) {
			t.Error("explicit same-tier commit replaced the wrapped key")
		}
		if stderrOf(c) != "" {
			t.Errorf("stderr = %q, want empty", stderrOf(c))
		}
		s := mustOpen(t, newCache(t, dir, "keychain", f))
		for _, repo := range []string{"o/a", "o/b"} {
			if _, ok := s.Get(in(repo)); !ok {
				t.Errorf("Get(%s) missed", repo)
			}
		}
	})
}

func TestCache_BackendNone(t *testing.T) {
	dir := t.TempDir()
	f := newFakeTiers()
	putCommit(t, newCache(t, dir, "", f), "o/r", freshEntry("a"))
	snapshot := func() map[string]string {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, e := range entries {
			out[e.Name()] = string(readFile(t, filepath.Join(dir, e.Name())))
		}
		return out
	}
	before := snapshot()

	c := newCache(t, dir, BackendNone, f)
	s := mustOpen(t, c)
	if s.Readable() {
		t.Error("Readable() = true for none")
	}
	if _, ok := s.Get(in("o/r")); ok {
		t.Error("Get hit with backend none")
	}
	s.Put(in("o/r2"), freshEntry("b"))
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	after := snapshot()
	if len(after) != len(before) {
		t.Errorf("files changed: before %d, after %d", len(before), len(after))
	}
	for name, content := range before {
		if after[name] != content {
			t.Errorf("%s changed", name)
		}
	}

	t.Run("does not create the directory", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing")
		s := mustOpen(t, newCache(t, missing, BackendNone, f))
		s.Put(in("o/r"), freshEntry("a"))
		if err := s.Commit(); err != nil {
			t.Fatal(err)
		}
		assertAbsent(t, missing)
	})
}

func TestCache_ClearKeepsTier(t *testing.T) {
	dir := t.TempDir()
	f := newFakeTiers()
	putCommit(t, newCache(t, dir, "", f), "o/r", freshEntry("a"))
	s := mustOpen(t, newCache(t, dir, "", f))
	s.Clear()
	if len(s.Entries()) != 0 {
		t.Errorf("Entries after Clear = %d, want 0", len(s.Entries()))
	}
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	assertAbsent(t, filepath.Join(dir, CacheFileName))
	if tier := readTier(t, dir); tier != "file" {
		t.Errorf("tier = %q, want file", tier)
	}

	t.Run("clear with no cache file", func(t *testing.T) {
		s := mustOpen(t, newCache(t, dir, "", f))
		s.Clear()
		if err := s.Commit(); err != nil {
			t.Errorf("Commit: %v", err)
		}
	})
}

func TestCache_ClearWhenUnreadable(t *testing.T) {
	dir := t.TempDir()
	f := newFakeTiers()
	f.avail["keychain"] = true
	putCommit(t, newCache(t, dir, "", f), "o/r", freshEntry("a"))
	f.set(func(f *fakeTiers) { f.unwrapErr["keychain"] = errors.New("locked") })

	s := mustOpen(t, newCache(t, dir, "", f))
	if s.Readable() {
		t.Fatal("session is readable")
	}
	s.Clear()
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	assertAbsent(t, filepath.Join(dir, CacheFileName))
	if tier := readTier(t, dir); tier != "keychain" {
		t.Errorf("tier = %q, want keychain", tier)
	}
}

func TestCache_TightensPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits")
	}
	dir := t.TempDir()
	f := newFakeTiers()
	putCommit(t, newCache(t, dir, "", f), "o/r", freshEntry("a"))
	files := []string{LockFileName, CacheFileName, TierFileName}
	for _, name := range files {
		if err := os.Chmod(filepath.Join(dir, name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	mustOpen(t, newCache(t, dir, "", f))
	assertMode(t, dir, 0o700)
	for _, name := range files {
		assertMode(t, filepath.Join(dir, name), 0o600)
	}

	t.Run("never through a symlink or on a directory", func(t *testing.T) {
		dir := t.TempDir()
		outside := filepath.Join(t.TempDir(), "target")
		writeFile(t, outside, "file")
		if err := os.Chmod(outside, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, TierFileName)); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, CacheFileName), 0o755); err != nil {
			t.Fatal(err)
		}
		mustOpen(t, newCache(t, dir, "", f))
		assertMode(t, outside, 0o644)
		assertMode(t, filepath.Join(dir, CacheFileName), 0o755)
	})
}

func TestCache_CommitPrunesExpired(t *testing.T) {
	dir := t.TempDir()
	f := newFakeTiers()
	s := mustOpen(t, newCache(t, dir, "", f))
	expired := freshEntry("old")
	expired.ExpiresAt = testNow.Add(-time.Minute)
	atNow := freshEntry("now")
	atNow.ExpiresAt = testNow
	s.Put(in("o/old"), expired)
	s.Put(in("o/now"), atNow)
	s.Put(in("o/fresh"), freshEntry("fresh"))
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := mustOpen(t, newCache(t, dir, "", f))
	entries := s2.Entries()
	if len(entries) != 1 {
		t.Errorf("entries = %d, want 1", len(entries))
	}
	if _, ok := s2.Get(in("o/fresh")); !ok {
		t.Error("fresh entry pruned")
	}
}

func TestCache_LockTimeout(t *testing.T) {
	dir := t.TempDir()
	f := newFakeTiers()
	s1 := mustOpen(t, newCache(t, dir, "", f))

	c2 := newCache(t, dir, "", f)
	c2.LockTimeout = 100 * time.Millisecond
	_, err := c2.Open()
	if !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("Open while locked = %v, want ErrLockTimeout", err)
	}
	if !strings.Contains(err.Error(), filepath.Join(dir, LockFileName)) || !strings.Contains(err.Error(), "100ms") {
		t.Errorf("error text = %q, want lock path and timeout", err)
	}

	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	s2, err := c2.Open()
	if err != nil {
		t.Fatalf("Open after release: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCache_ConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	f := newFakeTiers()
	const writers = 8
	var wg sync.WaitGroup
	errs := make(chan error, 2*writers) // Commit and Close may each fail
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &Cache{Dir: dir, Protectors: f.protectors(), Now: func() time.Time { return testNow }}
			s, err := c.Open()
			if err != nil {
				errs <- err
				return
			}
			defer func() {
				if err := s.Close(); err != nil {
					errs <- err
				}
			}()
			s.Put(in(fmt.Sprint("o/r", i)), freshEntry(fmt.Sprint("t", i)))
			if err := s.Commit(); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	s := mustOpen(t, newCache(t, dir, "", f))
	if got := len(s.Entries()); got != writers {
		t.Errorf("entries = %d, want %d", got, writers)
	}
	for i := range writers {
		if _, ok := s.Get(in(fmt.Sprint("o/r", i))); !ok {
			t.Errorf("entry %d missing", i)
		}
	}
}

func TestCache_NonceFreshPerCommit(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		avail   string
	}{
		{"explicit keychain reuses the DEK", "keychain", "keychain"},
		{"auto keeps the file envelope", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			f := newFakeTiers()
			if tt.avail != "" {
				f.avail[tt.avail] = true
			}
			putCommit(t, newCache(t, dir, tt.backend, f), "o/a", freshEntry("a"))
			first := readEnvelope(t, dir)
			putCommit(t, newCache(t, dir, tt.backend, f), "o/b", freshEntry("b"))
			second := readEnvelope(t, dir)

			if !bytes.Equal(first.WrappedKey, second.WrappedKey) {
				t.Fatal("DEK was not reused; the test does not exercise nonce reuse")
			}
			if len(first.Nonce) != 12 || len(second.Nonce) != 12 {
				t.Errorf("nonce lengths = %d, %d; want 12", len(first.Nonce), len(second.Nonce))
			}
			if bytes.Equal(first.Nonce, second.Nonce) {
				t.Error("two commits under one DEK reused the nonce")
			}
		})
	}
}

func TestCache_DEKFreshPerWrap(t *testing.T) {
	// The fake tiers XOR the DEK, so xorBytes(wrapped_key) is the DEK.
	dekOf := func(t *testing.T, dir string) []byte {
		t.Helper()
		dek := xorBytes(readEnvelope(t, dir).WrappedKey)
		if len(dek) != 32 {
			t.Fatalf("DEK length = %d, want 32", len(dek))
		}
		if bytes.Equal(dek, make([]byte, 32)) {
			t.Error("DEK is all zeros")
		}
		return dek
	}
	f := newFakeTiers()
	dir1, dir2 := t.TempDir(), t.TempDir()
	putCommit(t, newCache(t, dir1, "", f), "o/r", freshEntry("a"))
	putCommit(t, newCache(t, dir2, "", f), "o/r", freshEntry("a"))
	first, other := dekOf(t, dir1), dekOf(t, dir2)
	if bytes.Equal(first, other) {
		t.Error("two independent caches got the same DEK")
	}

	f.set(func(f *fakeTiers) { f.avail["keychain"] = true })
	putCommit(t, newCache(t, dir1, "", f), "o/r2", freshEntry("b"))
	if env := readEnvelope(t, dir1); env.Backend != "keychain" {
		t.Fatalf("envelope backend = %q, want keychain", env.Backend)
	}
	if upgraded := dekOf(t, dir1); bytes.Equal(upgraded, first) {
		t.Error("the upgrade re-wrap reused the old DEK")
	}
}

func TestCache_LoweredNoticeWhenReusingEnvelope(t *testing.T) {
	// An explicit tier reusing a readable envelope of that tier still lowers
	// a stronger tier file, and says so.
	dir := t.TempDir()
	f := newFakeTiers()
	putCommit(t, newCache(t, dir, "file", f), "o/a", freshEntry("a"))
	before := readEnvelope(t, dir)
	writeFile(t, filepath.Join(dir, TierFileName), "keychain")

	c := newCache(t, dir, "file", f)
	s := mustOpen(t, c)
	if _, ok := s.Get(in("o/a")); !ok {
		t.Fatal("explicit file did not read the file envelope")
	}
	s.Put(in("o/b"), freshEntry("b"))
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readEnvelope(t, dir).WrappedKey, before.WrappedKey) {
		t.Error("envelope was not reused")
	}
	if tier := readTier(t, dir); tier != "file" {
		t.Errorf("tier = %q, want file", tier)
	}
	if want := `cache tier lowered from "keychain" to "file" at your request`; !strings.Contains(stderrOf(c), want) {
		t.Errorf("stderr = %q, want %q", stderrOf(c), want)
	}
}

func TestCache_LoweredNoticeUsesStrongerOld(t *testing.T) {
	// A discarded keychain envelope next to a tpm tier file: the notice names
	// the stronger of the two.
	dir := t.TempDir()
	f := newFakeTiers()
	f.avail["keychain"] = true
	putCommit(t, newCache(t, dir, "keychain", f), "o/a", freshEntry("a"))
	writeFile(t, filepath.Join(dir, TierFileName), "tpm")

	c := newCache(t, dir, "file", f)
	putCommit(t, c, "o/b", freshEntry("b"))
	if want := `cache tier lowered from "tpm" to "file" at your request`; !strings.Contains(stderrOf(c), want) {
		t.Errorf("stderr = %q, want %q", stderrOf(c), want)
	}
}

func TestSession_CommitAfterClose(t *testing.T) {
	dir := t.TempDir()
	f := newFakeTiers()
	s := mustOpen(t, newCache(t, dir, "", f))
	s.Put(in("o/r"), freshEntry("a"))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("Commit after Close = %v, want ErrSessionClosed", err)
	}
	assertAbsent(t, filepath.Join(dir, CacheFileName))

	t.Run("clear after close", func(t *testing.T) {
		putCommit(t, newCache(t, dir, "", f), "o/r", freshEntry("a"))
		s := mustOpen(t, newCache(t, dir, "", f))
		s.Clear()
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if err := s.Commit(); !errors.Is(err, ErrSessionClosed) {
			t.Errorf("Commit after Close = %v, want ErrSessionClosed", err)
		}
		if _, err := os.Stat(filepath.Join(dir, CacheFileName)); err != nil {
			t.Errorf("cache.enc removed by a closed session: %v", err)
		}
	})

	t.Run("none stays a no-op", func(t *testing.T) {
		s := mustOpen(t, newCache(t, dir, BackendNone, f))
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if err := s.Commit(); err != nil {
			t.Errorf("Commit on a closed none session = %v, want nil", err)
		}
	})
}
