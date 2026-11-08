package gitcred

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/goodtune/ghp/internal/asciiutil"
	"github.com/goodtune/ghp/internal/securestore"
)

// Cache file names, timings, backend selectors and fixed strings.
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
	// ErrLockTimeout means another process held the cache lock too long.
	ErrLockTimeout = errors.New("timed out waiting for the credential cache lock")
	// ErrInvalidBackend means the cache backend selector is not known.
	ErrInvalidBackend = errors.New("unknown cache backend")
	// ErrSessionClosed means Commit was called after Close released the lock.
	ErrSessionClosed = errors.New("gitcred: session closed")
)

const (
	envelopeVersion = 1
	dekSize         = 32
	lockPollEvery   = 25 * time.Millisecond
	filePerm        = 0o600
	dirPerm         = 0o700
)

// Entry is one cached token.
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

// Fresh reports whether e is valid for more than MinRemaining after now.
func (e Entry) Fresh(now time.Time) bool {
	return e.ExpiresAt.Sub(now) > MinRemaining
}

// KeyInput is everything the cache key is derived from.
type KeyInput struct {
	ServerURL, Identity, Type, App, Repository string
	// Scopes is NormalizeScopes of the REQUESTED scopes, never the lowered
	// ones the server granted.
	Scopes string
}

// CacheKey returns the hex SHA-256 of the key fields joined by NUL: the
// server URL without trailing slashes, identity, type, app selector as
// given, the lower-cased repository and the requested scopes.
func CacheKey(in KeyInput) string {
	fields := []string{
		strings.TrimRight(in.ServerURL, "/"),
		in.Identity,
		in.Type,
		in.App,
		asciiutil.ToLower(in.Repository),
		in.Scopes,
	}
	sum := sha256.Sum256([]byte(strings.Join(fields, "\x00")))
	return hex.EncodeToString(sum[:])
}

// IdentityFor returns the hex SHA-256 of the phase A user token, or
// IdentityDotvault when the token is empty.
func IdentityFor(phaseAUserToken string) string {
	if phaseAUserToken == "" {
		return IdentityDotvault
	}
	sum := sha256.Sum256([]byte(phaseAUserToken))
	return hex.EncodeToString(sum[:])
}

// NormalizeScopes returns "perm:level" pairs sorted by permission and
// joined by ",".
func NormalizeScopes(scopes map[string]string) string {
	pairs := make([]string, 0, len(scopes))
	for perm, level := range scopes {
		pairs = append(pairs, perm+":"+level)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

// envelope is the on-disk form of cache.enc.
type envelope struct {
	Version    int    `json:"version"`
	Backend    string `json:"backend"`
	WrappedKey []byte `json:"wrapped_key"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// envelopeAAD returns the additional authenticated data that binds the
// header fields to the ciphertext.
func envelopeAAD(version int, backend string, wrappedKey []byte) ([]byte, error) {
	return json.Marshal(struct {
		Version    int    `json:"version"`
		Backend    string `json:"backend"`
		WrappedKey []byte `json:"wrapped_key"`
	}{version, backend, wrappedKey})
}

// Cache is the on-disk token cache of the git credential helper.
type Cache struct {
	Dir         string
	Backend     string                  // "" or "auto", "none", or a tier name
	Protectors  *securestore.Protectors // nil → securestore.Default()
	LockTimeout time.Duration           // 0 → DefaultLockTimeout
	Stderr      io.Writer               // notices; nil → io.Discard
	Now         func() time.Time
}

// Session is an open, locked view of the cache. Close releases the lock.
type Session struct {
	c          *Cache
	mode       string // BackendAuto, BackendNone or a tier name
	protectors *securestore.Protectors
	lock       *os.File
	stderr     io.Writer
	entries    map[string]Entry

	minTier   string
	envTier   string // tier of the envelope on disk that was accepted (readable or not)
	dek       []byte // non-nil only for a readable envelope
	wrapped   []byte
	discarded string // backend of an envelope discarded in Open

	readable bool
	readErr  error
	modified bool
	cleared  bool
}

func validBackend(b string) bool {
	switch b {
	case BackendAuto, BackendNone, securestore.TierTPM, securestore.TierDPAPI, securestore.TierKeychain, securestore.TierFile:
		return true
	}
	return false
}

// Open validates the backend, takes the cache lock, tightens permissions
// and reads the tier file and the envelope.
func (c *Cache) Open() (*Session, error) {
	mode := c.Backend
	if mode == "" {
		mode = BackendAuto
	}
	if !validBackend(mode) {
		return nil, fmt.Errorf("%w %q (want auto, none, tpm, dpapi, keychain or file)", ErrInvalidBackend, mode)
	}
	s := &Session{c: c, mode: mode, protectors: c.Protectors, stderr: c.Stderr, entries: map[string]Entry{}}
	if s.protectors == nil {
		s.protectors = securestore.Default()
	}
	if s.stderr == nil {
		s.stderr = io.Discard
	}
	if mode == BackendNone {
		return s, nil
	}
	if mode != BackendAuto {
		if err := s.protectors.Available(mode); err != nil {
			return nil, err
		}
	}

	if err := os.MkdirAll(c.Dir, dirPerm); err != nil {
		return nil, fmt.Errorf("creating cache directory: %w", err)
	}
	if err := os.Chmod(c.Dir, dirPerm); err != nil {
		return nil, fmt.Errorf("securing cache directory: %w", err)
	}
	lock, err := c.acquireLock()
	if err != nil {
		return nil, err
	}
	s.lock = lock
	if err := c.tightenPermissions(); err != nil {
		_ = s.Close()
		return nil, err
	}
	s.readable = true
	s.minTier = c.readTier()
	s.readEnvelope()
	return s, nil
}

func (c *Cache) acquireLock() (*os.File, error) {
	path := filepath.Join(c.Dir, LockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, filePerm)
	if err != nil {
		return nil, fmt.Errorf("opening cache lock: %w", err)
	}
	timeout := c.LockTimeout
	if timeout <= 0 {
		timeout = DefaultLockTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		ok, err := tryLock(f)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("locking %s: %w", path, err)
		}
		if ok {
			return f, nil
		}
		if !time.Now().Before(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("%w %s after %s", ErrLockTimeout, path, timeout)
		}
		time.Sleep(lockPollEvery)
	}
}

// tightenPermissions sets 0600 on the cache files that are regular files.
// It never follows a symlink and never touches a directory.
func (c *Cache) tightenPermissions() error {
	for _, name := range []string{LockFileName, CacheFileName, TierFileName} {
		path := filepath.Join(c.Dir, name)
		fi, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("checking %s: %w", name, err)
		}
		if !fi.Mode().IsRegular() || fi.Mode().Perm() == filePerm {
			continue
		}
		if err := os.Chmod(path, filePerm); err != nil {
			return fmt.Errorf("securing %s: %w", name, err)
		}
	}
	return nil
}

// readTier returns the minimum tier: "" when the file is absent or empty,
// "tpm" (the strongest floor) when it names no known tier or cannot be read.
func (c *Cache) readTier() string {
	b, err := os.ReadFile(filepath.Join(c.Dir, TierFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		return securestore.TierTPM
	}
	tier := strings.TrimSpace(string(b))
	if tier == "" {
		return ""
	}
	if securestore.Strength(tier) < 0 {
		return securestore.TierTPM
	}
	return tier
}

// readEnvelope loads cache.enc into s, discarding anything it cannot trust.
func (s *Session) readEnvelope() {
	b, err := os.ReadFile(s.Path())
	if err != nil {
		return // absent or unreadable: no envelope
	}
	var env envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return
	}
	if env.Version != envelopeVersion || securestore.Strength(env.Backend) < 0 {
		return
	}
	if s.mode == BackendAuto && securestore.Strength(env.Backend) < securestore.Strength(s.minTier) {
		s.discarded = env.Backend
		return
	}
	if s.mode != BackendAuto && env.Backend != s.mode {
		s.discarded = env.Backend
		return
	}

	dek, err := s.unwrap(env)
	if err != nil {
		if errors.Is(err, securestore.ErrForeignKey) {
			s.discarded = env.Backend
			return
		}
		s.envTier = env.Backend
		s.readable = false
		s.readErr = fmt.Errorf("%s: %w", env.Backend, err)
		s.notice("cannot read the credential cache (%v); continuing without it (run ghp auth git-credential clear if this persists)", s.readErr)
		return
	}
	entries, ok := decryptEntries(env, dek)
	if !ok {
		s.discarded = env.Backend
		return
	}
	s.envTier = env.Backend
	s.dek = dek
	s.wrapped = env.WrappedKey
	s.entries = entries
}

func (s *Session) unwrap(env envelope) ([]byte, error) {
	p, err := s.protectors.Open(env.Backend, s.c.Dir)
	if err != nil {
		return nil, err
	}
	return p.Unwrap(env.WrappedKey)
}

// decryptEntries authenticates and decrypts env under dek.
func decryptEntries(env envelope, dek []byte) (map[string]Entry, bool) {
	if len(dek) != dekSize {
		return nil, false
	}
	gcm, err := newGCM(dek)
	if err != nil || len(env.Nonce) != gcm.NonceSize() {
		return nil, false
	}
	aad, err := envelopeAAD(env.Version, env.Backend, env.WrappedKey)
	if err != nil {
		return nil, false
	}
	plain, err := gcm.Open(nil, env.Nonce, env.Ciphertext, aad)
	if err != nil {
		return nil, false
	}
	var entries map[string]Entry
	if err := json.Unmarshal(plain, &entries); err != nil {
		return nil, false
	}
	if entries == nil {
		entries = map[string]Entry{}
	}
	return entries, true
}

func newGCM(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// notice writes one prefixed stderr line; CR and LF become spaces.
func (s *Session) notice(format string, args ...any) {
	msg := strings.NewReplacer("\r", " ", "\n", " ").Replace(fmt.Sprintf(format, args...))
	_, _ = io.WriteString(s.stderr, MessagePrefix+msg+"\n")
}

// Get returns the entry for in. It misses when the entry is absent or was
// stored for another identity.
func (s *Session) Get(in KeyInput) (Entry, bool) {
	e, ok := s.entries[CacheKey(in)]
	if !ok || e.Identity != in.Identity {
		return Entry{}, false
	}
	return e, true
}

// Put stores e under in with e.Identity set to in.Identity, overwriting any
// existing entry.
func (s *Session) Put(in KeyInput, e Entry) {
	e.Identity = in.Identity
	s.entries[CacheKey(in)] = e
	s.modified = true
}

// Delete removes and returns the entry Get would return for in.
func (s *Session) Delete(in KeyInput) (Entry, bool) {
	e, ok := s.Get(in)
	if !ok {
		return Entry{}, false
	}
	delete(s.entries, CacheKey(in))
	s.modified = true
	return e, true
}

// Entries returns a copy of every entry, keyed by CacheKey.
func (s *Session) Entries() map[string]Entry {
	return maps.Clone(s.entries)
}

// Clear drops every entry; the next Commit removes cache.enc (even when the
// session is not readable) and keeps the tier file.
func (s *Session) Clear() {
	s.entries = map[string]Entry{}
	s.cleared = true
}

// Commit drops expired entries and writes the rest to cache.enc under the
// chosen tier, raising the tier file first. It does nothing for
// BackendNone, an unmodified session or an unreadable cache (which is never
// rewritten); after Clear it removes cache.enc instead. After Close it
// returns ErrSessionClosed.
func (s *Session) Commit() error {
	if s.mode == BackendNone {
		return nil
	}
	if s.lock == nil {
		return ErrSessionClosed
	}
	if s.cleared {
		if err := os.Remove(s.Path()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("removing credential cache: %w", err)
		}
		s.cleared, s.modified = false, false
		s.envTier, s.dek, s.wrapped = "", nil, nil
		return nil
	}
	if !s.modified || !s.readable {
		return nil
	}

	now := s.now()
	for k, e := range s.entries {
		if !e.ExpiresAt.After(now) {
			delete(s.entries, k)
		}
	}

	tier, dek, wrapped, err := s.chooseProtector()
	if err != nil {
		return err
	}
	if tier == "" {
		s.notice("no cache tier at least as strong as %q is available; token not cached (use --cache-backend <tier> to accept a weaker tier)", s.minTier)
		return nil
	}

	// The tier file is written before the envelope, so a failed envelope
	// write never leaves a stronger envelope behind a weaker floor. Auto
	// only ever raises it; an explicit tier sets it.
	setTier := s.mode != BackendAuto || s.minTier == "" || securestore.Strength(tier) > securestore.Strength(s.minTier)
	if setTier && tier != s.minTier {
		if err := writeAtomic(s.c.Dir, ".tier-*.tmp", TierFileName, []byte(tier)); err != nil {
			return fmt.Errorf("writing cache tier: %w", err)
		}
	}
	oldTier := s.minTier
	s.minTier = tier
	if err := s.writeEnvelope(tier, dek, wrapped); err != nil {
		return err
	}

	if tier == securestore.TierFile && (s.dek == nil || s.envTier != securestore.TierFile) {
		s.notice("cache protected by file permissions only; see docs")
	}
	if s.mode != BackendAuto {
		// Any downgrade is announced, naming the stronger of the discarded
		// envelope's tier and the previous tier file.
		old := oldTier
		if securestore.Strength(s.discarded) > securestore.Strength(old) {
			old = s.discarded
		}
		if securestore.Strength(tier) < securestore.Strength(old) {
			s.notice("cache tier lowered from %q to %q at your request", old, tier)
		}
	}
	s.envTier, s.dek, s.wrapped, s.discarded = tier, dek, wrapped, ""
	s.modified = false
	return nil
}

// chooseProtector returns the tier, DEK and wrapped key to write under, or
// an empty tier when no tier satisfies the minimum under auto.
func (s *Session) chooseProtector() (string, []byte, []byte, error) {
	if s.mode != BackendAuto {
		if s.dek != nil && s.envTier == s.mode {
			return s.envTier, s.dek, s.wrapped, nil
		}
		p, err := s.protectors.Open(s.mode, s.c.Dir)
		if err != nil {
			return "", nil, nil, fmt.Errorf("wrapping cache key with %s: %w", s.mode, err)
		}
		dek, wrapped, err := newWrappedKey(p)
		if err != nil {
			return "", nil, nil, fmt.Errorf("wrapping cache key with %s: %w", s.mode, err)
		}
		return s.mode, dek, wrapped, nil
	}

	floor := s.minTier
	if s.dek != nil {
		floor = s.envTier
	}
	for _, p := range s.protectors.AvailableAtLeast(floor, s.c.Dir) {
		if s.dek != nil && securestore.Strength(p.Name()) <= securestore.Strength(s.envTier) {
			continue
		}
		if dek, wrapped, err := newWrappedKey(p); err == nil {
			return p.Name(), dek, wrapped, nil
		}
	}
	if s.dek != nil {
		return s.envTier, s.dek, s.wrapped, nil
	}
	return "", nil, nil, nil
}

func newWrappedKey(p securestore.KeyProtector) ([]byte, []byte, error) {
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, err
	}
	wrapped, err := p.Wrap(dek)
	if err != nil {
		return nil, nil, err
	}
	return dek, wrapped, nil
}

func (s *Session) writeEnvelope(tier string, dek, wrapped []byte) error {
	plain, err := json.Marshal(s.entries)
	if err != nil {
		return fmt.Errorf("encoding credential cache: %w", err)
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return fmt.Errorf("encrypting credential cache: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("encrypting credential cache: %w", err)
	}
	aad, err := envelopeAAD(envelopeVersion, tier, wrapped)
	if err != nil {
		return fmt.Errorf("encrypting credential cache: %w", err)
	}
	b, err := json.Marshal(envelope{
		Version:    envelopeVersion,
		Backend:    tier,
		WrappedKey: wrapped,
		Nonce:      nonce,
		Ciphertext: gcm.Seal(nil, nonce, plain, aad),
	})
	if err != nil {
		return fmt.Errorf("encoding credential cache: %w", err)
	}
	if err := writeAtomic(s.c.Dir, ".cache-*.tmp", CacheFileName, b); err != nil {
		return fmt.Errorf("writing credential cache: %w", err)
	}
	return nil
}

// writeAtomic writes data to dir/name through a 0600 temp file and rename.
func writeAtomic(dir, pattern, name string, data []byte) (err error) {
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(filePerm); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

func (s *Session) now() time.Time {
	if s.c.Now != nil {
		return s.c.Now()
	}
	return time.Now()
}

// Close releases the lock. It is safe to call more than once.
func (s *Session) Close() error {
	if s.lock == nil {
		return nil
	}
	f := s.lock
	s.lock = nil
	uerr := unlock(f)
	cerr := f.Close()
	if uerr != nil {
		return fmt.Errorf("unlocking credential cache: %w", uerr)
	}
	return cerr
}

// Backend returns the tier of the envelope read or last written, or "" when
// there is none.
func (s *Session) Backend() string { return s.envTier }

// MinTier returns the parsed tier file, or "" when it is absent.
func (s *Session) MinTier() string { return s.minTier }

// Readable reports whether the cache could be read. It is false for
// BackendNone and when the envelope's key could not be unwrapped.
func (s *Session) Readable() bool { return s.readable }

// ReadError returns why the envelope's key could not be unwrapped.
func (s *Session) ReadError() error { return s.readErr }

// Path returns the path of cache.enc.
func (s *Session) Path() string { return filepath.Join(s.c.Dir, CacheFileName) }
