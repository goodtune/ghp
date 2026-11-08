package gitcred

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/goodtune/ghp/internal/asciiutil"
	"github.com/goodtune/ghp/internal/securestore"
)

// Fixed values of the helper protocol.
const (
	// Username is the username git is given with every token.
	Username = "x-access-token"
	// DefaultHost is the only host served when Options.Hosts is empty.
	DefaultHost = "github.com"

	sessionIDPrefix = "git-credential:"
	maxSessionID    = 128
	tokenPrefixLen  = 8
	defaultRetry    = "60"

	msgInvalidRequest = "invalid credential request from git"
	msgNoPath         = "git did not send a repository path; run ghp auth setup-git (it sets credential.useHttpPath)"
	msgNotLoggedIn    = "not logged in: run ghp auth login"
	msgSessionExpired = "ghp session expired or invalid: run ghp auth login"
	msgNoExpiry       = "server returned a token with no expiry; refusing to use it"
	msgNoCacheDir     = "no credential cache directory is configured"
	msgClearedBlind   = "cache could not be read; removed it without revoking tokens"

	statusLabelWidth = 16
)

// Config is the part of the CLI config the helper needs.
type Config struct {
	ServerURL, UserToken string
	Warnings             []string // config-loading warnings, re-emitted one per line with MessagePrefix
}

// Options configures one helper run.
type Options struct {
	Settings     Settings
	Hosts        []string // empty → []string{DefaultHost}
	CacheBackend string   // "" → auto
	CacheDir     string   // "" → behave as BackendNone
	Hostname     string
	LoadStatic   func() (Config, error)                    // phase A: files + env, never prompts
	LoadAuthed   func(ctx context.Context) (Config, error) // phase B: + dotvault, non-interactive; its error text is printed verbatim
	Protectors   *securestore.Protectors                   // nil → securestore.Default()
	HTTPClient   *http.Client
	LockTimeout  time.Duration
	Now          func() time.Time
}

// SessionID returns the session_id sent with every mint:
// "git-credential:<hostname>", cut to at most 128 bytes on a rune boundary.
func SessionID(hostname string) string {
	s := sessionIDPrefix + hostname
	if len(s) <= maxSessionID {
		return s
	}
	cut := maxSessionID
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// Run executes one helper operation and returns the process exit code.
// Every failure is one prefixed stderr line with stdout left empty; a token
// is never written anywhere but stdout.
func Run(ctx context.Context, opts Options, op string, stdin io.Reader, stdout, stderr io.Writer) int {
	h := &helper{opts: opts, stderr: stderr}
	switch op {
	case "get":
		return h.get(ctx, stdin, stdout)
	case "store":
		// The helper is the source of truth; what git offers is discarded.
		_, _ = io.Copy(io.Discard, stdin)
		return 0
	case "erase":
		h.erase(ctx, stdin)
		return 0
	case "status":
		return h.status(stdout)
	case "clear":
		return h.clear(ctx, stdout)
	default:
		// git requires unknown operations to be ignored.
		return 0
	}
}

// helper holds the state of one Run: the options and the configs loaded
// so far, so each phase runs at most once.
type helper struct {
	opts   Options
	stderr io.Writer

	static     Config
	authed     Config
	authedErr  error
	authedDone bool
}

// warn writes one prefixed stderr line; CR and LF become spaces.
func warn(stderr io.Writer, msg string) {
	msg = strings.NewReplacer("\r", " ", "\n", " ").Replace(msg)
	_, _ = io.WriteString(stderr, MessagePrefix+msg+"\n")
}

// fail writes msg as one prefixed stderr line and returns exit code 1.
func fail(stderr io.Writer, msg string) int {
	warn(stderr, msg)
	return 1
}

func (h *helper) warn(msg string)     { warn(h.stderr, msg) }
func (h *helper) fail(msg string) int { return fail(h.stderr, msg) }

func (h *helper) now() time.Time {
	if h.opts.Now != nil {
		return h.opts.Now()
	}
	return time.Now()
}

// loadStatic runs phase A and re-emits its warnings.
func (h *helper) loadStatic() error {
	if h.opts.LoadStatic == nil {
		return nil
	}
	cfg, err := h.opts.LoadStatic()
	for _, w := range cfg.Warnings {
		h.warn(w)
	}
	if err != nil {
		return err
	}
	h.static = cfg
	return nil
}

// loadAuthed runs phase B once and returns its result on every call.
func (h *helper) loadAuthed(ctx context.Context) (Config, error) {
	if !h.authedDone {
		h.authedDone = true
		if h.opts.LoadAuthed != nil {
			h.authed, h.authedErr = h.opts.LoadAuthed(ctx)
		}
	}
	return h.authed, h.authedErr
}

func (h *helper) hostAllowed(host string) bool {
	hosts := h.opts.Hosts
	if len(hosts) == 0 {
		hosts = []string{DefaultHost}
	}
	for _, allowed := range hosts {
		if asciiutil.EqualFold(allowed, host) {
			return true
		}
	}
	return false
}

func (h *helper) cache() *Cache {
	backend := h.opts.CacheBackend
	if h.opts.CacheDir == "" && (backend == "" || validBackend(backend)) {
		// No directory to keep a cache in; an invalid selector still
		// reaches Open so it is reported.
		backend = BackendNone
	}
	return &Cache{
		Dir:         h.opts.CacheDir,
		Backend:     backend,
		Protectors:  h.opts.Protectors,
		LockTimeout: h.opts.LockTimeout,
		Stderr:      h.stderr,
		Now:         h.opts.Now,
	}
}

// request is a parsed and validated credential request.
type request struct {
	req    Request
	target Target
	plan   Plan
}

// parse reads and validates the request in the order of §3 step 1. The
// returned message is the one-line failure text.
func (h *helper) parse(stdin io.Reader) (request, string) {
	req, err := ParseRequest(stdin)
	if err != nil {
		return request{}, msgInvalidRequest
	}
	if !h.hostAllowed(req.Host) {
		return request{}, fmt.Sprintf("host %q is not configured for this helper; add --host %s to the helper line or run ghp auth setup-git --host %s", req.Host, req.Host, req.Host)
	}
	target, err := ParseTarget(req)
	if errors.Is(err, ErrNoPath) {
		return request{}, msgNoPath
	}
	if err != nil {
		return request{}, err.Error()
	}
	plan, err := ParseSettings(h.opts.Settings)
	if err != nil {
		return request{}, err.Error()
	}
	return request{req: req, target: target, plan: plan}, ""
}

// serverURL runs phase A, then phase B when phase A has no server URL, and
// returns the server URL the cache key uses.
func (h *helper) serverURL(ctx context.Context) (string, error) {
	if err := h.loadStatic(); err != nil {
		return "", err
	}
	if h.static.ServerURL != "" {
		return h.static.ServerURL, nil
	}
	b, err := h.loadAuthed(ctx)
	if err != nil {
		return "", err
	}
	return b.ServerURL, nil
}

func (h *helper) keyInput(serverURL string, r request) KeyInput {
	return KeyInput{
		ServerURL:  serverURL,
		Identity:   IdentityFor(h.static.UserToken),
		Type:       r.plan.Type,
		App:        r.plan.App,
		Repository: r.target.FullName(),
		Scopes:     NormalizeScopes(r.plan.Scopes),
	}
}

// fatalCacheError reports whether a cache Open error is a configuration
// mistake the user must fix rather than a reason to continue uncached.
func fatalCacheError(err error) bool {
	return errors.Is(err, ErrInvalidBackend) ||
		errors.Is(err, securestore.ErrUnavailable) ||
		errors.Is(err, securestore.ErrUnknownTier)
}

func (h *helper) get(ctx context.Context, stdin io.Reader, stdout io.Writer) int {
	r, msg := h.parse(stdin)
	if msg != "" {
		return h.fail(msg)
	}
	serverURL, err := h.serverURL(ctx)
	if err != nil {
		return h.fail(err.Error())
	}
	if serverURL == "" {
		return h.fail(msgNotLoggedIn)
	}
	in := h.keyInput(serverURL, r)
	now := h.now()

	// Read with the lock held only for the read itself.
	cache := h.cache()
	var caching bool // set only once the cache has been read
	s, err := cache.Open()
	if err != nil {
		if fatalCacheError(err) {
			return h.fail(err.Error())
		}
		h.warn(fmt.Sprintf("could not use the credential cache (%v); continuing without it", err))
		caching = false
	} else {
		e, hit := s.Get(in)
		// An unreadable cache has already printed its notice; skipping the
		// store keeps that notice to one line.
		caching = s.Readable()
		// Closing the lock file releases the lock even when unlocking
		// reports an error, and nothing was written.
		_ = s.Close()
		if hit && e.Fresh(now) {
			return h.write(stdout, Credential{Username: Username, Password: e.Token, Expiry: e.ExpiresAt})
		}
	}

	b, err := h.loadAuthed(ctx)
	if err != nil {
		return h.fail(err.Error())
	}
	if b.ServerURL == "" || b.UserToken == "" {
		return h.fail(msgNotLoggedIn)
	}

	// Mint with no lock held.
	client := &Client{BaseURL: b.ServerURL, Token: b.UserToken, HTTP: h.opts.HTTPClient}
	res, err := Resolve(ctx, client, r.plan, r.target)
	if err != nil {
		return h.fail(mintErrorMessage(err, r.plan.Type))
	}
	scopes := NormalizeScopes(res.Scopes)
	tok, err := client.CreateToken(ctx, MintRequest{
		Type:           res.Type,
		Repositories:   []string{r.target.FullName()},
		Scopes:         scopes,
		Duration:       r.plan.TTL.String(),
		SessionID:      SessionID(h.opts.Hostname),
		AppRecordID:    res.AppRecordID,
		InstallationID: res.InstallationID,
	})
	if err != nil {
		return h.fail(mintErrorMessage(err, r.plan.Type))
	}
	if tok.ExpiresAt == nil {
		if tok.ID != "" {
			_ = client.RevokeToken(ctx, tok.ID) // best effort
		}
		return h.fail(msgNoExpiry)
	}

	// Render first so a token git could not parse is never cached.
	var out bytes.Buffer
	if err := WriteCredential(&out, Credential{Username: Username, Password: tok.Token, Expiry: *tok.ExpiresAt}); err != nil {
		return h.fail("server returned a token git cannot use: " + err.Error())
	}

	if caching {
		entry := Entry{
			Token:       tok.Token,
			TokenID:     tok.ID,
			Type:        res.Type,
			AppRecordID: res.AppRecordID,
			AppName:     res.AppName,
			Repository:  r.target.FullName(),
			Scopes:      scopes,
			ExpiresAt:   *tok.ExpiresAt,
			MintedAt:    now,
		}
		if err := store(cache, in, entry); err != nil {
			h.warn(fmt.Sprintf("could not save the credential cache: %v", err))
		}
	}

	if _, err := out.WriteTo(stdout); err != nil {
		return h.fail("writing credential for git: " + err.Error())
	}
	return 0
}

// store re-opens the cache (re-reading what other processes wrote), puts
// the entry over whatever is there and commits.
func store(cache *Cache, in KeyInput, e Entry) error {
	s, err := cache.Open()
	if err != nil {
		return err
	}
	s.Put(in, e)
	err = s.Commit()
	if cerr := s.Close(); err == nil {
		err = cerr
	}
	return err
}

func (h *helper) write(stdout io.Writer, c Credential) int {
	if err := WriteCredential(stdout, c); err != nil {
		return h.fail("writing credential for git: " + err.Error())
	}
	return 0
}

// mintErrorMessage maps a Resolve or CreateToken error to its one-line
// message.
func mintErrorMessage(err error, typ string) string {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return msgSessionExpired
	case errors.Is(err, ErrRateLimited):
		return fmt.Sprintf("ghp server rate limited token creation (20 per minute per IP); retry in %ss", retryAfterSeconds(err))
	case errors.Is(err, ErrForbidden) && typ == TypeAgent:
		return msgAgentForbidden
	}
	return err.Error()
}

// retryAfterSeconds returns the Retry-After delay in whole seconds, or 60
// when the header is absent or not a number of seconds.
func retryAfterSeconds(err error) string {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return defaultRetry
	}
	n, perr := strconv.Atoi(strings.TrimSpace(apiErr.RetryAfter))
	if perr != nil || n < 0 {
		return defaultRetry
	}
	return strconv.Itoa(n)
}

// tokenPrefix returns the first eight characters of a token followed by
// "...", the most of a token the helper ever prints.
func tokenPrefix(tok string) string {
	if len(tok) > tokenPrefixLen {
		tok = tok[:tokenPrefixLen]
	}
	return tok + "..."
}

// erase deletes the cached entry for the request when git sent no password
// or the cached token, then revokes it with the lock released. It never
// fails: problems are reported on stderr at one line each.
func (h *helper) erase(ctx context.Context, stdin io.Reader) {
	r, msg := h.parse(stdin)
	if msg != "" {
		return
	}
	if err := h.loadStatic(); err != nil {
		return
	}
	serverURL := h.static.ServerURL
	if serverURL == "" {
		b, err := h.loadAuthed(ctx)
		if err != nil {
			h.warn(err.Error())
			return
		}
		serverURL = b.ServerURL
	}
	if serverURL == "" {
		return
	}
	in := h.keyInput(serverURL, r)

	s, err := h.cache().Open()
	if err != nil {
		h.warn(fmt.Sprintf("could not use the credential cache (%v)", err))
		return
	}
	e, ok := s.Get(in)
	deleted := ok && (r.req.Password == "" ||
		subtle.ConstantTimeCompare([]byte(r.req.Password), []byte(e.Token)) == 1)
	if deleted {
		s.Delete(in)
	}
	err = s.Commit()
	if cerr := s.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		// The entry may still be on disk; revoking it would leave a dead
		// token cached.
		h.warn(fmt.Sprintf("could not save the credential cache: %v", err))
		return
	}
	if !deleted || e.TokenID == "" {
		return
	}

	// The lock is released; revoke with the phase A token, else phase B's.
	token, base := h.static.UserToken, serverURL
	if token == "" {
		b, err := h.loadAuthed(ctx)
		if err != nil {
			h.warn(fmt.Sprintf("could not revoke token %s: %v", tokenPrefix(e.Token), err))
			return
		}
		token = b.UserToken
		if b.ServerURL != "" {
			base = b.ServerURL
		}
	}
	if token == "" {
		h.warn(fmt.Sprintf("could not revoke token %s: %s", tokenPrefix(e.Token), msgNotLoggedIn))
		return
	}
	client := &Client{BaseURL: base, Token: token, HTTP: h.opts.HTTPClient}
	if err := client.RevokeToken(ctx, e.TokenID); err != nil {
		h.warn(fmt.Sprintf("could not revoke token %s: %v", tokenPrefix(e.Token), err))
	}
}

// protectionText describes what protects a cache written under each tier,
// keyed by tier name; "none" means there is no cache.
var protectionText = map[string]string{
	securestore.TierTPM:      "sealed by this machine's TPM",
	securestore.TierDPAPI:    "Windows DPAPI (current user)",
	securestore.TierKeychain: "macOS login keychain",
	securestore.TierFile:     "file permissions only (0600); see docs",
	BackendNone:              "no cache",
}

// openForHumans opens the cache for status and clear: always under auto,
// whatever --cache-backend says, with the cache's own notices suppressed
// (status reports ReadError itself; clear prints its own line).
func (h *helper) openForHumans() (*Session, error) {
	if h.opts.CacheDir == "" {
		return nil, errors.New(msgNoCacheDir)
	}
	s, err := (&Cache{
		Dir:         h.opts.CacheDir,
		Backend:     BackendAuto,
		Protectors:  h.opts.Protectors,
		LockTimeout: h.opts.LockTimeout,
		Stderr:      io.Discard,
		Now:         h.opts.Now,
	}).Open()
	if err != nil {
		return nil, fmt.Errorf("could not open the credential cache: %w", err)
	}
	return s, nil
}

// sortedEntries returns the entries ordered by repository, then type; ties
// keep cache-key order so the output is stable.
func sortedEntries(entries map[string]Entry) []Entry {
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Entry, 0, len(keys))
	for _, k := range keys {
		out = append(out, entries[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Repository != out[j].Repository {
			return out[i].Repository < out[j].Repository
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// printable replaces control characters so a value read from the cache or
// the server cannot break a status line or drive the terminal.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}

func orNone(s string) string {
	if s == "" {
		return BackendNone
	}
	return s
}

// status prints the cache path, tiers and entries. It never contacts the
// server or loads the CLI config, and never prints more of a token than
// tokenPrefix.
func (h *helper) status(stdout io.Writer) int {
	s, err := h.openForHumans()
	if err != nil {
		return h.fail(err.Error())
	}
	entries := sortedEntries(s.Entries())
	readable, readErr := s.Readable(), s.ReadError()
	backend, minTier, path := orNone(s.Backend()), orNone(s.MinTier()), s.Path()
	// Nothing was written; closing releases the lock even when unlocking
	// reports an error.
	_ = s.Close()

	protectors := h.opts.Protectors
	if protectors == nil {
		protectors = securestore.Default()
	}
	now := h.now()

	var b strings.Builder
	line := func(label, value string) {
		fmt.Fprintf(&b, "%-*s%s\n", statusLabelWidth, label+":", printable(value))
	}
	line("Cache path", path)
	line("Cache backend", backend)
	line("Minimum tier", minTier)
	protection, ok := protectionText[backend]
	if !ok {
		protection = "unknown tier"
	}
	line("Protection", protection)
	for _, name := range protectors.Names() {
		avail := "available"
		if err := protectors.Available(name); err != nil {
			avail = "unavailable (" + err.Error() + ")"
		}
		line("Tier "+name, avail)
	}
	if !readable {
		line("Entries", fmt.Sprintf("unavailable (%v)", readErr))
	} else {
		line("Entries", strconv.Itoa(len(entries)))
	}
	for _, e := range entries {
		app := e.AppName
		if app == "" {
			app = "-"
		}
		left := "expired"
		if d := e.ExpiresAt.Sub(now); d > 0 {
			left = fmt.Sprintf("in %dm", int64(math.Round(d.Minutes())))
		}
		fmt.Fprintf(&b, "  %s  %s  app=%s  token=%s  expires=%s (%s)\n",
			printable(e.Repository), printable(e.Type), printable(app),
			printable(tokenPrefix(e.Token)), e.ExpiresAt.UTC().Format(time.RFC3339), left)
	}
	if _, err := io.WriteString(stdout, b.String()); err != nil {
		return h.fail("writing status: " + err.Error())
	}
	return 0
}

// clear removes every cached entry, keeping the tier file, then revokes
// each removed token with the lock released. Only opening or rewriting the
// cache can fail it; revocation problems are reported one line each.
func (h *helper) clear(ctx context.Context, stdout io.Writer) int {
	s, err := h.openForHumans()
	if err != nil {
		return h.fail(err.Error())
	}
	unreadable := !s.Readable()
	entries := sortedEntries(s.Entries())
	s.Clear()
	err = s.Commit()
	if cerr := s.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		// cache.enc may still be on disk; revoking would leave dead tokens
		// cached.
		return h.fail(fmt.Sprintf("could not clear the credential cache: %v", err))
	}
	if unreadable {
		h.warn(msgClearedBlind)
	}

	revoked := 0
	if len(entries) > 0 {
		revoked = h.revokeAll(ctx, entries)
	}
	if _, err := fmt.Fprintf(stdout, "Cleared %d cached credentials; revoked %d.\n", len(entries), revoked); err != nil {
		return h.fail("writing result: " + err.Error())
	}
	return 0
}

// revokeAll revokes each entry's token best effort and returns how many
// were revoked. It runs phase A, then phase B when phase A has no user
// token.
func (h *helper) revokeAll(ctx context.Context, entries []Entry) int {
	if err := h.loadStatic(); err != nil {
		h.warn("tokens not revoked: " + err.Error())
		return 0
	}
	token, base := h.static.UserToken, h.static.ServerURL
	if token == "" {
		b, err := h.loadAuthed(ctx)
		if err != nil {
			h.warn("tokens not revoked: " + err.Error())
			return 0
		}
		token = b.UserToken
		if b.ServerURL != "" {
			base = b.ServerURL
		}
	}
	if token == "" || base == "" {
		h.warn("tokens not revoked: " + msgNotLoggedIn)
		return 0
	}
	client := &Client{BaseURL: base, Token: token, HTTP: h.opts.HTTPClient}
	revoked := 0
	for _, e := range entries {
		if e.TokenID == "" {
			h.warn(fmt.Sprintf("could not revoke token %s: no token id was cached", tokenPrefix(e.Token)))
			continue
		}
		if err := client.RevokeToken(ctx, e.TokenID); err != nil {
			h.warn(fmt.Sprintf("could not revoke token %s: %v", tokenPrefix(e.Token), err))
			continue
		}
		revoked++
	}
	return revoked
}
