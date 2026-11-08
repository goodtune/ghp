package gitcred

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/goodtune/ghp/internal/securestore"
)

// stdGet is the standard credential request of these tests.
const stdGet = "protocol=https\nhost=github.com\npath=goodtune/ghp.git\n\n"

// fakeToken is the n-th token the fake ghp server mints.
func fakeToken(n int) string { return fmt.Sprintf("gha_fake%04dabcdefghijklmnopqrstuvwxyz", n) }

// eraseWith returns an erase request for the standard target carrying
// password (none when empty).
func eraseWith(password string) string {
	s := "protocol=https\nhost=github.com\npath=goodtune/ghp.git\nusername=x-access-token\n"
	if password != "" {
		s += "password=" + password + "\n"
	}
	return s + "\n"
}

// fakeGHP is an httptest ghp server that records every request. Its
// configuration is changed only through set, so the handler goroutine never
// races the test.
type fakeGHP struct {
	t   *testing.T
	srv *httptest.Server

	mu            sync.Mutex
	now           func() time.Time
	apps          []App
	installations []Installation
	status        map[string]int // mux pattern → status override
	retryAfter    string
	message       string // error message of status overrides; "" → the status text
	nullExpiry    bool
	emptyToken    bool
	onMint        func()
	onRevoke      func()

	requests   []string // "METHOD path"
	auths      []string // Authorization header of each request, in step with requests
	mintBodies []MintRequest
	revoked    []string
	mints      int
}

func newFakeGHP(t *testing.T) *fakeGHP {
	t.Helper()
	g := &fakeGHP{
		t:   t,
		now: func() time.Time { return testNow },
		apps: []App{
			{ID: testAppID, Name: "my-app", AppID: 1, IsDefault: true},
		},
		installations: []Installation{
			installation(42, "goodtune", map[string]string{"contents": "write", "metadata": "read"}),
		},
		status: map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/apps", g.handleApps)
	mux.HandleFunc("GET /api/apps/{id}/installations", g.handleInstallations)
	mux.HandleFunc("POST /api/tokens", g.handleMint)
	mux.HandleFunc("DELETE /api/tokens/{id}", g.handleRevoke)
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ghpr_") {
			t.Errorf("Authorization = %q, want a bearer ghpr_ session token", got)
		}
		g.mu.Lock()
		g.requests = append(g.requests, r.Method+" "+r.URL.Path)
		g.auths = append(g.auths, r.Header.Get("Authorization"))
		g.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGHP) set(fn func(g *fakeGHP)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	fn(g)
}

// override writes the configured status for r's pattern and reports
// whether it did.
func (g *fakeGHP) override(w http.ResponseWriter, r *http.Request) bool {
	g.mu.Lock()
	code, ok := g.status[r.Pattern]
	retry, msg := g.retryAfter, g.message
	g.mu.Unlock()
	if !ok {
		return false
	}
	if retry != "" {
		w.Header().Set("Retry-After", retry)
	}
	if msg == "" {
		msg = http.StatusText(code)
	}
	writeJSONBody(g.t, w, code, map[string]string{"message": msg})
	return true
}

func (g *fakeGHP) handleApps(w http.ResponseWriter, r *http.Request) {
	if g.override(w, r) {
		return
	}
	g.mu.Lock()
	apps := g.apps
	g.mu.Unlock()
	writeJSONBody(g.t, w, http.StatusOK, apps)
}

func (g *fakeGHP) handleInstallations(w http.ResponseWriter, r *http.Request) {
	if g.override(w, r) {
		return
	}
	g.mu.Lock()
	insts := g.installations
	g.mu.Unlock()
	writeJSONBody(g.t, w, http.StatusOK, insts)
}

func (g *fakeGHP) handleMint(w http.ResponseWriter, r *http.Request) {
	var body MintRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		g.t.Errorf("decoding mint body: %v", err)
	}
	g.mu.Lock()
	g.mintBodies = append(g.mintBodies, body)
	hook := g.onMint
	g.mu.Unlock()
	if hook != nil {
		hook()
	}
	if g.override(w, r) {
		return
	}
	g.mu.Lock()
	g.mints++
	n := g.mints
	var expires any
	if !g.nullExpiry {
		expires = g.now().Add(time.Hour)
	}
	token := fakeToken(n)
	if g.emptyToken {
		token = ""
	}
	g.mu.Unlock()
	writeJSONBody(g.t, w, http.StatusCreated, map[string]any{
		"token":        token,
		"id":           "tok-" + strconv.Itoa(n),
		"type":         body.Type,
		"repositories": body.Repositories,
		"expires_at":   expires,
	})
}

func (g *fakeGHP) handleRevoke(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	hook := g.onRevoke
	g.mu.Unlock()
	if hook != nil {
		hook()
	}
	if g.override(w, r) {
		return
	}
	g.mu.Lock()
	g.revoked = append(g.revoked, r.PathValue("id"))
	g.mu.Unlock()
	writeJSONBody(g.t, w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (g *fakeGHP) mintCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.mints
}

func (g *fakeGHP) revokedIDs() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.revoked...)
}

func (g *fakeGHP) requestCount(prefix string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, r := range g.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

// authsFor returns the Authorization header of every request whose
// "METHOD path" starts with prefix.
func (g *fakeGHP) authsFor(prefix string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for i, r := range g.requests {
		if strings.HasPrefix(r, prefix) {
			out = append(out, g.auths[i])
		}
	}
	return out
}

func (g *fakeGHP) lastMint(t *testing.T) MintRequest {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.mintBodies) == 0 {
		t.Fatal("no mint request recorded")
	}
	return g.mintBodies[len(g.mintBodies)-1]
}

// testLoaders backs the phase A and phase B loaders and the clock.
type testLoaders struct {
	mu          sync.Mutex
	cfg         Config
	authedCfg   *Config // phase B's config when set, else cfg
	staticErr   error
	authedErr   error
	authedCalls int
	now         time.Time
}

func (l *testLoaders) set(fn func(l *testLoaders)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fn(l)
}

func (l *testLoaders) clock() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.now
}

func (l *testLoaders) calls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.authedCalls
}

// baseOptions returns options using the file tier only, a fresh cache
// directory and loaders that both return the fake server's URL and
// "ghpr_test".
func baseOptions(t *testing.T, g *fakeGHP) (Options, *testLoaders) {
	t.Helper()
	l := &testLoaders{cfg: Config{ServerURL: g.srv.URL, UserToken: testSessionToken}, now: testNow}
	g.set(func(g *fakeGHP) { g.now = l.clock })
	opts := Options{
		Protectors: securestore.NewProtectors(securestore.FileTier()),
		CacheDir:   t.TempDir(),
		Hostname:   "testhost",
		LoadStatic: func() (Config, error) {
			l.mu.Lock()
			defer l.mu.Unlock()
			return l.cfg, l.staticErr
		},
		LoadAuthed: func(context.Context) (Config, error) {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.authedCalls++
			if l.authedErr != nil {
				return Config{}, l.authedErr
			}
			if l.authedCfg != nil {
				return *l.authedCfg, nil
			}
			return l.cfg, nil
		},
		LockTimeout: time.Second,
		Now:         l.clock,
	}
	return opts, l
}

func run(t *testing.T, opts Options, op, stdin string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), opts, op, strings.NewReader(stdin), &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

// wantOutput is the credential the helper prints for token n expiring at
// exp.
func wantOutput(n int, exp time.Time) string {
	return fmt.Sprintf("username=x-access-token\npassword=%s\npassword_expiry_utc=%d\n", fakeToken(n), exp.Unix())
}

// assertFailure checks exit code 1, empty stdout and exactly one prefixed
// stderr line containing want.
func assertFailure(t *testing.T, stdout, stderr string, code int, want string) {
	t.Helper()
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, MessagePrefix) || !strings.HasSuffix(stderr, "\n") {
		t.Errorf("stderr = %q, want exactly one prefixed line", stderr)
	}
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
}

func TestRun_GetMintsAndCaches(t *testing.T) {
	g := newFakeGHP(t)
	opts, l := baseOptions(t, g)

	stdout, stderr, code := run(t, opts, "get", stdGet)
	if code != 0 {
		t.Fatalf("code = %d, stderr %q", code, stderr)
	}
	want := wantOutput(1, testNow.Add(time.Hour))
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}

	stdout2, stderr2, code := run(t, opts, "get", stdGet)
	if code != 0 {
		t.Fatalf("second get code = %d, stderr %q", code, stderr2)
	}
	if stdout2 != want {
		t.Errorf("second get stdout = %q, want %q", stdout2, want)
	}
	if stderr2 != "" {
		t.Errorf("cache hit stderr = %q, want empty", stderr2)
	}
	if n := g.mintCount(); n != 1 {
		t.Errorf("mints = %d, want 1", n)
	}
	if n := l.calls(); n != 1 {
		t.Errorf("phase B calls = %d, want 1 (miss only)", n)
	}
}

func TestRun_GetRemintsInsideMargin(t *testing.T) {
	g := newFakeGHP(t)
	opts, l := baseOptions(t, g)
	if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
		t.Fatalf("get: code %d, stderr %q", code, stderr)
	}

	tests := []struct {
		name      string
		offset    time.Duration
		wantMints int
	}{
		{"outside margin hits", 54 * time.Minute, 1},
		{"inside margin mints", 56 * time.Minute, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l.set(func(l *testLoaders) { l.now = testNow.Add(tt.offset) })
			stdout, stderr, code := run(t, opts, "get", stdGet)
			if code != 0 {
				t.Fatalf("code = %d, stderr %q", code, stderr)
			}
			if n := g.mintCount(); n != tt.wantMints {
				t.Errorf("mints = %d, want %d", n, tt.wantMints)
			}
			if !strings.Contains(stdout, "password="+fakeToken(tt.wantMints)+"\n") {
				t.Errorf("stdout = %q, want token %d", stdout, tt.wantMints)
			}
		})
	}
}

func TestRun_GetDoesNotHoldLockDuringMint(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	opened := false
	g.set(func(g *fakeGHP) {
		g.onMint = func() {
			s, err := (&Cache{Dir: opts.CacheDir, Protectors: opts.Protectors, LockTimeout: 100 * time.Millisecond}).Open()
			if err != nil {
				t.Errorf("Open during mint: %v", err)
				return
			}
			opened = true
			if err := s.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}
	})
	if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
		t.Fatalf("code = %d, stderr %q", code, stderr)
	}
	if !opened {
		t.Error("mint hook did not open the cache")
	}
}

func TestRun_GetIdentitySeparatesSessions(t *testing.T) {
	g := newFakeGHP(t)
	opts, l := baseOptions(t, g)
	steps := []struct {
		token     string
		wantMints int
	}{
		{"ghpr_a", 1},
		{"ghpr_b", 2},
		{"ghpr_a", 2},
	}
	for i, s := range steps {
		t.Run(fmt.Sprintf("%d_%s", i, s.token), func(t *testing.T) {
			l.set(func(l *testLoaders) { l.cfg.UserToken = s.token })
			if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
				t.Fatalf("code = %d, stderr %q", code, stderr)
			}
			if n := g.mintCount(); n != s.wantMints {
				t.Errorf("mints = %d, want %d", n, s.wantMints)
			}
		})
	}
}

func TestRun_GetAgentSelection(t *testing.T) {
	const otherID = "99999999-9999-4999-8999-999999999999"
	tests := []struct {
		name     string
		apps     []App
		selector string
	}{
		{
			name: "by name",
			apps: []App{
				{ID: testAppID, Name: "my-app", AppID: 1},
				{ID: otherID, Name: "other", AppID: 2, IsDefault: true},
			},
			selector: "MY-APP",
		},
		{
			name: "by id",
			apps: []App{
				{ID: otherID, Name: "other", AppID: 2, IsDefault: true},
				{ID: testAppID, Name: "my-app", AppID: 1},
			},
			selector: testAppID,
		},
		{
			name: "default of two",
			apps: []App{
				{ID: otherID, Name: "other", AppID: 2},
				{ID: testAppID, Name: "my-app", AppID: 1, IsDefault: true},
			},
		},
		{
			name: "single without default",
			apps: []App{{ID: testAppID, Name: "my-app", AppID: 1}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newFakeGHP(t)
			g.set(func(g *fakeGHP) { g.apps = tt.apps })
			opts, _ := baseOptions(t, g)
			opts.Settings.App = tt.selector
			if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
				t.Fatalf("code = %d, stderr %q", code, stderr)
			}
			body := g.lastMint(t)
			if body.AppRecordID != testAppID {
				t.Errorf("app_record_id = %q, want %q", body.AppRecordID, testAppID)
			}
			if body.InstallationID != 42 {
				t.Errorf("installation_id = %d, want 42", body.InstallationID)
			}
			if len(body.Repositories) != 1 || body.Repositories[0] != "goodtune/ghp" {
				t.Errorf("repositories = %q, want [goodtune/ghp]", body.Repositories)
			}
			if body.SessionID != "git-credential:testhost" {
				t.Errorf("session_id = %q", body.SessionID)
			}
			if body.Duration != "1h0m0s" {
				t.Errorf("duration = %q, want 1h0m0s", body.Duration)
			}
			if body.Type != TypeAgent {
				t.Errorf("type = %q, want agent", body.Type)
			}
			if body.Scopes != "contents:write" {
				t.Errorf("scopes = %q, want contents:write", body.Scopes)
			}
		})
	}
}

func TestRun_GetNoDefaultAmongTwo(t *testing.T) {
	g := newFakeGHP(t)
	g.set(func(g *fakeGHP) {
		g.apps = []App{
			{ID: testAppID, Name: "my-app", AppID: 1},
			{ID: "99999999-9999-4999-8999-999999999999", Name: "other", AppID: 2},
		}
	})
	opts, _ := baseOptions(t, g)
	stdout, stderr, code := run(t, opts, "get", stdGet)
	assertFailure(t, stdout, stderr, code, "none is the default")
}

func TestRun_GetNoInstallationForOwner(t *testing.T) {
	g := newFakeGHP(t)
	g.set(func(g *fakeGHP) {
		g.installations = []Installation{installation(41, "someone", map[string]string{"contents": "write"})}
	})
	opts, _ := baseOptions(t, g)
	stdout, stderr, code := run(t, opts, "get", stdGet)
	assertFailure(t, stdout, stderr, code, `no installation for "goodtune"`)
}

func TestRun_GetLowersDefaultedScopes(t *testing.T) {
	g := newFakeGHP(t)
	g.set(func(g *fakeGHP) {
		g.installations = []Installation{installation(42, "goodtune", map[string]string{"contents": "read"})}
	})
	opts, _ := baseOptions(t, g)
	if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
		t.Fatalf("code = %d, stderr %q", code, stderr)
	}
	if got := g.lastMint(t).Scopes; got != "contents:read" {
		t.Errorf("mint scopes = %q, want contents:read", got)
	}
	if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
		t.Fatalf("second get code = %d, stderr %q", code, stderr)
	}
	if n := g.mintCount(); n != 1 {
		t.Errorf("mints = %d, want 1 (second get hits under the requested scopes)", n)
	}
}

func TestRun_GetExplicitScopesExceed(t *testing.T) {
	g := newFakeGHP(t)
	g.set(func(g *fakeGHP) {
		g.installations = []Installation{installation(42, "goodtune", map[string]string{"contents": "read"})}
	})
	opts, _ := baseOptions(t, g)
	opts.Settings = Settings{Scopes: "contents:write", ScopesExplicit: true}
	stdout, stderr, code := run(t, opts, "get", stdGet)
	assertFailure(t, stdout, stderr, code, "contents:read")
	if n := g.requestCount("POST /api/tokens"); n != 0 {
		t.Errorf("mint requests = %d, want 0", n)
	}
}

func TestRun_GetAppsForbiddenSuggestsProxy(t *testing.T) {
	g := newFakeGHP(t)
	g.set(func(g *fakeGHP) { g.status["GET /api/apps"] = http.StatusForbidden })
	opts, _ := baseOptions(t, g)
	stdout, stderr, code := run(t, opts, "get", stdGet)
	assertFailure(t, stdout, stderr, code, "--type proxy")
}

func TestRun_GetProxy(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	opts.Settings.Type = TypeProxy
	if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
		t.Fatalf("code = %d, stderr %q", code, stderr)
	}
	body := g.lastMint(t)
	if body.Type != TypeProxy {
		t.Errorf("type = %q, want proxy", body.Type)
	}
	if body.AppRecordID != "" || body.InstallationID != 0 {
		t.Errorf("app fields = %q/%d, want none", body.AppRecordID, body.InstallationID)
	}
	if n := g.requestCount("GET /api/apps"); n != 0 {
		t.Errorf("/api/apps requests = %d, want 0", n)
	}
}

func TestRun_GetSessionExpired(t *testing.T) {
	g := newFakeGHP(t)
	g.set(func(g *fakeGHP) { g.status["POST /api/tokens"] = http.StatusUnauthorized })
	opts, _ := baseOptions(t, g)
	stdout, stderr, code := run(t, opts, "get", stdGet)
	if want := "ghp git-credential: ghp session expired or invalid: run ghp auth login\n"; stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	if code != 1 || stdout != "" {
		t.Errorf("code = %d, stdout %q; want 1 and empty", code, stdout)
	}
}

func TestRun_GetRateLimited(t *testing.T) {
	tests := []struct {
		name, retryAfter, want string
	}{
		{"seconds", "1", "retry in 1s"},
		{"absent", "", "retry in 60s"},
		{"http date", "Wed, 21 Oct 2026 07:28:00 GMT", "retry in 60s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newFakeGHP(t)
			g.set(func(g *fakeGHP) {
				g.status["POST /api/tokens"] = http.StatusTooManyRequests
				g.retryAfter = tt.retryAfter
			})
			opts, _ := baseOptions(t, g)
			stdout, stderr, code := run(t, opts, "get", stdGet)
			assertFailure(t, stdout, stderr, code, "rate limited")
			if !strings.Contains(stderr, tt.want) {
				t.Errorf("stderr = %q, want %q", stderr, tt.want)
			}
		})
	}
}

// TestRun_GetMintRejected pins how other mint errors reach git: the server
// message is printed as-is and only a 403 suggests --type proxy.
func TestRun_GetMintRejected(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		message string
		want    []string
		notWant string
	}{
		{
			name:    "400 repository not in installation account",
			status:  http.StatusBadRequest,
			message: `repository "a/b" does not belong to the installation account "c"`,
			want:    []string{"server returned 400", `repository "a/b" does not belong to the installation account "c"`},
			notWant: "--type proxy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newFakeGHP(t)
			g.set(func(g *fakeGHP) {
				g.status["POST /api/tokens"] = tt.status
				g.message = tt.message
			})
			opts, _ := baseOptions(t, g)
			stdout, stderr, code := run(t, opts, "get", stdGet)
			for _, w := range tt.want {
				assertFailure(t, stdout, stderr, code, w)
			}
			if strings.Contains(stderr, tt.notWant) {
				t.Errorf("stderr = %q, want no %q hint", stderr, tt.notWant)
			}
		})
	}
}

func TestRun_GetInvalidRequest(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	stdout, stderr, code := run(t, opts, "get", "garbage\n")
	if want := MessagePrefix + "invalid credential request from git\n"; stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	if code != 1 || stdout != "" {
		t.Errorf("code = %d, stdout %q; want 1 and empty", code, stdout)
	}

	stdout, stderr, code = run(t, opts, "erase", "garbage\n")
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("erase: code %d, stdout %q, stderr %q; want 0 and no output", code, stdout, stderr)
	}
}

func TestRun_GetHostNotConfigured(t *testing.T) {
	t.Run("default host list", func(t *testing.T) {
		g := newFakeGHP(t)
		opts, _ := baseOptions(t, g)
		stdout, stderr, code := run(t, opts, "get", "protocol=https\nhost=gitlab.com\npath=goodtune/ghp.git\n\n")
		assertFailure(t, stdout, stderr, code, `host "gitlab.com" is not configured`)
		if n := g.requestCount(""); n != 0 {
			t.Errorf("API requests = %d, want 0", n)
		}
	})
	t.Run("configured host, case folded", func(t *testing.T) {
		g := newFakeGHP(t)
		opts, _ := baseOptions(t, g)
		opts.Hosts = []string{"github.com", "ghe.example.com"}
		_, stderr, code := run(t, opts, "get", "protocol=https\nhost=GHE.example.com\npath=goodtune/ghp.git\n\n")
		if code != 0 {
			t.Errorf("code = %d, stderr %q; want 0", code, stderr)
		}
	})
}

func TestRun_GetMissingPath(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	stdout, stderr, code := run(t, opts, "get", "protocol=https\nhost=github.com\n\n")
	assertFailure(t, stdout, stderr, code, "ghp auth setup-git")
	if n := g.requestCount(""); n != 0 {
		t.Errorf("API requests = %d, want 0", n)
	}
}

func TestRun_GetBadPath(t *testing.T) {
	for _, path := range []string{"own%2Fer/repo.git", "../x.git"} {
		t.Run(path, func(t *testing.T) {
			g := newFakeGHP(t)
			opts, _ := baseOptions(t, g)
			stdout, stderr, code := run(t, opts, "get", "protocol=https\nhost=github.com\npath="+path+"\n\n")
			assertFailure(t, stdout, stderr, code, "")
			if n := g.requestCount(""); n != 0 {
				t.Errorf("API requests = %d, want 0", n)
			}
		})
	}
}

func TestRun_GetNotLoggedIn(t *testing.T) {
	g := newFakeGHP(t)
	opts, l := baseOptions(t, g)
	l.set(func(l *testLoaders) { l.cfg = Config{} })
	stdout, stderr, code := run(t, opts, "get", stdGet)
	assertFailure(t, stdout, stderr, code, "not logged in: run ghp auth login")
	if _, err := os.Stat(filepath.Join(opts.CacheDir, LockFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cache.lock exists or Stat failed oddly (%v); the cache must not be touched", err)
	}
}

func TestRun_GetPhaseAError(t *testing.T) {
	g := newFakeGHP(t)
	opts, l := baseOptions(t, g)
	l.set(func(l *testLoaders) { l.staticErr = errors.New("bad config") })
	stdout, stderr, code := run(t, opts, "get", stdGet)
	assertFailure(t, stdout, stderr, code, "bad config")
}

func TestRun_GetPhaseBErrorVerbatim(t *testing.T) {
	const msg = "dotvault login required: run `ghp auth status` in a terminal to log in"
	g := newFakeGHP(t)
	opts, l := baseOptions(t, g)
	l.set(func(l *testLoaders) {
		l.cfg = Config{}
		l.authedErr = errors.New(msg)
	})
	stdout, stderr, code := run(t, opts, "get", stdGet)
	if want := MessagePrefix + msg + "\n"; stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	if code != 1 || stdout != "" {
		t.Errorf("code = %d, stdout %q; want 1 and empty", code, stdout)
	}
}

func TestRun_FailFlattensNewlines(t *testing.T) {
	g := newFakeGHP(t)
	opts, l := baseOptions(t, g)
	l.set(func(l *testLoaders) {
		l.cfg = Config{}
		l.authedErr = errors.New("a\nb\rc")
	})
	_, stderr, code := run(t, opts, "get", stdGet)
	if want := MessagePrefix + "a b c\n"; stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
}

func TestRun_FailSanitisesServerText(t *testing.T) {
	tests := []struct {
		name    string
		message string
		check   func(t *testing.T, msg string)
	}{
		{"terminal escape", "boom\x1b[2Jbang\x07", func(t *testing.T, msg string) {
			if !strings.HasSuffix(msg, ": server returned 500: boom?[2Jbang?") {
				t.Errorf("message = %q, want control characters replaced by ?", msg)
			}
		}},
		{"1 KB message", strings.Repeat("x", 1024), func(t *testing.T, msg string) {
			const sep = ": server returned 500: "
			_, text, ok := strings.Cut(msg, sep)
			if !ok || text != strings.Repeat("x", maxServerTextBytes)+"..." {
				t.Errorf("message = %q, want the server text cut to %d bytes and ending in ...", msg, maxServerTextBytes)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newFakeGHP(t)
			g.set(func(g *fakeGHP) {
				g.status["POST /api/tokens"] = http.StatusInternalServerError
				g.message = tt.message
			})
			opts, _ := baseOptions(t, g)
			stdout, stderr, code := run(t, opts, "get", stdGet)
			assertFailure(t, stdout, stderr, code, "server returned 500")
			for _, r := range stderr[:len(stderr)-1] {
				if r < 0x20 || r == 0x7f {
					t.Errorf("stderr = %q contains control character %U", stderr, r)
				}
			}
			tt.check(t, strings.TrimSuffix(strings.TrimPrefix(stderr, MessagePrefix), "\n"))
		})
	}
}

func TestRun_WarningsReemitted(t *testing.T) {
	g := newFakeGHP(t)
	opts, l := baseOptions(t, g)
	l.set(func(l *testLoaders) {
		l.cfg.Warnings = []string{"warning: config file x has insecure permissions"}
	})
	_, stderr, code := run(t, opts, "get", stdGet)
	if code != 0 {
		t.Fatalf("code = %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stderr, MessagePrefix+"warning: config file x has insecure permissions\n") {
		t.Errorf("stderr = %q, want the prefixed warning", stderr)
	}
}

func TestRun_GetNullExpiry(t *testing.T) {
	g := newFakeGHP(t)
	g.set(func(g *fakeGHP) { g.nullExpiry = true })
	opts, _ := baseOptions(t, g)
	stdout, stderr, code := run(t, opts, "get", stdGet)
	assertFailure(t, stdout, stderr, code, "no expiry")
	if got := g.revokedIDs(); len(got) != 1 || got[0] != "tok-1" {
		t.Errorf("revoked = %q, want [tok-1]", got)
	}
}

func TestRun_GetEmptyToken(t *testing.T) {
	g := newFakeGHP(t)
	g.set(func(g *fakeGHP) { g.emptyToken = true })
	opts, _ := baseOptions(t, g)
	stdout, stderr, code := run(t, opts, "get", stdGet)
	assertFailure(t, stdout, stderr, code, "")
	if want := MessagePrefix + "server returned an empty token\n"; stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	if got := g.revokedIDs(); len(got) != 1 || got[0] != "tok-1" {
		t.Errorf("revoked = %q, want [tok-1]", got)
	}
	if _, err := os.Stat(filepath.Join(opts.CacheDir, CacheFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cache.enc stat err = %v, want not exist (nothing cached)", err)
	}
}

func TestRun_GetTTLNever(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	opts.Settings.TTL = "never"
	stdout, stderr, code := run(t, opts, "get", stdGet)
	assertFailure(t, stdout, stderr, code, "never")
	if n := g.requestCount(""); n != 0 {
		t.Errorf("API requests = %d, want 0", n)
	}
}

func TestRun_GetCacheBackendErrors(t *testing.T) {
	tests := []struct{ backend, want string }{
		{"bogus", "unknown cache backend"},
		{securestore.TierTPM, "unknown tier"}, // not in the file-only protector set
	}
	for _, tt := range tests {
		t.Run(tt.backend, func(t *testing.T) {
			g := newFakeGHP(t)
			opts, _ := baseOptions(t, g)
			opts.CacheBackend = tt.backend
			stdout, stderr, code := run(t, opts, "get", stdGet)
			assertFailure(t, stdout, stderr, code, tt.want)
			if n := g.requestCount(""); n != 0 {
				t.Errorf("API requests = %d, want 0", n)
			}
		})
	}
}

func TestRun_GetNoCacheDir(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	opts.CacheDir = ""
	for i := 1; i <= 2; i++ {
		stdout, stderr, code := run(t, opts, "get", stdGet)
		if code != 0 || stderr != "" {
			t.Fatalf("get %d: code %d, stderr %q; want 0 and no notice", i, code, stderr)
		}
		if !strings.Contains(stdout, "password="+fakeToken(i)+"\n") {
			t.Errorf("get %d stdout = %q, want a fresh mint", i, stdout)
		}
	}
}

func TestRun_GetLockTimeoutStillReturnsToken(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	opts.LockTimeout = 100 * time.Millisecond
	held, err := (&Cache{Dir: opts.CacheDir, Protectors: opts.Protectors}).Open()
	if err != nil {
		t.Fatalf("holding the lock: %v", err)
	}
	defer func() { _ = held.Close() }()

	stdout, stderr, code := run(t, opts, "get", stdGet)
	if code != 0 {
		t.Fatalf("code = %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "password="+fakeToken(1)+"\n") {
		t.Errorf("stdout = %q, want the minted token", stdout)
	}
	if strings.Count(stderr, "\n") != 1 || !strings.Contains(stderr, "continuing without it") {
		t.Errorf("stderr = %q, want exactly one line containing %q", stderr, "continuing without it")
	}
}

func TestRun_GetCacheUnusableStillReturnsToken(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	file := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts.CacheDir = filepath.Join(file, "sub")

	stdout, stderr, code := run(t, opts, "get", stdGet)
	if code != 0 {
		t.Fatalf("code = %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "password=") {
		t.Errorf("stdout = %q, want a credential", stdout)
	}
	if strings.Count(stderr, "\n") != 1 || !strings.Contains(stderr, "could not use the credential cache") {
		t.Errorf("stderr = %q, want exactly one line containing %q", stderr, "could not use the credential cache")
	}
}

func TestRun_GetUnreadableCacheNoticeOnce(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	f := newFakeTiers()
	f.avail[securestore.TierKeychain] = true
	putCommit(t, newCache(t, opts.CacheDir, "", f), "o/r", freshEntry("a"))
	encPath := filepath.Join(opts.CacheDir, CacheFileName)
	before := readFile(t, encPath)
	f.set(func(f *fakeTiers) { f.unwrapErr[securestore.TierKeychain] = errors.New("locked") })
	opts.Protectors = f.protectors()

	stdout, stderr, code := run(t, opts, "get", stdGet)
	if code != 0 {
		t.Fatalf("code = %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "password=") {
		t.Errorf("stdout = %q, want a credential", stdout)
	}
	const remedy = "; continuing without it (run ghp auth git-credential clear if this persists)\n"
	if strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, MessagePrefix+"cannot read the credential cache (") || !strings.HasSuffix(stderr, remedy) {
		t.Errorf("stderr = %q, want exactly one unreadable-cache line ending %q", stderr, remedy)
	}
	if !bytes.Equal(readFile(t, encPath), before) {
		t.Error("unreadable cache.enc was rewritten")
	}
}

func TestRun_Store(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	stdout, stderr, code := run(t, opts, "store", "protocol=https\nhost=github.com\npassword=whatever\n\n")
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("code %d, stdout %q, stderr %q; want 0 and no output", code, stdout, stderr)
	}
	if n := g.requestCount(""); n != 0 {
		t.Errorf("API requests = %d, want 0", n)
	}
}

func TestRun_UnknownOp(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	stdout, stderr, code := run(t, opts, "frobnicate", stdGet)
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("code %d, stdout %q, stderr %q; want 0 and no output", code, stdout, stderr)
	}
}

func TestRun_EraseDeletesAndRevokes(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{"matching password", fakeToken(1)},
		{"no password", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newFakeGHP(t)
			opts, _ := baseOptions(t, g)
			if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
				t.Fatalf("get: code %d, stderr %q", code, stderr)
			}
			lockFree := false
			g.set(func(g *fakeGHP) {
				g.onRevoke = func() {
					s, err := (&Cache{Dir: opts.CacheDir, Protectors: opts.Protectors, LockTimeout: 100 * time.Millisecond}).Open()
					if err != nil {
						t.Errorf("Open during revoke: %v", err)
						return
					}
					lockFree = true
					if err := s.Close(); err != nil {
						t.Errorf("Close: %v", err)
					}
				}
			})

			stdout, stderr, code := run(t, opts, "erase", eraseWith(tt.password))
			if code != 0 || stdout != "" || stderr != "" {
				t.Errorf("erase: code %d, stdout %q, stderr %q; want 0 and no output", code, stdout, stderr)
			}
			if got := g.revokedIDs(); len(got) != 1 || got[0] != "tok-1" {
				t.Errorf("revoked = %q, want [tok-1]", got)
			}
			if !lockFree {
				t.Error("revoke hook could not open the cache")
			}

			if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
				t.Fatalf("get after erase: code %d, stderr %q", code, stderr)
			}
			if n := g.mintCount(); n != 2 {
				t.Errorf("mints = %d, want 2", n)
			}
		})
	}
}

func TestRun_EraseKeepsNewerToken(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
		t.Fatalf("get: code %d, stderr %q", code, stderr)
	}
	stdout, stderr, code := run(t, opts, "erase", eraseWith("gha_stale"))
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("erase: code %d, stdout %q, stderr %q; want 0 and no output", code, stdout, stderr)
	}
	if got := g.revokedIDs(); len(got) != 0 {
		t.Errorf("revoked = %q, want none", got)
	}
	if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
		t.Fatalf("get: code %d, stderr %q", code, stderr)
	}
	if n := g.mintCount(); n != 1 {
		t.Errorf("mints = %d, want 1 (cached token kept)", n)
	}
}

func TestRun_EraseRevokeFailure(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
		t.Fatalf("get: code %d, stderr %q", code, stderr)
	}
	g.set(func(g *fakeGHP) { g.status["DELETE /api/tokens/{id}"] = http.StatusInternalServerError })
	stdout, stderr, code := run(t, opts, "erase", eraseWith(fakeToken(1)))
	if code != 0 || stdout != "" {
		t.Errorf("erase: code %d, stdout %q; want 0 and empty", code, stdout)
	}
	if strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, MessagePrefix+"could not revoke token gha_fake...") {
		t.Errorf("stderr = %q, want one line starting %q", stderr, MessagePrefix+"could not revoke token gha_fake...")
	}
}

func TestRun_NeverLeaksToken(t *testing.T) {
	type step struct{ op, stdin string }
	tests := []struct {
		name  string
		setup func(g *fakeGHP)
		steps []step
	}{
		{"get and erase", nil, []step{{"get", stdGet}, {"get", stdGet}, {"erase", eraseWith(fakeToken(1))}}},
		{"revoke failure", func(g *fakeGHP) { g.status["DELETE /api/tokens/{id}"] = http.StatusInternalServerError },
			[]step{{"get", stdGet}, {"erase", eraseWith(fakeToken(1))}}},
		{"session expired", func(g *fakeGHP) { g.status["POST /api/tokens"] = http.StatusUnauthorized }, []step{{"get", stdGet}}},
		{"rate limited", func(g *fakeGHP) { g.status["POST /api/tokens"] = http.StatusTooManyRequests }, []step{{"get", stdGet}}},
		{"null expiry", func(g *fakeGHP) { g.nullExpiry = true }, []step{{"get", stdGet}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newFakeGHP(t)
			if tt.setup != nil {
				g.set(tt.setup)
			}
			opts, _ := baseOptions(t, g)
			for _, s := range tt.steps {
				_, stderr, _ := run(t, opts, s.op, s.stdin)
				if strings.Contains(stderr, "gha_fake0") {
					t.Errorf("%s stderr leaks a token: %q", s.op, stderr)
				}
			}
		})
	}
}

func TestSessionID(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     string
		wantLen  int
	}{
		{name: "short", hostname: "h", want: "git-credential:h"},
		{name: "truncated", hostname: strings.Repeat("a", 200), wantLen: 128},
		// The prefix is 15 bytes; 112 "a" put a 2-byte "é" across byte 128.
		{name: "rune boundary", hostname: strings.Repeat("a", 112) + "é" + "b", wantLen: 127},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SessionID(tt.hostname)
			if tt.want != "" && got != tt.want {
				t.Errorf("SessionID = %q, want %q", got, tt.want)
			}
			if tt.wantLen != 0 && len(got) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(got), tt.wantLen)
			}
			if len(got) > 128 || !utf8.ValidString(got) || !strings.HasPrefix(got, "git-credential:") {
				t.Errorf("SessionID = %q: want valid UTF-8, at most 128 bytes, prefixed", got)
			}
		})
	}
}

// getFor returns a get request for owner/repo.
func getFor(repo string) string {
	return "protocol=https\nhost=github.com\npath=" + repo + ".git\n\n"
}

// fatalLoaders makes both config loaders fail the test when called.
func fatalLoaders(t *testing.T, opts *Options) {
	t.Helper()
	opts.LoadStatic = func() (Config, error) {
		t.Fatal("phase A loader called")
		return Config{}, nil
	}
	opts.LoadAuthed = func(context.Context) (Config, error) {
		t.Fatal("phase B loader called")
		return Config{}, nil
	}
}

func TestRun_StatusShowsEntriesNotTokens(t *testing.T) {
	g := newFakeGHP(t)
	opts, l := baseOptions(t, g)
	if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
		t.Fatalf("get: code %d, stderr %q", code, stderr)
	}

	tests := []struct {
		name    string
		offset  time.Duration
		backend string
		want    []string
	}{
		{"fresh", 0, "", []string{
			"Cache path:     " + filepath.Join(opts.CacheDir, CacheFileName) + "\n",
			"Cache backend:  file\n",
			"Minimum tier:   file\n",
			"Protection:     file permissions only (0600); see docs\n",
			"Tier file:      available\n",
			"Entries:        1\n",
			"  goodtune/ghp  agent  app=my-app  token=gha_fake...  expires=2026-11-08T13:00:00Z (in 60m)\n",
		}},
		{"rounded minutes", 30*time.Minute + 20*time.Second, "", []string{"(in 30m)\n"}},
		{"expired", 2 * time.Hour, "", []string{"expires=2026-11-08T13:00:00Z (expired)\n"}},
		{"cache backend ignored", 0, securestore.TierTPM, []string{"Cache backend:  file\n", "Entries:        1\n"}},
		{"cache backend none ignored", 0, BackendNone, []string{"Cache backend:  file\n", "Entries:        1\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l.set(func(l *testLoaders) { l.now = testNow.Add(tt.offset) })
			o := opts
			o.CacheBackend = tt.backend
			stdout, stderr, code := run(t, o, "status", "")
			if code != 0 || stderr != "" {
				t.Fatalf("status: code %d, stderr %q; want 0 and no stderr", code, stderr)
			}
			for _, w := range tt.want {
				if !strings.Contains(stdout, w) {
					t.Errorf("stdout = %q, want it to contain %q", stdout, w)
				}
			}
			if strings.Contains(stdout, fakeToken(1)) || strings.Contains(stdout, "gha_fake0") {
				t.Errorf("stdout = %q, leaks more than 8 characters of the token", stdout)
			}
		})
	}
}

func TestRun_StatusSortsEntries(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	for _, repo := range []string{"goodtune/zeta", "goodtune/alpha"} {
		if _, stderr, code := run(t, opts, "get", getFor(repo)); code != 0 {
			t.Fatalf("get %s: code %d, stderr %q", repo, code, stderr)
		}
	}
	stdout, stderr, code := run(t, opts, "status", "")
	if code != 0 || stderr != "" {
		t.Fatalf("status: code %d, stderr %q", code, stderr)
	}
	a, z := strings.Index(stdout, "  goodtune/alpha  "), strings.Index(stdout, "  goodtune/zeta  ")
	if a < 0 || z < 0 || a > z {
		t.Errorf("stdout = %q, want the goodtune/alpha line before goodtune/zeta", stdout)
	}
	if !strings.Contains(stdout, "Entries:        2\n") {
		t.Errorf("stdout = %q, want 2 entries", stdout)
	}
}

func TestRun_StatusEmpty(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	stdout, stderr, code := run(t, opts, "status", "")
	if code != 0 || stderr != "" {
		t.Fatalf("status: code %d, stderr %q", code, stderr)
	}
	want := "Cache path:     " + filepath.Join(opts.CacheDir, CacheFileName) + "\n" +
		"Cache backend:  none\n" +
		"Minimum tier:   none\n" +
		"Protection:     no cache\n" +
		"Tier file:      available\n" +
		"Entries:        0\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

func TestRun_StatusTiers(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	f := newFakeTiers()
	f.avail[securestore.TierKeychain] = true
	opts.Protectors = f.protectors()
	if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
		t.Fatalf("get: code %d, stderr %q", code, stderr)
	}
	stdout, stderr, code := run(t, opts, "status", "")
	if code != 0 || stderr != "" {
		t.Fatalf("status: code %d, stderr %q", code, stderr)
	}
	want := "Cache backend:  keychain\n" +
		"Minimum tier:   keychain\n" +
		"Protection:     macOS login keychain\n" +
		"Tier tpm:       unavailable (securestore: protector unavailable: tpm: not present)\n" +
		"Tier keychain:  available\n" +
		"Tier file:      available\n" +
		"Entries:        1\n"
	if !strings.Contains(stdout, want) {
		t.Errorf("stdout = %q, want it to contain %q", stdout, want)
	}
}

func TestRun_StatusNoServer(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
		t.Fatalf("get: code %d, stderr %q", code, stderr)
	}
	before := g.requestCount("")
	fatalLoaders(t, &opts)
	if _, stderr, code := run(t, opts, "status", ""); code != 0 {
		t.Fatalf("status: code %d, stderr %q", code, stderr)
	}
	if n := g.requestCount(""); n != before {
		t.Errorf("API requests = %d, want %d (status never contacts the server)", n, before)
	}
}

func TestRun_StatusUnreadableQuiet(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	f := newFakeTiers()
	f.avail[securestore.TierKeychain] = true
	putCommit(t, newCache(t, opts.CacheDir, "", f), "o/r", freshEntry("a"))
	f.set(func(f *fakeTiers) { f.unwrapErr[securestore.TierKeychain] = errors.New("locked") })
	opts.Protectors = f.protectors()

	stdout, stderr, code := run(t, opts, "status", "")
	if code != 0 {
		t.Fatalf("status: code %d, stderr %q", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty (the cache notice is suppressed)", stderr)
	}
	for _, w := range []string{"Cache backend:  keychain\n", "Entries:        unavailable (keychain: locked)\n"} {
		if !strings.Contains(stdout, w) {
			t.Errorf("stdout = %q, want it to contain %q", stdout, w)
		}
	}
}

func TestRun_StatusOpenFails(t *testing.T) {
	tests := []struct {
		name string
		dir  func(t *testing.T) string
		want string
	}{
		{"no cache directory", func(*testing.T) string { return "" }, "no credential cache directory"},
		{"directory under a file", func(t *testing.T) string {
			file := filepath.Join(t.TempDir(), "plain")
			if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(file, "sub")
		}, "could not open the credential cache"},
	}
	for _, tt := range tests {
		for _, op := range []string{"status", "clear"} {
			t.Run(tt.name+"/"+op, func(t *testing.T) {
				g := newFakeGHP(t)
				opts, _ := baseOptions(t, g)
				opts.CacheDir = tt.dir(t)
				stdout, stderr, code := run(t, opts, op, "")
				assertFailure(t, stdout, stderr, code, tt.want)
			})
		}
	}
}

func TestRun_ClearRevokesAndKeepsTier(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	for _, repo := range []string{"goodtune/ghp", "goodtune/other"} {
		if _, stderr, code := run(t, opts, "get", getFor(repo)); code != 0 {
			t.Fatalf("get %s: code %d, stderr %q", repo, code, stderr)
		}
	}
	lockFree := 0
	g.set(func(g *fakeGHP) {
		g.onRevoke = func() {
			s, err := (&Cache{Dir: opts.CacheDir, Protectors: opts.Protectors, LockTimeout: 100 * time.Millisecond}).Open()
			if err != nil {
				t.Errorf("Open during revoke: %v", err)
				return
			}
			lockFree++
			if err := s.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}
	})

	stdout, stderr, code := run(t, opts, "clear", "")
	if code != 0 || stderr != "" {
		t.Fatalf("clear: code %d, stderr %q; want 0 and no stderr", code, stderr)
	}
	if want := "Cleared 2 cached credentials; revoked 2.\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if n := g.requestCount("DELETE /api/tokens/"); n != 2 {
		t.Errorf("DELETE requests = %d, want 2", n)
	}
	if got := g.revokedIDs(); len(got) != 2 || got[0] != "tok-1" || got[1] != "tok-2" {
		t.Errorf("revoked = %q, want [tok-1 tok-2]", got)
	}
	if lockFree != 2 {
		t.Errorf("revoke hook opened the cache %d times, want 2", lockFree)
	}
	if _, err := os.Stat(filepath.Join(opts.CacheDir, CacheFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cache.enc stat err = %v, want not exist", err)
	}
	if got := string(readFile(t, filepath.Join(opts.CacheDir, TierFileName))); got != securestore.TierFile {
		t.Errorf("tier = %q, want %q", got, securestore.TierFile)
	}

	if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
		t.Fatalf("get after clear: code %d, stderr %q", code, stderr)
	}
	if n := g.mintCount(); n != 3 {
		t.Errorf("mints = %d, want 3", n)
	}
}

func TestRun_ClearEmpty(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	fatalLoaders(t, &opts)
	stdout, stderr, code := run(t, opts, "clear", "")
	if code != 0 || stderr != "" {
		t.Fatalf("clear: code %d, stderr %q", code, stderr)
	}
	if want := "Cleared 0 cached credentials; revoked 0.\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if n := g.requestCount(""); n != 0 {
		t.Errorf("API requests = %d, want 0", n)
	}
}

func TestRun_ClearWithoutServer(t *testing.T) {
	tests := []struct {
		name string
		set  func(l *testLoaders)
		want string
	}{
		{"empty config", func(l *testLoaders) { l.cfg = Config{} }, "tokens not revoked: " + msgNotLoggedIn},
		{"phase B error", func(l *testLoaders) {
			l.cfg = Config{}
			l.authedErr = errors.New("dotvault login required")
		}, "tokens not revoked: dotvault login required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newFakeGHP(t)
			opts, l := baseOptions(t, g)
			if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
				t.Fatalf("get: code %d, stderr %q", code, stderr)
			}
			l.set(tt.set)

			stdout, stderr, code := run(t, opts, "clear", "")
			if code != 0 {
				t.Fatalf("clear: code %d, stderr %q", code, stderr)
			}
			if want := "Cleared 1 cached credentials; revoked 0.\n"; stdout != want {
				t.Errorf("stdout = %q, want %q", stdout, want)
			}
			if stderr != MessagePrefix+tt.want+"\n" {
				t.Errorf("stderr = %q, want one line %q", stderr, MessagePrefix+tt.want)
			}
			if n := g.requestCount("DELETE "); n != 0 {
				t.Errorf("DELETE requests = %d, want 0", n)
			}
			if _, err := os.Stat(filepath.Join(opts.CacheDir, CacheFileName)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("cache.enc stat err = %v, want not exist", err)
			}
		})
	}
}

func TestRun_ClearRevokeFailure(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	for _, repo := range []string{"goodtune/ghp", "goodtune/other"} {
		if _, stderr, code := run(t, opts, "get", getFor(repo)); code != 0 {
			t.Fatalf("get %s: code %d, stderr %q", repo, code, stderr)
		}
	}
	g.set(func(g *fakeGHP) { g.status["DELETE /api/tokens/{id}"] = http.StatusInternalServerError })
	stdout, stderr, code := run(t, opts, "clear", "")
	if code != 0 {
		t.Fatalf("clear: code %d, stderr %q", code, stderr)
	}
	if want := "Cleared 2 cached credentials; revoked 0.\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if strings.Count(stderr, "\n") != 2 || strings.Count(stderr, MessagePrefix+"could not revoke token gha_fake...") != 2 {
		t.Errorf("stderr = %q, want two prefixed could-not-revoke lines", stderr)
	}
	if strings.Contains(stderr, "gha_fake0") {
		t.Errorf("stderr leaks a token: %q", stderr)
	}
}

func TestRun_ClearUnreadable(t *testing.T) {
	g := newFakeGHP(t)
	opts, _ := baseOptions(t, g)
	f := newFakeTiers()
	f.avail[securestore.TierKeychain] = true
	putCommit(t, newCache(t, opts.CacheDir, "", f), "o/r", freshEntry("a"))
	f.set(func(f *fakeTiers) { f.unwrapErr[securestore.TierKeychain] = errors.New("locked") })
	opts.Protectors = f.protectors()
	fatalLoaders(t, &opts)

	stdout, stderr, code := run(t, opts, "clear", "")
	if code != 0 {
		t.Fatalf("clear: code %d, stderr %q", code, stderr)
	}
	if want := "Cleared 0 cached credentials; revoked 0.\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if want := MessagePrefix + "cache could not be read; removed it without revoking tokens\n"; stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	if n := g.requestCount(""); n != 0 {
		t.Errorf("API requests = %d, want 0", n)
	}
	if _, err := os.Stat(filepath.Join(opts.CacheDir, CacheFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cache.enc stat err = %v, want not exist", err)
	}
	if got := string(readFile(t, filepath.Join(opts.CacheDir, TierFileName))); got != securestore.TierKeychain {
		t.Errorf("tier = %q, want %q", got, securestore.TierKeychain)
	}
}

// splitPhases makes phase A return a stale session token and phase B a
// live one, as when an old `ghp auth login` token sits in config.yaml and
// dotvault supplies the current one.
func splitPhases(g *fakeGHP, l *testLoaders, staticURL string) {
	l.set(func(l *testLoaders) {
		l.cfg = Config{ServerURL: staticURL, UserToken: "ghpr_stale"}
		l.authedCfg = &Config{ServerURL: g.srv.URL, UserToken: "ghpr_live"}
	})
}

// wantAuths checks that every request matching prefix carried want and
// that there were n of them.
func wantAuths(t *testing.T, g *fakeGHP, prefix string, n int, want string) {
	t.Helper()
	got := g.authsFor(prefix)
	if len(got) != n {
		t.Fatalf("%s requests = %d, want %d", prefix, len(got), n)
	}
	for _, a := range got {
		if a != want {
			t.Errorf("%s Authorization = %q, want %q", prefix, a, want)
		}
	}
}

func TestRun_GetMintsWithPhaseBCredentials(t *testing.T) {
	g := newFakeGHP(t)
	opts, l := baseOptions(t, g)
	splitPhases(g, l, g.srv.URL)
	if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
		t.Fatalf("get: code %d, stderr %q", code, stderr)
	}
	wantAuths(t, g, "POST /api/tokens", 1, "Bearer ghpr_live")
	wantAuths(t, g, "GET /api/apps", 2, "Bearer ghpr_live")
}

func TestRun_EraseRevokesWithPhaseBToken(t *testing.T) {
	g := newFakeGHP(t)
	opts, l := baseOptions(t, g)
	splitPhases(g, l, g.srv.URL)
	if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
		t.Fatalf("get: code %d, stderr %q", code, stderr)
	}
	stdout, stderr, code := run(t, opts, "erase", eraseWith(fakeToken(1)))
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("erase: code %d, stdout %q, stderr %q; want 0 and no output", code, stdout, stderr)
	}
	if got := g.revokedIDs(); len(got) != 1 || got[0] != "tok-1" {
		t.Errorf("revoked = %q, want [tok-1]", got)
	}
	wantAuths(t, g, "DELETE /api/tokens/", 1, "Bearer ghpr_live")
}

func TestRun_ClearRevokesWithPhaseBToken(t *testing.T) {
	tests := []struct {
		name      string
		staticURL func(g *fakeGHP) string
	}{
		{"phase A has a stale token", func(g *fakeGHP) string { return g.srv.URL }},
		{"phase A has a token but no server URL", func(*fakeGHP) string { return "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newFakeGHP(t)
			opts, l := baseOptions(t, g)
			splitPhases(g, l, tt.staticURL(g))
			for _, repo := range []string{"goodtune/ghp", "goodtune/other"} {
				if _, stderr, code := run(t, opts, "get", getFor(repo)); code != 0 {
					t.Fatalf("get %s: code %d, stderr %q", repo, code, stderr)
				}
			}
			stdout, stderr, code := run(t, opts, "clear", "")
			if code != 0 || stderr != "" {
				t.Fatalf("clear: code %d, stderr %q; want 0 and no stderr", code, stderr)
			}
			if want := "Cleared 2 cached credentials; revoked 2.\n"; stdout != want {
				t.Errorf("stdout = %q, want %q", stdout, want)
			}
			wantAuths(t, g, "DELETE /api/tokens/", 2, "Bearer ghpr_live")
		})
	}
}

func TestRun_RevokeFallsBackToPhaseA(t *testing.T) {
	const phaseBErr = "dotvault login required"
	tests := []struct {
		name  string
		op    string
		stdin string
		n     int
	}{
		{"erase", "erase", eraseWith(fakeToken(1)), 1},
		{"clear", "clear", "", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newFakeGHP(t)
			opts, l := baseOptions(t, g)
			splitPhases(g, l, g.srv.URL)
			if _, stderr, code := run(t, opts, "get", stdGet); code != 0 {
				t.Fatalf("get: code %d, stderr %q", code, stderr)
			}
			l.set(func(l *testLoaders) { l.authedErr = errors.New(phaseBErr) })
			_, stderr, code := run(t, opts, tt.op, tt.stdin)
			if code != 0 {
				t.Fatalf("%s: code %d, stderr %q", tt.op, code, stderr)
			}
			want := MessagePrefix + phaseBErr + "; revoking with the user token from the config files or environment\n"
			if stderr != want {
				t.Errorf("stderr = %q, want %q", stderr, want)
			}
			wantAuths(t, g, "DELETE /api/tokens/", tt.n, "Bearer ghpr_stale")
		})
	}
}
