package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	dvclient "github.com/goodtune/dotvault/client"

	"github.com/goodtune/ghp/internal/gitcred"
	"github.com/goodtune/ghp/internal/securestore"
)

// credGet is the standard credential request of these tests.
const credGet = "protocol=https\nhost=github.com\npath=goodtune/ghp.git\n\n"

const (
	mainAppID  = "11111111-1111-1111-1111-111111111111"
	otherAppID = "22222222-2222-2222-2222-222222222222"
)

// fakeCredServer is an httptest ghp server for the helper's API calls. It
// serves two apps, "main" (the default) and "other", each installed on
// goodtune, and records every mint body.
type fakeCredServer struct {
	srv *httptest.Server

	mu    sync.Mutex
	perms map[string]string
	mints []gitcred.MintRequest
}

func newFakeCredServer(t *testing.T) *fakeCredServer {
	t.Helper()
	f := &fakeCredServer{perms: map[string]string{"contents": "write", "metadata": "read"}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/apps", func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(t, w, http.StatusOK, []gitcred.App{
			{ID: mainAppID, Name: "main", AppID: 1, IsDefault: true},
			{ID: otherAppID, Name: "other", AppID: 2},
		})
	})
	mux.HandleFunc("GET /api/apps/{id}/installations", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		perms := f.perms
		f.mu.Unlock()
		writeTestJSON(t, w, http.StatusOK, []map[string]any{{
			"id":          42,
			"account":     map[string]string{"login": "goodtune"},
			"permissions": perms,
		}})
	})
	mux.HandleFunc("POST /api/tokens", func(w http.ResponseWriter, r *http.Request) {
		var body gitcred.MintRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decoding mint body: %v", err)
		}
		f.mu.Lock()
		f.mints = append(f.mints, body)
		n := len(f.mints)
		f.mu.Unlock()
		writeTestJSON(t, w, http.StatusCreated, map[string]any{
			"token":        fmt.Sprintf("gha_cli%04dabcdefghijklmnopqrstuvwxyz", n),
			"id":           "tok-" + strconv.Itoa(n),
			"type":         body.Type,
			"repositories": body.Repositories,
			"expires_at":   time.Now().Add(time.Hour),
		})
	})
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ghpr_") {
			t.Errorf("Authorization = %q, want a bearer ghpr_ session token", got)
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, status int, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encoding response: %v", err)
	}
}

func (f *fakeCredServer) setPerms(perms map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.perms = perms
}

func (f *fakeCredServer) mintBodies() []gitcred.MintRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]gitcred.MintRequest(nil), f.mints...)
}

// setupGitCredential isolates the helper: a fresh HOME, the fake server, a
// static session token, every GHP_GIT_CM_* variable empty and a file-only
// protector set. It returns the fake server and the HOME directory.
func setupGitCredential(t *testing.T) (*fakeCredServer, string) {
	t.Helper()
	f := newFakeCredServer(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("GHP_SERVER_URL", f.srv.URL)
	t.Setenv("GHP_USER_TOKEN", "ghpr_test")
	for _, name := range []string{"GHP_GIT_CM_APP", "GHP_GIT_CM_TYPE", "GHP_GIT_CM_SCOPES", "GHP_GIT_CM_TTL", "GHP_GIT_CM_CACHE_BACKEND"} {
		t.Setenv(name, "")
	}
	orig := gitCredentialProtectors
	t.Cleanup(func() { gitCredentialProtectors = orig })
	gitCredentialProtectors = func() *securestore.Protectors {
		return securestore.NewProtectors(securestore.FileTier())
	}
	return f, home
}

// runGitCredential executes `ghp auth git-credential args...` through the
// root command and returns what main would leave behind: stdout, stderr
// and the process exit code.
func runGitCredential(t *testing.T, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	root := newRootCmd()
	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"auth", "git-credential"}, args...))
	err := root.Execute()
	var ec *exitCodeError
	switch {
	case err == nil:
	case errors.As(err, &ec):
		code = ec.code
	default:
		fmt.Fprintln(&errOut, err)
		code = 1
	}
	return out.String(), errOut.String(), code
}

// password returns the password line of a credential response.
func password(t *testing.T, stdout string) string {
	t.Helper()
	for _, line := range strings.Split(stdout, "\n") {
		if v, ok := strings.CutPrefix(line, "password="); ok {
			return v
		}
	}
	t.Fatalf("no password in output %q", stdout)
	return ""
}

const dotvaultUserConfig = "dotvault:\n  service: ghp\n  fields:\n    user_token: token\n"

func TestGitCredential_TypePrecedence(t *testing.T) {
	tests := []struct {
		name string
		env  string
		args []string
		want string
	}{
		{name: "env", env: "proxy", want: "proxy"},
		{name: "flag over env", env: "proxy", args: []string{"--type", "agent"}, want: "agent"},
		{name: "default", want: "agent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, _ := setupGitCredential(t)
			t.Setenv("GHP_GIT_CM_TYPE", tt.env)
			stdout, stderr, code := runGitCredential(t, credGet, append([]string{"get"}, tt.args...)...)
			if code != 0 {
				t.Fatalf("code = %d, stderr = %q", code, stderr)
			}
			if stdout == "" {
				t.Error("stdout is empty, want a credential")
			}
			mints := f.mintBodies()
			if len(mints) != 1 || mints[0].Type != tt.want {
				t.Fatalf("mints = %+v, want one of type %q", mints, tt.want)
			}
		})
	}
}

func TestGitCredential_AppPrecedence(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "env", want: otherAppID},
		{name: "flag over env", args: []string{"--app", "main"}, want: mainAppID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, _ := setupGitCredential(t)
			t.Setenv("GHP_GIT_CM_APP", "other")
			_, stderr, code := runGitCredential(t, credGet, append([]string{"get"}, tt.args...)...)
			if code != 0 {
				t.Fatalf("code = %d, stderr = %q", code, stderr)
			}
			mints := f.mintBodies()
			if len(mints) != 1 || mints[0].AppRecordID != tt.want {
				t.Fatalf("mints = %+v, want one with app_record_id %q", mints, tt.want)
			}
		})
	}
}

func TestGitCredential_EnvAppIgnoredUnderProxyFlag(t *testing.T) {
	t.Run("env app with proxy flag", func(t *testing.T) {
		f, _ := setupGitCredential(t)
		t.Setenv("GHP_GIT_CM_APP", "other")
		_, stderr, code := runGitCredential(t, credGet, "get", "--type", "proxy")
		if code != 0 {
			t.Fatalf("code = %d, stderr = %q", code, stderr)
		}
		mints := f.mintBodies()
		if len(mints) != 1 || mints[0].Type != "proxy" || mints[0].AppRecordID != "" || mints[0].InstallationID != 0 {
			t.Fatalf("mints = %+v, want one proxy mint without app fields", mints)
		}
	})
	t.Run("env app with env proxy", func(t *testing.T) {
		// Only a --type flag (the helper line) excuses an exported app.
		f, _ := setupGitCredential(t)
		t.Setenv("GHP_GIT_CM_APP", "other")
		t.Setenv("GHP_GIT_CM_TYPE", "proxy")
		stdout, stderr, code := runGitCredential(t, credGet, "get")
		if code != 1 {
			t.Fatalf("code = %d, want 1", code)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want empty", stdout)
		}
		if !strings.Contains(stderr, "--app is only valid with --type agent") {
			t.Errorf("stderr = %q, want the --app/--type message", stderr)
		}
		if n := len(f.mintBodies()); n != 0 {
			t.Errorf("mints = %d, want 0", n)
		}
	})
	t.Run("app flag with proxy flag", func(t *testing.T) {
		f, _ := setupGitCredential(t)
		stdout, stderr, code := runGitCredential(t, credGet, "get", "--app", "other", "--type", "proxy")
		if code != 1 {
			t.Fatalf("code = %d, want 1", code)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want empty", stdout)
		}
		if !strings.Contains(stderr, "--app is only valid with --type agent") {
			t.Errorf("stderr = %q, want the --app/--type message", stderr)
		}
		if n := len(f.mintBodies()); n != 0 {
			t.Errorf("mints = %d, want 0", n)
		}
	})
}

func TestGitCredential_ScopesFromEnvAreExplicit(t *testing.T) {
	t.Run("env scopes above the installation fail", func(t *testing.T) {
		f, _ := setupGitCredential(t)
		f.setPerms(map[string]string{"contents": "read"})
		t.Setenv("GHP_GIT_CM_SCOPES", "contents:write")
		stdout, stderr, code := runGitCredential(t, credGet, "get")
		if code != 1 {
			t.Fatalf("code = %d, want 1 (stderr %q)", code, stderr)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want empty", stdout)
		}
	})
	t.Run("default scopes are capped to the installation", func(t *testing.T) {
		f, _ := setupGitCredential(t)
		f.setPerms(map[string]string{"contents": "read"})
		_, stderr, code := runGitCredential(t, credGet, "get")
		if code != 0 {
			t.Fatalf("code = %d, stderr = %q", code, stderr)
		}
		mints := f.mintBodies()
		if len(mints) != 1 || mints[0].Scopes != "contents:read" {
			t.Fatalf("mints = %+v, want one with scopes contents:read", mints)
		}
	})
}

func TestGitCredential_TTLPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		args     []string
		wantCode int
		want     string
	}{
		{name: "env", env: "never", wantCode: 1},
		{name: "flag over env", env: "never", args: []string{"--ttl", "30m"}, want: "30m0s"},
		{name: "default", want: "1h0m0s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, _ := setupGitCredential(t)
			t.Setenv("GHP_GIT_CM_TTL", tt.env)
			_, stderr, code := runGitCredential(t, credGet, append([]string{"get", "--type", "proxy"}, tt.args...)...)
			if code != tt.wantCode {
				t.Fatalf("code = %d, want %d (stderr %q)", code, tt.wantCode, stderr)
			}
			mints := f.mintBodies()
			if tt.wantCode != 0 {
				if !strings.Contains(stderr, "--ttl never is not allowed") || len(mints) != 0 {
					t.Errorf("stderr = %q, mints = %d; want the --ttl never message and no mint", stderr, len(mints))
				}
				return
			}
			if len(mints) != 1 || mints[0].Duration != tt.want {
				t.Fatalf("mints = %+v, want one with duration %q", mints, tt.want)
			}
		})
	}
}

func TestGitCredential_CacheBackendPrecedence(t *testing.T) {
	tests := []struct {
		name      string
		env       string
		args      []string
		wantCache bool
	}{
		{name: "env", env: "none", wantCache: false},
		{name: "flag over env", env: "none", args: []string{"--cache-backend", "file"}, wantCache: true},
		{name: "default", wantCache: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, home := setupGitCredential(t)
			t.Setenv("GHP_GIT_CM_CACHE_BACKEND", tt.env)
			_, stderr, code := runGitCredential(t, credGet, append([]string{"get", "--type", "proxy"}, tt.args...)...)
			if code != 0 {
				t.Fatalf("code = %d, stderr = %q", code, stderr)
			}
			_, err := os.Stat(filepath.Join(home, ".config", "ghp", "git-credential", "cache.enc"))
			if got := err == nil; got != tt.wantCache {
				t.Errorf("cache.enc exists = %v, want %v (stat error %v)", got, tt.wantCache, err)
			}
		})
	}
}

func TestGitCredential_HostFlag(t *testing.T) {
	gheGet := "protocol=https\nhost=ghe.example.com\npath=goodtune/ghp.git\n\n"
	tests := []struct {
		name     string
		stdin    string
		args     []string
		wantCode int
	}{
		{name: "unlisted host", stdin: gheGet, wantCode: 1},
		{name: "listed host", stdin: gheGet, args: []string{"--host", "ghe.example.com"}, wantCode: 0},
		{name: "default replaced", stdin: credGet, args: []string{"--host", "ghe.example.com"}, wantCode: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupGitCredential(t)
			stdout, stderr, code := runGitCredential(t, tt.stdin, append([]string{"get"}, tt.args...)...)
			if code != tt.wantCode {
				t.Fatalf("code = %d, want %d (stderr %q)", code, tt.wantCode, stderr)
			}
			if tt.wantCode != 0 {
				if stdout != "" {
					t.Errorf("stdout = %q, want empty", stdout)
				}
				if !strings.Contains(stderr, "is not configured for this helper") {
					t.Errorf("stderr = %q, want the unconfigured-host message", stderr)
				}
			}
		})
	}
}

func TestGitCredential_ConfigWarningsPrefixed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits are not meaningful on Windows")
	}
	_, home := setupGitCredential(t)
	writeUserConfig(t, home, "{}\n")
	if err := os.Chmod(filepath.Join(home, ".config", "ghp", "config.yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runGitCredential(t, credGet, "get", "--type", "proxy")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	found := false
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, "ghp git-credential: warning: config file") {
			found = true
		}
	}
	if !found {
		t.Errorf("stderr = %q, want a prefixed config-file warning line", stderr)
	}
}

func TestGitCredential_CacheUnderUserConfig(t *testing.T) {
	_, home := setupGitCredential(t)
	_, stderr, code := runGitCredential(t, credGet, "get", "--type", "proxy")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	path := filepath.Join(home, ".config", "ghp", "git-credential", "cache.enc")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("cache file: %v", err)
	}
}

func TestGitCredential_DotvaultLoginRequired(t *testing.T) {
	_, home := setupGitCredential(t)
	t.Setenv("GHP_USER_TOKEN", "")
	writeUserConfig(t, home, dotvaultUserConfig)
	reader := &fakeReader{cachedErr: fmt.Errorf("x: %w", dvclient.ErrLoginRequired)}
	withFakeReader(t, reader, nil)

	stdout, stderr, code := runGitCredential(t, credGet, "get")
	if code != 1 {
		t.Fatalf("code = %d, want 1 (stderr %q)", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	want := "ghp git-credential: dotvault login required: run `ghp auth status` in a terminal to log in\n"
	if stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	if reader.authCalls != 0 {
		t.Errorf("authCalls = %d, want 0 (the helper must never log in interactively)", reader.authCalls)
	}
}

func TestGitCredential_CacheHitSkipsDotvault(t *testing.T) {
	f, home := setupGitCredential(t)
	t.Setenv("GHP_USER_TOKEN", "")
	writeUserConfig(t, home, dotvaultUserConfig)
	reader := &fakeReader{secrets: map[string]string{"ghp/token": "ghpr_vault"}}
	calls := 0
	orig := newDotvaultReader
	t.Cleanup(func() { newDotvaultReader = orig })
	newDotvaultReader = func(string) (dotvaultReader, error) {
		calls++
		return reader, nil
	}

	first, stderr, code := runGitCredential(t, credGet, "get", "--type", "proxy")
	if code != 0 {
		t.Fatalf("first get: code = %d, stderr = %q", code, stderr)
	}
	if calls != 1 {
		t.Fatalf("after first get: factory calls = %d, want 1", calls)
	}
	second, stderr, code := runGitCredential(t, credGet, "get", "--type", "proxy")
	if code != 0 {
		t.Fatalf("second get: code = %d, stderr = %q", code, stderr)
	}
	if calls != 1 {
		t.Errorf("after second get: factory calls = %d, want 1 (cache hit)", calls)
	}
	if p1, p2 := password(t, first), password(t, second); p1 != p2 {
		t.Errorf("passwords differ: %q then %q", p1, p2)
	}
	if n := len(f.mintBodies()); n != 1 {
		t.Errorf("mints = %d, want 1", n)
	}
	if reader.authCalls != 0 {
		t.Errorf("authCalls = %d, want 0", reader.authCalls)
	}
}

func TestGitCredential_UnknownOperation(t *testing.T) {
	setupGitCredential(t)
	stdout, stderr, code := runGitCredential(t, credGet, "frobnicate")
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("code = %d, stdout = %q, stderr = %q; want 0 and no output", code, stdout, stderr)
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"/usr/local/bin/ghp", "/usr/local/bin/ghp"},
		{"ghp", "ghp"},
		{"my-app", "my-app"},
		{"ghe.example.com:8443", "ghe.example.com:8443"},
		{"a@b%c+d=e,f", "a@b%c+d=e,f"},
		{"/opt/my tools/ghp", "'/opt/my tools/ghp'"},
		{`C:\Program Files\ghp.exe`, `'C:\Program Files\ghp.exe'`},
		{"prod;rm -rf ~", "'prod;rm -rf ~'"},
		{"a&b", "'a&b'"},
		{"a`b", "'a`b'"},
		{"a|b", "'a|b'"},
		{`a"b`, `'a"b'`},
		{"a$b", "'a$b'"},
		{"it's", `'it'\''s'`},
		{"", "''"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := shellQuote(tt.in); got != tt.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestGitCredentialHelperLine(t *testing.T) {
	tests := []struct {
		name                string
		ghp, host, app, typ string
		want                string
		wantErr             bool
	}{
		{name: "default host", ghp: "ghp", host: "github.com", typ: "agent", want: "!ghp auth git-credential"},
		{name: "default host any case", ghp: "ghp", host: "GitHub.com", typ: "agent", want: "!ghp auth git-credential"},
		{name: "other host", ghp: "ghp", host: "ghe.example.com", typ: "agent", want: "!ghp auth git-credential --host ghe.example.com"},
		{name: "app with space", ghp: "/usr/bin/ghp", host: "github.com", app: "my app", typ: "agent", want: "!/usr/bin/ghp auth git-credential --app 'my app'"},
		{name: "app with shell metacharacters", ghp: "ghp", host: "github.com", app: "prod;rm -rf ~", typ: "agent", want: "!ghp auth git-credential --app 'prod;rm -rf ~'"},
		{name: "proxy type", ghp: "ghp", host: "github.com", typ: "proxy", want: "!ghp auth git-credential --type proxy"},
		{name: "app newline", ghp: "ghp", host: "github.com", app: "a\nb", typ: "agent", wantErr: true},
		{name: "app carriage return", ghp: "ghp", host: "github.com", app: "a\rb", typ: "agent", wantErr: true},
		{name: "app NUL", ghp: "ghp", host: "github.com", app: "a\x00b", typ: "agent", wantErr: true},
		{name: "ghp path newline", ghp: "/x\n/ghp", host: "github.com", typ: "agent", wantErr: true},
		{name: "host newline", ghp: "ghp", host: "ghe.example.com\nx", typ: "agent", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := gitCredentialHelperLine(tt.ghp, tt.host, tt.app, tt.typ)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("gitCredentialHelperLine = %q, want error", got)
				}
				if !strings.Contains(err.Error(), "contains a newline, carriage return or NUL") {
					t.Errorf("error = %q", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("gitCredentialHelperLine: %v", err)
			}
			if got != tt.want {
				t.Errorf("gitCredentialHelperLine = %q, want %q", got, tt.want)
			}
		})
	}
}

// swapOSExecutable makes ghpCommand see path as the running executable.
func swapOSExecutable(t *testing.T, path string) {
	t.Helper()
	orig := osExecutable
	t.Cleanup(func() { osExecutable = orig })
	osExecutable = func() (string, error) { return path, nil }
}

func TestGhpCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks and executable bits differ on Windows")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "real-ghp")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	onPath := t.TempDir()
	if err := os.Symlink(real, filepath.Join(onPath, "ghp")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link-ghp")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	emptyPath := t.TempDir()

	tests := []struct {
		name, exe, path, want string
	}{
		{name: "ghp on PATH is the running binary", exe: real, path: onPath, want: "ghp"},
		{name: "ghp not on PATH", exe: real, path: emptyPath, want: real},
		{name: "unresolved executable path kept", exe: link, path: emptyPath, want: link},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swapOSExecutable(t, tt.exe)
			t.Setenv("PATH", tt.path)
			got, err := ghpCommand()
			if err != nil {
				t.Fatalf("ghpCommand: %v", err)
			}
			if got != tt.want {
				t.Errorf("ghpCommand = %q, want %q", got, tt.want)
			}
		})
	}
}

// setupGitConfig points git at a temporary global config (seeded with a gh
// helper for github.com), never the real one, and leaves only the real
// git's directory on PATH. It returns the config file path.
func setupGitConfig(t *testing.T) string {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not found on PATH")
	}
	home := t.TempDir()
	cfg := filepath.Join(home, "gitconfig")
	seed := "[credential \"https://github.com\"]\n\thelper = !gh auth git-credential\n"
	if err := os.WriteFile(cfg, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("GIT_CONFIG_GLOBAL", cfg)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("PATH", filepath.Dir(gitPath))
	swapOSExecutable(t, "/opt/my tools/ghp")
	return cfg
}

// gitConfigValues returns every value of key in the global config.
func gitConfigValues(t *testing.T, key string) []string {
	t.Helper()
	out, err := exec.Command("git", "config", "--global", "--get-all", key).Output()
	if err != nil {
		t.Fatalf("git config --get-all %s: %v", key, err)
	}
	return strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
}

// runSetupGit executes `ghp auth setup-git args...` through the root command.
func runSetupGit(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"auth", "setup-git"}, args...))
	err = root.Execute()
	return out.String(), errOut.String(), err
}

// forbidRunGit fails the test if setup-git runs git.
func forbidRunGit(t *testing.T) {
	t.Helper()
	orig := runGit
	t.Cleanup(func() { runGit = orig })
	runGit = func(ctx context.Context, args ...string) error {
		t.Errorf("runGit called with %q", args)
		return nil
	}
}

func assertSetupGitConfig(t *testing.T) {
	t.Helper()
	want := map[string][]string{
		"credential.https://github.com.helper":           {"", "!'/opt/my tools/ghp' auth git-credential --app my-app"},
		"credential.https://ghe.example.com.helper":      {"", "!'/opt/my tools/ghp' auth git-credential --host ghe.example.com --app my-app"},
		"credential.https://github.com.useHttpPath":      {"true"},
		"credential.https://ghe.example.com.useHttpPath": {"true"},
	}
	for key, values := range want {
		if got := gitConfigValues(t, key); !slices.Equal(got, values) {
			t.Errorf("%s = %q, want %q", key, got, values)
		}
	}
}

func TestSetupGit_WritesGlobalConfig(t *testing.T) {
	setupGitConfig(t)
	stdout, stderr, err := runSetupGit(t, "--host", "github.com", "--host", "ghe.example.com", "--app", "my-app")
	if err != nil {
		t.Fatalf("setup-git: %v (stderr %q)", err, stderr)
	}
	assertSetupGitConfig(t)

	wantOut := "Configured https://github.com:\n" +
		"  credential.https://github.com.helper = !'/opt/my tools/ghp' auth git-credential --app my-app\n" +
		"  credential.https://github.com.useHttpPath = true\n" +
		"Configured https://ghe.example.com:\n" +
		"  credential.https://ghe.example.com.helper = !'/opt/my tools/ghp' auth git-credential --host ghe.example.com --app my-app\n" +
		"  credential.https://ghe.example.com.useHttpPath = true\n"
	if stdout != wantOut {
		t.Errorf("stdout = %q, want %q", stdout, wantOut)
	}
	wantErr := "warning: replaced any existing credential helper for github.com, ghe.example.com (for example gh)\n"
	if stderr != wantErr {
		t.Errorf("stderr = %q, want %q", stderr, wantErr)
	}
}

func TestSetupGit_DefaultHostAndProxyType(t *testing.T) {
	setupGitConfig(t)
	if _, stderr, err := runSetupGit(t, "--type", "proxy"); err != nil {
		t.Fatalf("setup-git: %v (stderr %q)", err, stderr)
	}
	want := []string{"", "!'/opt/my tools/ghp' auth git-credential --type proxy"}
	if got := gitConfigValues(t, "credential.https://github.com.helper"); !slices.Equal(got, want) {
		t.Errorf("helper = %q, want %q", got, want)
	}
}

func TestSetupGit_Idempotent(t *testing.T) {
	setupGitConfig(t)
	for i := range 2 {
		if _, stderr, err := runSetupGit(t, "--host", "github.com", "--host", "ghe.example.com", "--app", "my-app"); err != nil {
			t.Fatalf("setup-git run %d: %v (stderr %q)", i+1, err, stderr)
		}
	}
	assertSetupGitConfig(t)
}

func TestSetupGit_AppWithProxyRejected(t *testing.T) {
	forbidRunGit(t)
	swapOSExecutable(t, "/usr/local/bin/ghp")
	_, _, err := runSetupGit(t, "--type", "proxy", "--app", "my-app")
	if err == nil || !strings.Contains(err.Error(), "--app is only valid with --type agent") {
		t.Fatalf("err = %v, want --app is only valid with --type agent", err)
	}
}

func TestSetupGit_RejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		exe  string
		args []string
	}{
		{name: "host with path", args: []string{"--host", "github.com/evil"}},
		{name: "host with space", args: []string{"--host", "a b"}},
		{name: "host with newline", args: []string{"--host", "github.com\nevil"}},
		{name: "bad host after good host", args: []string{"--host", "github.com", "--host", "a b"}},
		{name: "app with newline", args: []string{"--app", "x\ny"}},
		{name: "app with NUL", args: []string{"--app", "x\x00y"}},
		{name: "unknown type", args: []string{"--type", "admin"}},
		{name: "executable path with newline", exe: "/x\n/ghp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forbidRunGit(t)
			exe := tt.exe
			if exe == "" {
				exe = "/usr/local/bin/ghp"
			}
			swapOSExecutable(t, exe)
			t.Setenv("PATH", t.TempDir())
			stdout, _, err := runSetupGit(t, tt.args...)
			if err == nil {
				t.Fatal("setup-git succeeded, want error")
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
		})
	}
}
