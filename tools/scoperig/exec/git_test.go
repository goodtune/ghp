package exec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

// githubCert returns a CA PEM file and a TLS certificate for github.com
// signed by it, so git can verify the fake vhost through GIT_SSL_CAINFO.
func githubCert(t *testing.T) (caFile string, cert tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "scoperig test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "github.com"},
		DNSNames: []string{"github.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return caFile, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key}
}

func mustGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := osexec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir, "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}

// fakeGitVhost serves git smart HTTP for bare repositories under root
// through `git http-backend`, as the instance's github.com vhost would:
// a Basic credential whose password is the token, 403 for a repository
// outside the token's allowlist, and 403 for a push without write.
type fakeGitVhost struct {
	t     *testing.T
	root  string
	token string
	mu    sync.Mutex
	allow map[string]string // "owner/name" -> "read" | "write"
	hosts []string
}

func (f *fakeGitVhost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hosts = append(f.hosts, r.Host)
	f.mu.Unlock()
	_, pass, ok := r.BasicAuth()
	if !ok || pass != f.token {
		w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
		http.Error(w, "bad credentials", http.StatusUnauthorized)
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 3)
	if len(parts) < 3 || !strings.HasSuffix(parts[1], ".git") {
		http.NotFound(w, r)
		return
	}
	repo := parts[0] + "/" + strings.TrimSuffix(parts[1], ".git")
	f.mu.Lock()
	lvl := f.allow[repo]
	f.mu.Unlock()
	push := r.URL.Query().Get("service") == "git-receive-pack" || strings.HasSuffix(r.URL.Path, "/git-receive-pack")
	if lvl == "" || (push && lvl != "write") {
		http.Error(w, `{"message":"Token is not scoped to `+repo+`"}`, http.StatusForbidden)
		return
	}
	h := &cgi.Handler{Path: gitPath(f.t), Args: []string{"http-backend"},
		Env: []string{"GIT_PROJECT_ROOT=" + f.root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1", "REMOTE_USER=x-access-token"}}
	h.ServeHTTP(w, r)
}

func gitPath(t *testing.T) string {
	p, err := osexec.LookPath("git")
	if err != nil {
		t.Skip("git not on PATH")
	}
	return p
}

// newGitFixture builds bare repositories for A, B and W (PlaceholderVars
// names) and a TLS server with a github.com certificate.
func newGitFixture(t *testing.T) (*RunEnv, *fakeGitVhost, string) {
	t.Helper()
	gitPath(t)
	root := t.TempDir()
	seed := t.TempDir()
	mustGit(t, seed, "init", "-q", "-b", "main", ".")
	mustGit(t, seed, "commit", "-q", "--allow-empty", "-m", "seed")
	v := scenario.PlaceholderVars()
	for _, r := range []scenario.RepoRef{v.RepoA, v.RepoB, v.RepoW} {
		dst := filepath.Join(root, r.Owner, r.Name+".git")
		mustGit(t, seed, "clone", "-q", "--bare", seed, dst)
		mustGit(t, dst, "config", "http.receivepack", "true")
	}
	env, _, _ := newEnv(t, nil)
	caFile, cert := githubCert(t)
	f := &fakeGitVhost{t: t, root: root, token: "ghx_test0000fakevalue", allow: map[string]string{}}
	ts := httptest.NewUnstartedServer(f)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	env.APIBase = "https://" + ts.Listener.Addr().String() + "/api/v3"
	env.CAFile = caFile
	return env, f, root
}

func TestGit_CloneAndPush(t *testing.T) {
	env, f, root := newGitFixture(t)
	v := env.Vars
	clone := func(repo string) *scenario.Scenario {
		return &scenario.Scenario{ID: "GIT-C48.x", Kind: "git", GitOp: "clone", Repo: repo}
	}
	push := &scenario.Scenario{ID: "GIT-C48.push", Kind: "git", GitOp: "push", Repo: "W", Branch: "scoperig-{{.RunID}}-push"}

	tests := []struct {
		name       string
		allow      map[string]string
		s          *scenario.Scenario
		wantExit0  bool
		wantStatus int
	}{
		{"clone A with read", map[string]string{v.RepoA.String(): "read"}, clone("A"), true, 0},
		{"clone B with an A token", map[string]string{v.RepoA.String(): "read"}, clone("B"), false, 403},
		{"push W with read", map[string]string{v.RepoW.String(): "read"}, push, false, 403},
		{"push W with write", map[string]string{v.RepoW.String(): "write"}, push, true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f.mu.Lock()
			f.allow, f.hosts = tt.allow, nil
			f.mu.Unlock()
			obs, err := Git{}.Run(context.Background(), tt.s, env.Open, env)
			if err != nil {
				t.Fatal(err)
			}
			if (*obs.GHExit == 0) != tt.wantExit0 || obs.Status != tt.wantStatus {
				t.Fatalf("exit %d status %d, want exit0=%v status %d; stderr %s", *obs.GHExit, obs.Status, tt.wantExit0, tt.wantStatus, obs.Stderr)
			}
			if strings.Contains(obs.Stderr, "fakevalue") || strings.Contains(obs.Stdout, "fakevalue") {
				t.Errorf("token in output: %s %s", obs.Stdout, obs.Stderr)
			}
			f.mu.Lock()
			for _, h := range f.hosts {
				if !strings.HasPrefix(h, "github.com") {
					t.Errorf("Host = %q, want github.com", h)
				}
			}
			f.mu.Unlock()
		})
	}
	refs := mustGit(t, filepath.Join(root, v.RepoW.Owner, v.RepoW.Name+".git"), "for-each-ref", "--format=%(refname)")
	if !strings.Contains(refs, "refs/heads/scoperig-"+v.RunID+"-push") {
		t.Errorf("pushed branch missing from W: %s", refs)
	}
	for _, r := range []scenario.RepoRef{v.RepoA, v.RepoB} {
		refs := mustGit(t, filepath.Join(root, r.Owner, r.Name+".git"), "for-each-ref", "--format=%(refname)")
		if strings.TrimSpace(refs) != "refs/heads/main" {
			t.Errorf("%s changed: %s", r, refs)
		}
	}
}

func TestGit_PushOnlyToW(t *testing.T) {
	env, _, _ := newGitFixture(t)
	s := &scenario.Scenario{ID: "X", Kind: "git", GitOp: "push", Repo: "A", Branch: "b-{{.RunID}}"}
	if _, err := (Git{}).Run(context.Background(), s, env.Open, env); err == nil || !strings.Contains(err.Error(), "only to W") {
		t.Fatalf("err = %v", err)
	}
}

func TestGitTarget(t *testing.T) {
	old := lookupHost
	t.Cleanup(func() { lookupHost = old })
	lookupHost = func(context.Context, string) ([]string, error) { return []string{"2001:db8::1"}, nil }
	tests := []struct{ base, wantURL, wantResolve string }{
		{"https://ghp.example/api/v3", "https://github.com/o/r.git", "github.com:443:[2001:db8::1]"},
		{"https://10.0.0.5:8443/api/v3", "https://github.com:8443/o/r.git", "github.com:8443:10.0.0.5"},
	}
	for _, tt := range tests {
		u, r, err := gitTarget(context.Background(), tt.base, "o", "r")
		if err != nil || u != tt.wantURL || r != tt.wantResolve {
			t.Errorf("gitTarget(%s) = %q, %q, %v", tt.base, u, r, err)
		}
	}
	if _, _, err := gitTarget(context.Background(), "http://h/api/v3", "o", "r"); err == nil {
		t.Error("http base: want error")
	}
}

// TestGit_RigScenarios runs the checked-in GIT-C48 scenarios against the
// fake vhost, with each profile's allowlist and level, and checks every
// expectation holds.
func TestGit_RigScenarios(t *testing.T) {
	env, f, _ := newGitFixture(t)
	tree, err := scenario.Load("../../../rig")
	if err != nil {
		t.Fatal(err)
	}
	v := env.Vars
	n := 0
	for _, s := range tree.Scenarios {
		if s.Kind != "git" {
			continue
		}
		n++
		t.Run(s.ID, func(t *testing.T) {
			p := tree.Profiles[s.Profile]
			lvl := "read"
			if strings.Contains(p.Scopes, "contents:write") || p.Scopes == "" {
				lvl = "write"
			}
			allow := map[string]string{}
			for _, r := range p.Repositories {
				e, err := scenario.Expand(r, v)
				if err != nil {
					t.Fatal(err)
				}
				allow[e] = lvl
			}
			f.mu.Lock()
			f.allow = allow
			f.mu.Unlock()
			obs, err := Git{}.Run(context.Background(), s, env.Open, env)
			if err != nil {
				t.Fatal(err)
			}
			if errs := expect.Match(s.Expect, obs); len(errs) > 0 {
				t.Errorf("%v; stderr %s", errs, obs.Stderr)
			}
		})
	}
	if n != 4 {
		t.Errorf("git scenarios = %d, want 4", n)
	}
}
