package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/scenario"
	"github.com/goodtune/ghp/tools/scoperig/tokens"
)

// ErrPreflight marks instance/session failures (the CLI maps it to exit 3).
var ErrPreflight = errors.New("preflight failed")

// Capabilities records what the instance and fixtures allow. Missing entries
// are not errors: they feed scenario `requires:` and become coverage gaps.
// Keys: repo_w_push, repo_create, github_vhost, agent_installation.
type Capabilities map[string]bool

var versionRe = regexp.MustCompile(`(?i)version\W{0,10}(v?\d+\.\d+[0-9A-Za-z.\-+]*)`)

func newTLSConfig(pool *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// Preflight checks the instance is reachable (GET / answers 2xx or 3xx; the
// live instance redirects 303 to /login) and the session token is accepted
// (GET /api/tokens -> 200). The version is read best-effort from /login and
// is "" when the page does not show one.
func Preflight(ctx context.Context, c *Config, hc *http.Client) (string, error) {
	if err := c.RequireServer(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrPreflight, err)
	}
	noFollow := *hc
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	status, _, _, err := get(ctx, &noFollow, c.ServerURL+"/", nil)
	if err != nil {
		return "", fmt.Errorf("%w: instance unreachable: %v", ErrPreflight, err)
	}
	if status < 200 || status >= 400 {
		return "", fmt.Errorf("%w: instance GET / returned %d", ErrPreflight, status)
	}

	version := ""
	if st, body, _, err := get(ctx, &noFollow, c.ServerURL+"/login", nil); err == nil && st == http.StatusOK {
		if m := versionRe.FindSubmatch(body); m != nil {
			version = string(m[1])
		}
	}

	status, _, _, err = get(ctx, hc, c.ServerURL+"/api/tokens", c.session)
	if err != nil {
		return "", fmt.Errorf("%w: session check: %v", ErrPreflight, err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("%w: GHP_USER_TOKEN rejected: GET /api/tokens returned %d", ErrPreflight, status)
	}
	return version, nil
}

func (c *Config) session(r *http.Request) { r.Header.Set("Authorization", "Bearer "+c.UserToken) }

// ProbeCapabilities uses the open token to learn the login and what the
// fixtures allow. Only an identity failure is an error (fail closed); every
// other probe failure just leaves its capability false.
func ProbeCapabilities(ctx context.Context, c *Config, hc *http.Client, open tokens.Handle, v *scenario.Vars) (Capabilities, error) {
	api := "https://" + c.Instance.Host + "/api/v3"
	caps := Capabilities{"repo_w_push": false, "repo_create": false, "github_vhost": false, "agent_installation": false}

	status, body, _, err := get(ctx, hc, api+"/user", open.Authorize)
	if err != nil {
		return nil, fmt.Errorf("probe login: %w", err)
	}
	var user struct {
		Login string `json:"login"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &user) != nil || user.Login == "" {
		return nil, fmt.Errorf("probe login: GET /api/v3/user returned %d without a login", status)
	}
	v.Login = user.Login

	if c.RepoW != "" {
		if st, b, _, err := get(ctx, hc, api+"/repos/"+c.RepoW, open.Authorize); err == nil && st == http.StatusOK {
			var repo struct {
				Permissions struct {
					Push bool `json:"push"`
				} `json:"permissions"`
			}
			if json.Unmarshal(b, &repo) == nil {
				caps["repo_w_push"] = repo.Permissions.Push
			}
		}
	}

	// repo_create rule: the open token passes the underlying credential's
	// X-OAuth-Scopes through; creating a repository needs the `repo` or
	// `public_repo` scope, and the rig only creates under the probed login,
	// so W's owner must equal that login.
	if _, _, hdr, err := get(ctx, hc, api+"/", open.Authorize); err == nil {
		owner, _, _ := strings.Cut(c.RepoW, "/")
		caps["repo_create"] = hasScope(hdr.Get("X-OAuth-Scopes"), "repo", "public_repo") &&
			strings.EqualFold(owner, v.Login)
	}

	caps["github_vhost"] = probeVHost(ctx, c.Instance.Host, rootCAs(hc))

	if c.InstallationID > 0 && c.ServerURL != "" {
		if st, _, _, err := get(ctx, hc, c.ServerURL+"/api/tokens?all=true", c.session); err == nil && st == http.StatusOK {
			caps["agent_installation"] = true
		}
	}
	return caps, nil
}

// probeVHost dials host (port 443 unless given) with SNI github.com, verifying
// against pool, then sends GET /. Any HTTP response means the instance serves
// the github.com virtual host.
func probeVHost(ctx context.Context, host string, pool *x509.CertPool) bool {
	addr := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		addr = net.JoinHostPort(host, "443")
	}
	cfg := newTLSConfig(pool)
	cfg.ServerName = "github.com"
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: cfg}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	tr := &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil }}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://github.com/", nil)
	if err != nil {
		return false
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func rootCAs(hc *http.Client) *x509.CertPool {
	if tr, ok := hc.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil {
		return tr.TLSClientConfig.RootCAs
	}
	return nil
}

func hasScope(header string, want ...string) bool {
	for _, s := range strings.Split(header, ",") {
		s = strings.TrimSpace(s)
		for _, w := range want {
			if s == w {
				return true
			}
		}
	}
	return false
}

func get(ctx context.Context, hc *http.Client, u string, auth func(*http.Request)) (int, []byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if auth != nil {
		auth(req)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, body, resp.Header, nil
}
