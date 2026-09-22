# raw.githubusercontent.com Proxy Handler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `raw.githubusercontent.com` backend handler that enforces `contents:read` scope for GHP-issued tokens and passes through query-token and anonymous requests for observability.

**Architecture:** A new host-dispatch case routes `raw.githubusercontent.com` to `internal/proxy/raw.go`. The handler parses `owner`/`repo` from the first two path segments, then classifies each request into one of three paths — GHP-token (resolve, enforce, swap credential), GitHub query-token (policy-gated passthrough), or anonymous (passthrough). All three are logged and counted; only the first is enforced.

**Tech Stack:** Go 1.24, `httputil.ReverseProxy`, koanf config, Prometheus `promauto`, OpenTelemetry structured access logs.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-26-raw-githubusercontent-proxy-design.md`. Read it before starting.
- Guiding principle: **GHP is an enforcement point for tokens it issued and a telemetry point for everything else.**
- Go formatting via `gofmt`. Table-driven tests using `t.Run()`. Explicit `if err != nil`.
- Prometheus label values for `owner`/`repo` MUST be lowercased (GitHub is case-insensitive; mixed casing splits time series).
- Every new metric requires a test in `internal/metrics/metrics_test.go`.
- Run `make check` (tests + `go vet`) before each commit.
- Branch: `feat/raw-githubusercontent-proxy` (already created, spec already committed).

---

### Task 1: Redact sensitive query parameters in access logs

Currently `accesslog.go:126` emits `r.URL.RawQuery` verbatim. Once raw passthrough lands, this would write live GitHub blob capabilities (valid ~7 days) into the access log. This is a general fix benefiting every backend, so it ships first and independently.

**Files:**
- Modify: `internal/server/accesslog.go` (add `redactQueryParam` + `redactedQuery`; change line 126)
- Test: `internal/server/accesslog_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `func redactedQuery(rawQuery string) string` — returns the query string with sensitive parameter values replaced by `REDACTED`, preserving parameter order and non-sensitive values. `func redactQueryParam(name string) bool`.

- [ ] **Step 1: Write the failing test**

Add to `internal/server/accesslog_test.go`:

```go
func TestRedactedQuery(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no sensitive params", "ref=main&path=README.md", "ref=main&path=README.md"},
		{"github blob token", "token=AACGATXPAI3FK7WLHZDREQLKMR6GLAA", "token=REDACTED"},
		{"access_token", "access_token=abc123", "access_token=REDACTED"},
		{"client_secret", "client_secret=shhh", "client_secret=REDACTED"},
		{"mixed", "ref=main&token=abc&page=2", "ref=main&token=REDACTED&page=2"},
		{"case insensitive name", "TOKEN=abc", "TOKEN=REDACTED"},
		{"repeated param", "token=a&token=b", "token=REDACTED&token=REDACTED"},
		{"valueless param", "token", "token=REDACTED"},
		{"unparseable is redacted wholesale", "%zz&token=abc", "REDACTED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redactedQuery(tt.in); got != tt.want {
				t.Errorf("redactedQuery(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
```

Note the `unparseable` case: if `url.ParseQuery` errors we must NOT fall back to emitting the raw string, because a malformed query could still contain a token. Fail closed.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/ -run TestRedactedQuery -v`
Expected: FAIL — `undefined: redactedQuery`

- [ ] **Step 3: Write the implementation**

In `internal/server/accesslog.go`, add below `redactResponseHeader`:

```go
// redactQueryParam reports whether a URL query parameter's value must be
// redacted from access logs. GitHub's contents API returns download_url
// values carrying a ?token= blob capability that remains valid for days —
// logging it verbatim would persist a usable credential in the log stream.
func redactQueryParam(name string) bool {
	switch strings.ToLower(name) {
	case "token", "access_token", "client_secret":
		return true
	default:
		return false
	}
}

// redactedQuery returns rawQuery with the values of sensitive parameters
// replaced by the same placeholder used for headers. Parameter order is
// preserved so the logged value stays comparable to the request.
//
// If rawQuery cannot be parsed, the entire query is redacted rather than
// emitted verbatim: a malformed query may still carry a credential, and
// failing closed is cheaper than leaking one.
func redactedQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	if _, err := url.ParseQuery(rawQuery); err != nil {
		return "REDACTED"
	}
	parts := strings.Split(rawQuery, "&")
	for i, part := range parts {
		name, _, _ := strings.Cut(part, "=")
		decoded, err := url.QueryUnescape(name)
		if err != nil {
			decoded = name
		}
		if redactQueryParam(decoded) {
			parts[i] = name + "=REDACTED"
		}
	}
	return strings.Join(parts, "&")
}
```

Add `"net/url"` to the imports if not already present.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/server/ -run TestRedactedQuery -v`
Expected: PASS

- [ ] **Step 5: Wire it into the access log emission**

In `internal/server/accesslog.go`, replace lines 125-127:

```go
		if q := r.URL.RawQuery; q != "" {
			attrs = append(attrs, otellog.String(attrURLQuery, q))
		}
```

with:

```go
		if q := r.URL.RawQuery; q != "" {
			attrs = append(attrs, otellog.String(attrURLQuery, redactedQuery(q)))
		}
```

- [ ] **Step 6: Write the integration test**

Add to `internal/server/accesslog_test.go`:

```go
func TestAccessLogHandler_RedactsQueryToken(t *testing.T) {
	rec, aw := newTestAccessLogRecorder(t)
	h := accessLogHandler(backend.Codeload, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), aw)

	req := httptest.NewRequest(http.MethodGet, "/o/r/main/README.md?token=SECRETVALUE123", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	got := rec.str(t, attrURLQuery)
	if strings.Contains(got, "SECRETVALUE123") {
		t.Errorf("%s = %q, must not contain the token value", attrURLQuery, got)
	}
	if got != "token=REDACTED" {
		t.Errorf("%s = %q, want %q", attrURLQuery, got, "token=REDACTED")
	}
}
```

Reuse whatever recorder helper the existing tests in this file use (see `TestAccessLogHandler_*` around `accesslog_test.go:81` for the established pattern and the `rec.str(t, attr)` accessor); if the helper is named differently, match the existing name rather than introducing `newTestAccessLogRecorder`.

- [ ] **Step 7: Run the full server test suite**

Run: `go test ./internal/server/ -v -run TestAccessLog`
Expected: PASS, including pre-existing access log tests.

- [ ] **Step 8: Commit**

```bash
git add internal/server/accesslog.go internal/server/accesslog_test.go
git commit -m "fix(accesslog): redact sensitive query parameters

Query strings were logged verbatim while headers were redacted. GitHub
contents download_url values carry a ?token= blob capability valid for
days; logging it persisted a usable credential in the log stream.

Fails closed on unparseable queries."
```

---

### Task 2: Add the `raw.allow_query_token` config field

**Files:**
- Modify: `internal/config/config.go` (add `RawConfig`, field on `Config`, `ReloadFrom` entry, accessor)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `type RawConfig struct { AllowQueryToken bool \`koanf:"allow_query_token"\` }`, field `Raw RawConfig \`koanf:"raw"\`` on `Config`, and method `func (c *Config) RawAllowQueryToken() bool` (read-lock protected, safe against concurrent `ReloadFrom`).

**Important:** the default is `true`. A bare `bool` zero-values to `false`, so it must be set explicitly in `Defaults()` (`config.go:291`), which `Load` uses as the base struct before koanf unmarshals the YAML and env overrides on top. `Metrics.Enabled: true` is the existing precedent for a bool defaulting to true. `ReloadFrom` calls `Load`, so a reload also picks the default back up when the field is absent — do not rely on the zero value anywhere.

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go`:

```go
func TestRawAllowQueryToken(t *testing.T) {
	t.Run("defaults to true", func(t *testing.T) {
		cfg, err := Load("")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !cfg.RawAllowQueryToken() {
			t.Error("RawAllowQueryToken() = false, want true by default")
		}
	})

	t.Run("honours explicit false", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cfg.yaml")
		if err := os.WriteFile(path, []byte("raw:\n  allow_query_token: false\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.RawAllowQueryToken() {
			t.Error("RawAllowQueryToken() = true, want false")
		}
	})

	t.Run("hot reload picks up change", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cfg.yaml")
		if err := os.WriteFile(path, []byte("raw:\n  allow_query_token: true\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !cfg.RawAllowQueryToken() {
			t.Fatal("precondition: want true before reload")
		}
		if err := os.WriteFile(path, []byte("raw:\n  allow_query_token: false\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := cfg.ReloadFrom(path); err != nil {
			t.Fatalf("ReloadFrom: %v", err)
		}
		if cfg.RawAllowQueryToken() {
			t.Error("RawAllowQueryToken() = true after reload, want false")
		}
	})
}
```

Match the existing `Load` signature in this package — if it takes different arguments (e.g. a flag set or an options struct), adapt these calls to the established pattern used by the neighbouring config tests rather than changing `Load`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestRawAllowQueryToken -v`
Expected: FAIL — `cfg.RawAllowQueryToken undefined`

- [ ] **Step 3: Add the config struct and field**

In `internal/config/config.go`, add after `CodeloadConfig`:

```go
// RawConfig controls how raw.githubusercontent.com requests are handled.
//
// raw.githubusercontent.com accepts GitHub credentials via the Authorization
// header, and is explicitly exempt from the sec-GitHub-allowed-enterprise
// corporate proxy restriction (GitHub scopes that header to github.com,
// api.github.com and *.githubcopilot.com only). It also returns no
// X-RateLimit-* headers, so the traffic is invisible to both enterprise
// network policy and GHP's rate limit telemetry unless proxied.
type RawConfig struct {
	// AllowQueryToken controls whether requests carrying a GitHub-issued
	// ?token= query parameter (as returned in the contents API download_url)
	// are forwarded when no GHP token is present.
	//
	// Such tokens are opaque to GHP: they cannot be attributed to an agent,
	// scope-checked, or revoked, and remain valid for days. When true
	// (the default) they are forwarded and logged, trading attribution for
	// compatibility and visibility. When false they are rejected with 403.
	AllowQueryToken bool `koanf:"allow_query_token"`
}
```

Add to the `Config` struct next to `Codeload`:

```go
	Raw RawConfig `koanf:"raw"`
```

- [ ] **Step 4: Set the default and wire hot reload**

In `Defaults()` (`config.go:291`), add to the returned struct literal:

```go
		Raw: RawConfig{
			AllowQueryToken: true,
		},
```

In `ReloadFrom` (`config.go:466` area), add to the in-place mutation set, after `c.Codeload = fresh.Codeload`:

```go
	c.Raw = fresh.Raw
```

Also add `RawAllowQueryToken` to the accessor list in the `ReloadFrom` doc comment (`config.go:444`), which enumerates the accessors whose reads are serialised against reload.

- [ ] **Step 5: Add the accessor**

Add near `CodeloadRedirectTo` (`config.go:568`):

```go
// RawAllowQueryToken reports whether raw.githubusercontent.com requests
// carrying a GitHub-issued ?token= query parameter are forwarded when no GHP
// token is present. It takes the read lock so callers on the request hot path
// can read it without racing against ReloadFrom.
func (c *Config) RawAllowQueryToken() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Raw.AllowQueryToken
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/config/ -run TestRawAllowQueryToken -v`
Expected: PASS (all three subtests)

- [ ] **Step 7: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add raw.allow_query_token

Gates whether raw.githubusercontent.com requests carrying a
GitHub-issued ?token= are forwarded when no GHP token is present.
Defaults to true. Hot-reloadable via SIGUSR1."
```

---

### Task 3: Add the `ghp_raw_request_total` metric

**Files:**
- Modify: `internal/metrics/metrics.go`
- Test: `internal/metrics/metrics_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `metrics.RawRequestTotal` — a `*prometheus.CounterVec` with labels `owner`, `repo`, `result`. Valid `result` values: `authenticated`, `query_token`, `anonymous`, `denied_scope`, `denied_policy`, `denied_method`.

- [ ] **Step 1: Write the failing test**

Add to `internal/metrics/metrics_test.go`, following the existing counter test pattern in that file:

```go
func TestRawRequestTotal(t *testing.T) {
	results := []string{
		"authenticated", "query_token", "anonymous",
		"denied_scope", "denied_policy", "denied_method",
	}
	for _, result := range results {
		t.Run(result, func(t *testing.T) {
			owner, repo := "testowner", "testrepo-"+result
			before := testutil.ToFloat64(RawRequestTotal.WithLabelValues(owner, repo, result))
			RawRequestTotal.WithLabelValues(owner, repo, result).Inc()
			after := testutil.ToFloat64(RawRequestTotal.WithLabelValues(owner, repo, result))
			if after != before+1 {
				t.Errorf("RawRequestTotal[%s] = %v, want %v", result, after, before+1)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/metrics/ -run TestRawRequestTotal -v`
Expected: FAIL — `undefined: RawRequestTotal`

- [ ] **Step 3: Add the counter**

In `internal/metrics/metrics.go`, add after `CodeloadRedirectTotal`:

```go
	// RawRequestTotal counts raw.githubusercontent.com requests handled,
	// labeled by owner, repo, and result:
	//   "authenticated" — GHP token present; scope enforced; forwarded with
	//                     the resolved GitHub credential
	//   "query_token"   — GitHub-issued ?token= present, no GHP token;
	//                     forwarded unmodified and unattributed
	//   "anonymous"     — no credential; forwarded unmodified
	//   "denied_scope"  — GHP token not scoped to the requested repository,
	//                     or lacking contents:read
	//   "denied_policy" — query token rejected by raw.allow_query_token=false
	//   "denied_method" — method other than GET or HEAD
	//
	// The ref and file path are not included as labels to keep cardinality
	// bounded; they are captured in access logs as part of the URL.
	// Cardinality: bounded by (repos seen × results).
	RawRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_raw_request_total",
		Help: "Total raw.githubusercontent.com requests handled, by owner, repo, and result.",
	}, []string{"owner", "repo", "result"})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/metrics/ -run TestRawRequestTotal -v`
Expected: PASS (all six subtests)

- [ ] **Step 5: Commit**

```bash
git add internal/metrics/metrics.go internal/metrics/metrics_test.go
git commit -m "feat(metrics): add ghp_raw_request_total

Counts raw.githubusercontent.com requests by owner, repo, and
classification result."
```

---

### Task 4: Add the raw auth attribution access-log slot

**Files:**
- Modify: `internal/proxy/context.go` (new context key, slot, setter)
- Modify: `internal/server/semconv.go` (new attribute const)
- Modify: `internal/server/accesslog.go` (emit the attribute)
- Test: `internal/proxy/context_test.go`, `internal/server/accesslog_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `proxy.SetRawAuth(r *http.Request, v string)` — stores the classification in the request's context slot, no-op when no slot was prepared. `AccessLogSlots.RawAuth *string`. Attribute name `ghp.raw.auth`.

- [ ] **Step 1: Write the failing test**

Add to `internal/proxy/context_test.go`:

```go
func TestRawAuthSlot(t *testing.T) {
	t.Run("round trips through the slot", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/o/r/main/f.txt", nil)
		req, slots := PrepareAccessLogSlots(req)
		SetRawAuth(req, "query_token")
		if *slots.RawAuth != "query_token" {
			t.Errorf("RawAuth = %q, want %q", *slots.RawAuth, "query_token")
		}
	})

	t.Run("no-op without a prepared slot", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/o/r/main/f.txt", nil)
		SetRawAuth(req, "anonymous") // must not panic
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestRawAuthSlot -v`
Expected: FAIL — `undefined: SetRawAuth`

- [ ] **Step 3: Add the slot**

In `internal/proxy/context.go`:

Add the key alongside the others:

```go
var rawAuthCtxKey = &contextKey{"raw-auth"}
```

Add the field to `AccessLogSlots`:

```go
	RawAuth *string // "proxy_token", "query_token", "anonymous", or "" for non-raw backends
```

In `PrepareAccessLogSlots`, allocate and thread it through exactly as `cacheRepoSlot` is:

```go
	rawAuthSlot := new(string)
	// ... ctx = context.WithValue(ctx, rawAuthCtxKey, rawAuthSlot)
	// ... RawAuth: rawAuthSlot,
```

Add the setter next to `SetUsername`:

```go
// SetRawAuth records how a raw.githubusercontent.com request authenticated,
// so the access-log middleware can partition attributable traffic from
// traffic GHP only observed. It is a no-op if no slot was prepared.
func SetRawAuth(r *http.Request, v string) {
	if slot, ok := r.Context().Value(rawAuthCtxKey).(*string); ok && slot != nil {
		*slot = v
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/ -run TestRawAuthSlot -v`
Expected: PASS

- [ ] **Step 5: Emit the attribute**

In `internal/server/semconv.go`, add next to `attrGHPCacheRepo`:

```go
	attrGHPRawAuth = "ghp.raw.auth"
```

In `internal/server/accesslog.go`, after the `slots.CacheRepo` block (line ~138):

```go
		if *slots.RawAuth != "" {
			attrs = append(attrs, otellog.String(attrGHPRawAuth, *slots.RawAuth))
		}
```

- [ ] **Step 6: Verify the whole package still builds and passes**

Run: `make check`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/proxy/context.go internal/proxy/context_test.go internal/server/semconv.go internal/server/accesslog.go
git commit -m "feat(accesslog): add ghp.raw.auth attribution slot

Records whether a raw request authenticated via a GHP token, a
GitHub-issued query token, or not at all, so log queries can separate
attributable traffic from traffic GHP only observed."
```

---

### Task 5: Raw handler — routing, path parsing, classification, and scope enforcement

Builds the complete handler: path parsing, all three classification paths, and `contents:read` enforcement on the GHP-token path.

**Files:**
- Modify: `internal/backend/backend.go` (add `Raw` const)
- Create: `internal/proxy/raw.go`
- Test: `internal/proxy/raw_test.go`

**Interfaces:**
- Consumes: `config.RawAllowQueryToken()` (Task 2), `metrics.RawRequestTotal` (Task 3), `proxy.SetRawAuth` (Task 4). Existing in `internal/proxy`: `ScopeEnforcer.Resolve`, `TokenResolver.ResolveToGitHubToken`, `extractClientToken`, `parseScopeInfo`, `si.isOpenScoped()`, `si.repoAllowed(repo)`, `si.Scopes.HasPermission(permission, level)`, `writeError`, `SetUserID`, `SetUsername`.
- Produces: `backend.Raw = "raw.githubusercontent.com"`. `func NewRawHandler(cfg *config.Config, enforcer ScopeEnforcer, resolver TokenResolver, ur *UsernameResolver, logger *slog.Logger, transport http.RoundTripper) http.Handler`. `func parseRawPath(p string) (owner, repo string, ok bool)` — lowercases owner and repo; returns `ok=false` when fewer than three non-empty segments.

The permission enforced is `contents:read`, matching `GET /repos/{owner}/{repo}/contents/…` at `internal/proxy/scope.go:29`. Follow the flow in `NewScopedPassthroughHandler` (`passthrough.go:210-300`) — same ordering, same decision stages.

- [ ] **Step 1: Write the failing path-parsing test**

Create `internal/proxy/raw_test.go`:

```go
package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/config"
)

func TestParseRawPath(t *testing.T) {
	tests := []struct {
		name              string
		path              string
		wantOwner         string
		wantRepo          string
		wantOK            bool
	}{
		{"classic ref form", "/goodtune/ghp/main/README.md", "goodtune", "ghp", true},
		{"explicit refs form", "/goodtune/ghp/refs/heads/main/README.md", "goodtune", "ghp", true},
		{"ref containing slashes", "/goodtune/ghp/feature/x/y/file.txt", "goodtune", "ghp", true},
		{"nested file path", "/goodtune/ghp/main/a/b/c/d.yaml", "goodtune", "ghp", true},
		{"casing normalised", "/GoodTune/GHP/main/README.md", "goodtune", "ghp", true},
		{"leading double slash", "//goodtune/ghp/main/README.md", "goodtune", "ghp", true},
		{"owner and repo only", "/goodtune/ghp", "", "", false},
		{"owner only", "/goodtune", "", "", false},
		{"root", "/", "", "", false},
		{"empty", "", "", "", false},
		{"trailing slash no file", "/goodtune/ghp/", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, ok := parseRawPath(tt.path)
			if ok != tt.wantOK || owner != tt.wantOwner || repo != tt.wantRepo {
				t.Errorf("parseRawPath(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.path, owner, repo, ok, tt.wantOwner, tt.wantRepo, tt.wantOK)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestParseRawPath -v`
Expected: FAIL — `undefined: parseRawPath`

- [ ] **Step 3: Add the backend const**

In `internal/backend/backend.go`, add after `Codeload`:

```go
	// Raw handles requests to raw.githubusercontent.com — direct file content
	// downloads at /{owner}/{repo}/{ref}/{path}. Requests bearing a GHP-issued
	// token are scope-enforced and forwarded with the resolved credential.
	// Requests bearing a GitHub-issued ?token= query parameter, and anonymous
	// requests, are forwarded unmodified — GHP observes and logs them but
	// cannot attribute or enforce them. This host is exempt from the
	// sec-GitHub-allowed-enterprise corporate proxy restriction, which is why
	// proxying it is worthwhile in the first place.
	Raw = "raw.githubusercontent.com"
```

- [ ] **Step 4: Create the handler with path parsing**

Create `internal/proxy/raw.go`:

```go
package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/metrics"
)

// rawPathRe matches raw.githubusercontent.com content paths and captures the
// owner and repository. The remainder is deliberately left unparsed: refs may
// contain slashes, and both /{owner}/{repo}/{ref}/{path} and the newer
// /{owner}/{repo}/refs/heads/{branch}/{path} form must yield the same
// owner/repo. Only the first two segments participate in enforcement.
var rawPathRe = regexp.MustCompile(`^/+([^/]+)/([^/]+)/(.+)$`)

// upstreamRaw is the canonical upstream URL used as the passthrough target.
var upstreamRaw = mustParseRawURL("https://raw.githubusercontent.com")

func mustParseRawURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// parseRawPath extracts the owner and repository from a raw content path.
// Owner and repo are lowercased: GitHub treats them case-insensitively, so
// leaving the client's casing intact would split Prometheus time series.
func parseRawPath(p string) (owner, repo string, ok bool) {
	m := rawPathRe.FindStringSubmatch(p)
	if m == nil {
		return "", "", false
	}
	return strings.ToLower(m[1]), strings.ToLower(m[2]), true
}

// newRawPassthrough builds a transparent reverse proxy to upstream
// raw.githubusercontent.com, preserving the client's Host header so tests and
// access logs see the value that was sent.
func newRawPassthrough(transport http.RoundTripper) http.Handler {
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			originalHost := req.Host
			req.URL.Scheme = upstreamRaw.Scheme
			req.URL.Host = upstreamRaw.Host
			req.Host = originalHost
		},
	}
	if transport != nil {
		rp.Transport = transport
	}
	return rp
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/proxy/ -run TestParseRawPath -v`
Expected: PASS

- [ ] **Step 6: Write the failing classification test**

Add to `internal/proxy/raw_test.go`:

```go
func TestRawHandler_UnattributedPaths(t *testing.T) {
	tests := []struct {
		name            string
		method          string
		target          string
		allowQueryToken bool
		wantStatus      int
		wantForwarded   bool
		wantQueryOnUpstream string
	}{
		{
			name: "anonymous request is forwarded",
			method: http.MethodGet, target: "/goodtune/ghp/main/README.md",
			allowQueryToken: true, wantStatus: http.StatusOK, wantForwarded: true,
		},
		{
			name: "query token forwarded unmodified when allowed",
			method: http.MethodGet, target: "/goodtune/ghp/main/README.md?token=ABC123",
			allowQueryToken: true, wantStatus: http.StatusOK, wantForwarded: true,
			wantQueryOnUpstream: "token=ABC123",
		},
		{
			name: "query token rejected when policy disallows",
			method: http.MethodGet, target: "/goodtune/ghp/main/README.md?token=ABC123",
			allowQueryToken: false, wantStatus: http.StatusForbidden, wantForwarded: false,
		},
		{
			name: "HEAD is allowed",
			method: http.MethodHead, target: "/goodtune/ghp/main/README.md",
			allowQueryToken: true, wantStatus: http.StatusOK, wantForwarded: true,
		},
		{
			name: "POST is rejected",
			method: http.MethodPost, target: "/goodtune/ghp/main/README.md",
			allowQueryToken: true, wantStatus: http.StatusForbidden, wantForwarded: false,
		},
		{
			name: "non-matching path is forwarded uncounted",
			method: http.MethodGet, target: "/goodtune/ghp",
			allowQueryToken: true, wantStatus: http.StatusOK, wantForwarded: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var forwarded bool
			var upstreamQuery string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				upstreamQuery = r.URL.RawQuery
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			cfg := &config.Config{}
			cfg.Raw.AllowQueryToken = tt.allowQueryToken

			h := NewRawHandler(cfg, nil, nil, nil, nil, rewriteTransport(t, upstream.URL))

			req := httptest.NewRequest(tt.method, tt.target, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if forwarded != tt.wantForwarded {
				t.Errorf("forwarded = %v, want %v", forwarded, tt.wantForwarded)
			}
			if tt.wantQueryOnUpstream != "" && upstreamQuery != tt.wantQueryOnUpstream {
				t.Errorf("upstream query = %q, want %q", upstreamQuery, tt.wantQueryOnUpstream)
			}
		})
	}
}
```

`rewriteTransport` is a helper that redirects the reverse proxy to the test server. Check `codeload_test.go` first — it already passes a `transport` for exactly this purpose. Reuse that helper if one exists; otherwise add:

```go
// rewriteTransport returns a RoundTripper that redirects every request to the
// given test server, so the reverse proxy under test never makes a real
// network call.
func rewriteTransport(t *testing.T, target string) http.RoundTripper {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	return &rewriteRoundTripper{host: u.Host, scheme: u.Scheme}
}

type rewriteRoundTripper struct{ host, scheme string }

func (rt *rewriteRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = rt.scheme
	req.URL.Host = rt.host
	return http.DefaultTransport.RoundTrip(req)
}
```

- [ ] **Step 7: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestRawHandler_UnattributedPaths -v`
Expected: FAIL — `undefined: NewRawHandler`

- [ ] **Step 8: Implement the handler**

Append to `internal/proxy/raw.go`:

```go
// NewRawHandler returns an http.Handler for raw.githubusercontent.com requests.
//
// Requests are classified into three paths, evaluated in order:
//
//   - A GHP-issued token (ghx_/gha_) in the Authorization header: the token is
//     resolved, contents:read is enforced against the repository allowlist, any
//     GitHub-issued ?token= is stripped, and the request is forwarded with the
//     real credential. This is the only enforced path.
//   - A GitHub-issued ?token= with no GHP token: forwarded unmodified when
//     raw.allow_query_token is true (the default), rejected with 403 otherwise.
//     GHP cannot attribute, scope-check, or revoke such tokens.
//   - Neither: forwarded anonymously. Anonymous requests cannot reach private
//     content — GitHub returns 404 without a credential — so blocking them buys
//     no confidentiality and breaks ordinary public-content tooling.
//
// This asymmetry is deliberate: GHP is an enforcement point for tokens it
// issued and a telemetry point for everything else.
//
// cfg is read on every request so SIGUSR1 hot-reload of raw.allow_query_token
// takes effect without a server restart. transport is optional; when nil the
// default RoundTripper is used.
func NewRawHandler(cfg *config.Config, enforcer ScopeEnforcer, resolver TokenResolver, ur *UsernameResolver, logger *slog.Logger, transport http.RoundTripper) http.Handler {
	passthrough := newRawPassthrough(transport)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		owner, repo, ok := parseRawPath(r.URL.Path)
		if !ok {
			// Not a content path. Forward and leave it to upstream; not
			// counted, so label cardinality stays bounded by real requests.
			passthrough.ServeHTTP(w, r)
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			metrics.RawRequestTotal.WithLabelValues(owner, repo, "denied_method").Inc()
			writeError(w, http.StatusForbidden, "Only GET and HEAD are permitted for raw content")
			return
		}

		clientTok, _, _ := extractClientToken(r)
		if clientTok != "" {
			serveRawAuthenticated(w, r, passthrough, enforcer, resolver, ur, logger, owner, repo, clientTok)
			return
		}

		if r.URL.Query().Get("token") != "" {
			if !cfg.RawAllowQueryToken() {
				metrics.RawRequestTotal.WithLabelValues(owner, repo, "denied_policy").Inc()
				writeError(w, http.StatusForbidden,
					"GitHub-issued query tokens are not permitted (raw.allow_query_token is disabled)")
				return
			}
			metrics.RawRequestTotal.WithLabelValues(owner, repo, "query_token").Inc()
			SetRawAuth(r, "query_token")
			passthrough.ServeHTTP(w, r)
			return
		}

		metrics.RawRequestTotal.WithLabelValues(owner, repo, "anonymous").Inc()
		SetRawAuth(r, "anonymous")
		passthrough.ServeHTTP(w, r)
	})
}
```

- [ ] **Step 9: Implement the enforced path**

Append to `internal/proxy/raw.go`:

```go
// serveRawAuthenticated handles requests bearing a GHP-issued token. The
// token's repository allowlist and contents:read permission are enforced
// before the request is forwarded with the resolved GitHub credential.
//
// Any GitHub-issued ?token= is stripped before forwarding: carrying both a
// GHP-resolved credential and an independent GitHub capability would let the
// latter satisfy a request the former was denied.
func serveRawAuthenticated(w http.ResponseWriter, r *http.Request, passthrough http.Handler, enforcer ScopeEnforcer, resolver TokenResolver, ur *UsernameResolver, logger *slog.Logger, owner, repo, clientTok string) {
	decisionStart := time.Now()
	repoFull := owner + "/" + repo

	resolveTokenType := ""
	if tt, ok := token.TokenTypeFromPrefix(clientTok); ok {
		resolveTokenType = string(tt)
	}

	resolveStart := time.Now()
	pt, err := enforcer.Resolve(r.Context(), clientTok)
	metrics.ObserveDecision(metrics.StageTokenResolution, resolveTokenType, time.Since(resolveStart))
	if err != nil || pt == nil {
		if err != nil && logger != nil {
			logger.Warn("raw scope enforcement: token resolution failed", "error", err)
		}
		metrics.ObserveDecision(metrics.StageTotal, resolveTokenType, time.Since(decisionStart))
		writeError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	tokenType := pt.TokenType
	if pt.UserID != nil {
		SetUserID(r, *pt.UserID)
	}

	scopeParseStart := time.Now()
	si, err := parseScopeInfo(pt)
	metrics.ObserveDecision(metrics.StageScopeParsing, tokenType, time.Since(scopeParseStart))
	if err != nil {
		if logger != nil {
			logger.Error("raw scope enforcement: failed to parse token scope", "error", err)
		}
		metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
		writeError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	if !si.isOpenScoped() {
		scopeEnforceStart := time.Now()
		if len(si.Repos) > 0 && !si.repoAllowed(repoFull) {
			metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
			metrics.RawRequestTotal.WithLabelValues(owner, repo, "denied_scope").Inc()
			writeError(w, http.StatusForbidden, fmt.Sprintf("Token is not scoped to %s", repoFull))
			return
		}
		if len(si.Scopes) > 0 && !si.Scopes.HasPermission("contents", "read") {
			metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
			metrics.RawRequestTotal.WithLabelValues(owner, repo, "denied_scope").Inc()
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("Token does not have permission for contents:read on %s", repoFull))
			return
		}
		metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
	}

	ghTokenStart := time.Now()
	realToken, err := resolver.ResolveToGitHubToken(r.Context(), clientTok)
	metrics.ObserveDecision(metrics.StageGitHubTokenResolution, tokenType, time.Since(ghTokenStart))
	if err != nil {
		if logger != nil {
			logger.Warn("raw scope enforcement: GitHub token resolution failed", "error", err)
		}
		metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
		writeError(w, http.StatusUnauthorized, "Token resolution failed")
		return
	}

	usernameStart := time.Now()
	if ur != nil {
		if u := ur.ResolveFromGitHubToken(r.Context(), realToken); u != "" {
			SetUsername(r, u)
		}
	}
	metrics.ObserveDecision(metrics.StageUsernameResolution, tokenType, time.Since(usernameStart))

	// Strip the GitHub-issued capability before forwarding our own credential.
	if q := r.URL.Query(); q.Get("token") != "" {
		q.Del("token")
		r.URL.RawQuery = q.Encode()
	}

	_, _, rewriteAuth := extractClientToken(r)
	if rewriteAuth != nil {
		r.Header.Set("Authorization", rewriteAuth(realToken))
	}

	metrics.RawRequestTotal.WithLabelValues(owner, repo, "authenticated").Inc()
	SetRawAuth(r, "proxy_token")
	metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))

	upstreamStart := time.Now()
	passthrough.ServeHTTP(w, r)
	metrics.ObserveDecision(metrics.StageUpstreamRoundtrip, tokenType, time.Since(upstreamStart))
}
```

Add `"fmt"`, `"time"`, and `"github.com/goodtune/ghp/internal/token"` to the imports in `raw.go`.

- [ ] **Step 10: Run the unattributed-path tests**

Run: `go test ./internal/proxy/ -run TestRawHandler_UnattributedPaths -v`
Expected: PASS (all six subtests)

- [ ] **Step 11: Write the failing scope enforcement test**

Add to `internal/proxy/raw_test.go`. Use whatever `ScopeEnforcer` / `TokenResolver` fakes already exist in the package's test files (`passthrough_test.go` has them); if their names differ, use theirs rather than defining duplicates.

```go
func TestRawHandler_ScopeEnforcement(t *testing.T) {
	tests := []struct {
		name          string
		tokenRepos    []string
		tokenScopes   map[string]string // permission -> level; nil means unrestricted
		target        string
		wantStatus    int
		wantForwarded bool
		wantAuthHeader string
	}{
		{
			name: "repo in allowlist is forwarded with real credential",
			tokenRepos: []string{"goodtune/ghp"},
			tokenScopes: map[string]string{"contents": "read"},
			target: "/goodtune/ghp/main/README.md",
			wantStatus: http.StatusOK, wantForwarded: true,
			wantAuthHeader: "token real-github-token",
		},
		{
			name: "repo outside allowlist is denied",
			tokenRepos: []string{"goodtune/other"},
			tokenScopes: map[string]string{"contents": "read"},
			target: "/goodtune/ghp/main/README.md",
			wantStatus: http.StatusForbidden, wantForwarded: false,
		},
		{
			name: "missing contents permission is denied",
			tokenRepos: []string{"goodtune/ghp"},
			tokenScopes: map[string]string{"issues": "read"},
			target: "/goodtune/ghp/main/README.md",
			wantStatus: http.StatusForbidden, wantForwarded: false,
		},
		{
			name: "open scoped token is forwarded",
			tokenRepos: nil, tokenScopes: nil,
			target: "/goodtune/ghp/main/README.md",
			wantStatus: http.StatusOK, wantForwarded: true,
			wantAuthHeader: "token real-github-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var forwarded bool
			var gotAuth string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				gotAuth = r.Header.Get("Authorization")
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			cfg := &config.Config{}
			cfg.Raw.AllowQueryToken = true

			enforcer := newFakeScopeEnforcer(t, tt.tokenRepos, tt.tokenScopes)
			resolver := newFakeTokenResolver("real-github-token")

			h := NewRawHandler(cfg, enforcer, resolver, nil, nil, rewriteTransport(t, upstream.URL))

			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			req.Header.Set("Authorization", "token ghx_testtoken")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if forwarded != tt.wantForwarded {
				t.Errorf("forwarded = %v, want %v", forwarded, tt.wantForwarded)
			}
			if tt.wantAuthHeader != "" && gotAuth != tt.wantAuthHeader {
				t.Errorf("upstream Authorization = %q, want %q", gotAuth, tt.wantAuthHeader)
			}
		})
	}
}

func TestRawHandler_StripsQueryTokenOnAuthenticatedPath(t *testing.T) {
	var upstreamQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{}
	cfg.Raw.AllowQueryToken = true
	enforcer := newFakeScopeEnforcer(t, nil, nil)
	resolver := newFakeTokenResolver("real-github-token")
	h := NewRawHandler(cfg, enforcer, resolver, nil, nil, rewriteTransport(t, upstream.URL))

	req := httptest.NewRequest(http.MethodGet, "/goodtune/ghp/main/README.md?token=GITHUBISSUED&ref=x", nil)
	req.Header.Set("Authorization", "token ghx_testtoken")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if strings.Contains(upstreamQuery, "GITHUBISSUED") {
		t.Errorf("upstream query = %q, GitHub-issued token must be stripped", upstreamQuery)
	}
	if !strings.Contains(upstreamQuery, "ref=x") {
		t.Errorf("upstream query = %q, unrelated params must be preserved", upstreamQuery)
	}
}
```

Stripping matters: forwarding both a GHP-resolved credential and a GitHub-issued capability means the enforcement decision could be bypassed by the query token if the two disagree.

- [ ] **Step 12: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestRawHandler_Scope -v`
Expected: FAIL if enforcement is missing or misordered

- [ ] **Step 13: Add the metrics assertions test**

Add to `internal/proxy/raw_test.go`:

```go
func TestRawHandler_CountsResults(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{}
	cfg.Raw.AllowQueryToken = false
	h := NewRawHandler(cfg, nil, nil, nil, nil, rewriteTransport(t, upstream.URL))

	before := rawCounterValue(t, "metricsowner", "metricsrepo", "denied_policy")
	req := httptest.NewRequest(http.MethodGet, "/MetricsOwner/MetricsRepo/main/f.txt?token=X", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	after := rawCounterValue(t, "metricsowner", "metricsrepo", "denied_policy")

	if after != before+1 {
		t.Errorf("denied_policy counter = %v, want %v", after, before+1)
	}
}
```

Add `rawCounterValue` mirroring `codeloadCounterValue` (`codeload_test.go:22`) — copy that helper's implementation and change the label arity to `(owner, repo, result)`.

- [ ] **Step 14: Run the full suite**

Run: `make check`
Expected: PASS

- [ ] **Step 15: Commit**

```bash
git add internal/backend/backend.go internal/proxy/raw.go internal/proxy/raw_test.go
git commit -m "feat(proxy): add raw.githubusercontent.com handler

Parses owner/repo from the first two path segments, which keeps both
the classic /{owner}/{repo}/{ref}/{path} and the newer refs/heads form
unambiguous.

Requests bearing a GHP token are scope-enforced against the repository
allowlist and contents:read, then forwarded with the resolved
credential; any GitHub-issued ?token= is stripped so it cannot satisfy
a request the scope check denied. Query-token and anonymous requests
are forwarded unmodified and counted, but not attributed."
```

---

### Task 6: Wire into host dispatch, document, and record the principle

**Files:**
- Modify: `internal/server/server.go` (`hostDispatchConfig`, `newHostDispatch`, handler construction)
- Modify: `docs/admin/configuration.md`
- Modify: `docs/how-it-works.md`
- Modify: `CLAUDE.md`
- Test: `internal/server/server_test.go`

**Interfaces:**
- Consumes: `backend.Raw`, `proxy.NewRawHandler` (Task 5).
- Produces: nothing new.

- [ ] **Step 1: Write the failing dispatch test**

Add to `internal/server/server_test.go`, matching the existing host-dispatch test pattern in that file:

```go
func TestHostDispatch_Raw(t *testing.T) {
	var hit string
	mark := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = name })
	}
	d := newHostDispatch(hostDispatchConfig{
		apiHandler:      mark("api"),
		githubHandler:   mark("github"),
		codeloadHandler: mark("codeload"),
		copilotHandler:  mark("copilot"),
		rawHandler:      mark("raw"),
		mgmtHandler:     mark("mgmt"),
		managementHost:  "ghp.example.com",
	})

	for _, host := range []string{"raw.githubusercontent.com", "RAW.GithubUserContent.com", "raw.githubusercontent.com:443"} {
		t.Run(host, func(t *testing.T) {
			hit = ""
			req := httptest.NewRequest(http.MethodGet, "/o/r/main/f.txt", nil)
			req.Host = host
			d.ServeHTTP(httptest.NewRecorder(), req)
			if hit != "raw" {
				t.Errorf("host %q routed to %q, want %q", host, hit, "raw")
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/ -run TestHostDispatch_Raw -v`
Expected: FAIL — `unknown field rawHandler`

- [ ] **Step 3: Add the dispatch field and case**

In `internal/server/server.go`, add to `hostDispatchConfig` (line ~741):

```go
	rawHandler      http.Handler
```

Add to the switch in `newHostDispatch`, after the `backend.Codeload` case:

```go
		case host == backend.Raw:
			cfg.rawHandler.ServeHTTP(w, r)
```

- [ ] **Step 4: Construct and wire the handler**

In `internal/server/server.go`, after the `codeloadHandler` construction (line ~457):

```go
	rawHandler := proxy.NewRawHandler(s.cfg, tokenSvc, proxyTokenResolver, usernameResolver, s.logger, nil)
```

Add to the `newHostDispatch` call:

```go
		rawHandler:      accessLogHandler(backend.Raw, rawHandler, aw),
```

Note `tokenSvc` satisfies `ScopeEnforcer` and `proxyTokenResolver` satisfies `TokenResolver` — the same values passed to `NewScopedPassthroughHandler` at `server.go:453`.

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/server/ -run TestHostDispatch -v`
Expected: PASS (including pre-existing dispatch tests)

- [ ] **Step 6: Run the full suite**

Run: `make check`
Expected: PASS

- [ ] **Step 7: Document the config field**

In `docs/admin/configuration.md`, add `GHP_RAW_ALLOW_QUERY_TOKEN` to the environment variable table (default `true`) and add to the full YAML reference:

```yaml
raw:
  # Whether to forward raw.githubusercontent.com requests carrying a
  # GitHub-issued ?token= query parameter when no ghx_/gha_ token is present.
  #
  # The GitHub contents API returns download_url values containing such a
  # token. It is opaque to GHP: it cannot be attributed to an agent,
  # scope-checked, or revoked, and remains valid for days.
  #
  # true (default) forwards and logs these requests, trading attribution for
  # compatibility and visibility. false rejects them with 403, at the cost of
  # breaking clients that follow download_url without sending their own token.
  allow_query_token: true
```

- [ ] **Step 8: Document the behaviour and limitations**

In `docs/how-it-works.md`, add a `raw.githubusercontent.com` section covering:

- Why the handler exists: raw accepts GitHub credentials via the `Authorization` header but is **explicitly exempt** from the `sec-GitHub-allowed-enterprise` corporate proxy restriction, which GitHub scopes to `github.com`, `api.github.com` and `*.githubcopilot.com`. Cite the "Endpoints that don't require restriction" list.
- The three-way classification table from the spec.
- **Limitation 1 — the query-token path is unenforced.** State plainly that a token scoped to repo A can still fetch repo B's private content through this handler if the agent holds a GitHub-issued `?token=` for it, and that `allow_query_token: false` closes it. Describe the post-hoc correlation approach: match a recent REST API request against a subsequent raw request from the same user-agent and source IP, using `x-github-request-id` as a join key against GitHub's audit log.
- **Limitation 2 — no rate-limit visibility.** Raw returns no `X-RateLimit-*` headers, so this traffic never appears in `ghp_github_ratelimit_*`. Quota consumed via raw is invisible to GHP by construction.

- [ ] **Step 9: Record the guiding principle in CLAUDE.md**

Add a new top-level section to `CLAUDE.md`, after "Project Overview":

```markdown
## Enforcement vs Telemetry

**GHP is an enforcement point for tokens it issued and a telemetry point for
everything else.**

Handlers may forward traffic GHP cannot attribute or scope-check, provided it
is logged and counted. This is deliberate, not a gap. Two rules follow:

- **Never imply enforcement that isn't happening.** When a handler observes
  without enforcing, say so in the docs, and give operators a config switch to
  refuse the unenforceable traffic if they would rather break clients than
  allow it. `raw.allow_query_token` is the reference example.
- **A credential GHP did not issue is never forwarded alongside one it did.**
  If a request carries both, strip the foreign credential — otherwise it can
  satisfy a request the scope check denied.

Some GitHub hosts are outside enterprise network policy entirely.
`raw.githubusercontent.com` accepts `Authorization` headers but is exempt from
the `sec-GitHub-allowed-enterprise` corporate proxy restriction, which GitHub
scopes to `github.com`, `api.github.com`, and `*.githubcopilot.com` only. That
exemption is why proxying these hosts is worth the effort: GHP is the only
place the traffic can be seen.
```

Also add `ghp_raw_request_total` to the "Existing metrics" list in CLAUDE.md.

- [ ] **Step 10: Verify docs build**

Run: `make docs` (or the documented MkDocs build command — check the `Makefile` for the exact target)
Expected: builds without warnings about the modified pages

- [ ] **Step 11: Final full verification**

Run: `make check && make lint`
Expected: PASS

- [ ] **Step 12: Commit**

```bash
git add internal/server/server.go internal/server/server_test.go docs/admin/configuration.md docs/how-it-works.md CLAUDE.md
git commit -m "feat(server): route raw.githubusercontent.com

Wires the raw handler into host dispatch with access logging, documents
the configuration and both accepted limitations, and records the
enforcement-vs-telemetry principle in CLAUDE.md."
```

---

## Verification Checklist

Before considering the feature complete, confirm each of these by running the command and reading the output — not by assuming:

- [ ] `make check` passes.
- [ ] `make lint` passes.
- [ ] `go test ./internal/proxy/ -run TestRaw -v` — all subtests pass.
- [ ] `go test ./internal/server/ -run 'TestAccessLog|TestHostDispatch' -v` — all pass.
- [ ] `go test ./internal/config/ -run TestRawAllowQueryToken -v` — all pass.
- [ ] `go test ./internal/metrics/ -run TestRawRequestTotal -v` — all six result values pass.
- [ ] No access log line emits a raw `token=` value (Task 1 test asserts this).
- [ ] `docs/admin/configuration.md` lists both the env var and the YAML field.
- [ ] `CLAUDE.md` contains the enforcement-vs-telemetry section and the new metric.

## Deferred

Rewriting `download_url` in API responses, per the spec's non-goals. Adding it
later converts the `query_token` result class into a fully attributed path
without changing anything built above.
