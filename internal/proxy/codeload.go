package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/metrics"
)

// codeloadArchiveRe matches codeload.github.com archive download paths of the
// form /{owner}/{repo}/{format}/{ref}, where format is one of "tar.gz", "zip",
// "legacy.tar.gz", or "legacy.zip", and ref is a SHA, branch, or tag.
//
// The "legacy.*" alternatives must precede "tar.gz" / "zip" so the longer
// prefix wins (Go's regexp is leftmost-first; we anchor the format segment to
// avoid greedy mismatches by using grouped alternation).
var codeloadArchiveRe = regexp.MustCompile(`^/+([^/]+)/([^/]+)/(legacy\.tar\.gz|legacy\.zip|tar\.gz|zip)/(.+)$`)

// upstreamCodeload is the canonical upstream codeload URL used as the
// passthrough target. Parsed once at package init.
var upstreamCodeload = mustParseCodeloadURL("https://codeload.github.com")

func mustParseCodeloadURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// NewCodeloadHandler returns an http.Handler for codeload.github.com requests.
//
// When cfg.Codeload.RedirectTo is set to an absolute URL, archive download
// requests matching /{owner}/{repo}/(tar.gz|zip|legacy.tar.gz|legacy.zip)/{ref}
// are answered with a 302 to RedirectTo + the original path (and query string).
// Requests for orgs or org/repo pairs in cfg.Codeload.Allow bypass the redirect
// and are forwarded to the upstream codeload service. Non-archive paths are
// always forwarded. When RedirectTo is empty, every archive request is still
// counted as result="passthrough" before forwarding so operators can see total
// archive volume even before a mirror is configured.
//
// cfg is read on every request so SIGUSR1 hot-reload of codeload.redirect_to
// and codeload.allow takes effect without a server restart. transport is
// optional; when nil the default RoundTripper is used. It exists to allow
// tests to intercept upstream requests without making real network calls.
func NewCodeloadHandler(cfg *config.Config, logger *slog.Logger, transport http.RoundTripper) http.Handler {
	passthrough := newCodeloadPassthrough(transport)

	// Cache the parsed redirect_to keyed by the raw config string so we don't
	// re-validate the URL on every request, but still pick up changes when
	// codeload.redirect_to is updated via hot-reload. The "" key represents
	// "no redirect configured".
	var (
		mu       sync.RWMutex
		cachedIn string
		cachedOk bool
		cachedTo string
	)

	resolveRedirectBase := func() string {
		// CodeloadSnapshot copies under config.RWMutex so we can't race
		// with a concurrent SIGUSR1 reload mutating cfg.Codeload.
		raw := cfg.CodeloadSnapshot().RedirectTo

		mu.RLock()
		if raw == cachedIn {
			out := cachedTo
			ok := cachedOk
			mu.RUnlock()
			if ok {
				return out
			}
			return ""
		}
		mu.RUnlock()

		mu.Lock()
		defer mu.Unlock()
		// Re-check under the write lock in case another goroutine populated it.
		if raw == cachedIn {
			if cachedOk {
				return cachedTo
			}
			return ""
		}
		cachedIn = raw
		base := strings.TrimRight(raw, "/")
		if base == "" {
			cachedOk = false
			cachedTo = ""
			return ""
		}
		// Require a parseable absolute URL with an explicit host and an
		// http(s) scheme. Without these, the synthesised Location header
		// would be malformed (e.g. "file:///tmp/<path>") or unreachable from
		// a browser — so log and fall back to passthrough rather than
		// emitting a redirect that's guaranteed to break the client.
		// Also reject values that already carry a query string or fragment:
		// the redirect target is built by appending the request path/query,
		// which would produce something like ".../base?x=y/owner/repo/..."
		// — clearly broken — so make the misconfiguration loud.
		u, err := url.Parse(base)
		switch {
		case err != nil, !u.IsAbs(), u.Host == "",
			u.Scheme != "http" && u.Scheme != "https",
			u.RawQuery != "", u.Fragment != "":
			if logger != nil {
				logger.Error("codeload redirect_to must be an absolute http(s) URL with a host and no query/fragment; falling back to passthrough",
					"redirect_to", raw)
			}
			cachedOk = false
			cachedTo = ""
			return ""
		}
		cachedOk = true
		cachedTo = base
		return base
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := codeloadArchiveRe.FindStringSubmatch(r.URL.Path)
		if m == nil {
			// Non-archive paths: always passthrough, never counted (the
			// counter is scoped to archive requests so cardinality stays
			// predictable).
			passthrough.ServeHTTP(w, r)
			return
		}

		// Normalise owner/repo to lowercase before using as Prometheus
		// labels. GitHub is case-insensitive on owner and repo, so
		// "Actions/Checkout" and "actions/checkout" must resolve to the
		// same time series — otherwise clients with inconsistent casing
		// would split the counter and inflate cardinality. Pattern matches
		// internal/gitcache/middleware.go.
		owner := strings.ToLower(m[1])
		repo := strings.ToLower(m[2])
		archive := m[3]

		redirectBase := resolveRedirectBase()
		if redirectBase == "" || cfg.IsCodeloadAllowed(owner, repo) {
			metrics.CodeloadRedirectTotal.WithLabelValues(owner, repo, archive, "passthrough").Inc()
			passthrough.ServeHTTP(w, r)
			return
		}

		// Build the redirect target from the URL's escaped path and raw query
		// rather than r.URL.RequestURI() so the result is unambiguous when the
		// request arrives in absolute-form (e.g. through a forward proxy) — we
		// only ever want the path/query component appended to redirectBase.
		target := redirectBase + r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		metrics.CodeloadRedirectTotal.WithLabelValues(owner, repo, archive, "redirect").Inc()
		http.Redirect(w, r, target, http.StatusFound)
	})
}

// newCodeloadPassthrough builds a transparent reverse proxy to upstream
// codeload.github.com. It preserves the original Host header so tests and
// access logs see the value the client sent.
func newCodeloadPassthrough(transport http.RoundTripper) http.Handler {
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			originalHost := req.Host
			req.URL.Scheme = upstreamCodeload.Scheme
			req.URL.Host = upstreamCodeload.Host
			req.Host = originalHost
		},
	}
	if transport != nil {
		rp.Transport = transport
	}
	return rp
}
