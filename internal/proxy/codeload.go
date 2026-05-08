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
// always forwarded. When RedirectTo is empty, every request is forwarded
// transparently to upstream codeload.github.com.
//
// transport is optional; when nil the default RoundTripper is used. It exists
// to allow tests to intercept upstream requests without making real network
// calls.
func NewCodeloadHandler(cfg *config.Config, logger *slog.Logger, transport http.RoundTripper) http.Handler {
	passthrough := newCodeloadPassthrough(transport)

	// Pre-validate and normalise the redirect base URL once so the per-request
	// handler avoids repeated TrimRight + url.Parse work.
	redirectBase := strings.TrimRight(cfg.Codeload.RedirectTo, "/")
	if redirectBase != "" {
		if u, err := url.Parse(redirectBase); err != nil || !u.IsAbs() {
			if logger != nil {
				logger.Error("codeload redirect_to must be an absolute URL; falling back to passthrough",
					"redirect_to", cfg.Codeload.RedirectTo)
			}
			redirectBase = ""
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirectBase == "" {
			passthrough.ServeHTTP(w, r)
			return
		}

		m := codeloadArchiveRe.FindStringSubmatch(r.URL.Path)
		if m == nil {
			passthrough.ServeHTTP(w, r)
			return
		}

		owner, repo, archive := m[1], m[2], m[3]

		if cfg.IsCodeloadAllowed(owner, repo) {
			metrics.CodeloadRedirectTotal.WithLabelValues(owner, repo, archive, "passthrough").Inc()
			passthrough.ServeHTTP(w, r)
			return
		}

		target := redirectBase + r.URL.RequestURI()
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
