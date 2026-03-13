package proxy

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/jdx/go-netrc"
)

// releasesDownloadRe matches github.com release download paths of the form
// /{org}/{repo}/releases/download/{tag}/{asset} and captures org, repo, tag,
// and asset.
var releasesDownloadRe = regexp.MustCompile(`^/+([^/]+)/([^/]+)/releases/download/([^/]+)/(.+)$`)

// releasesDownloadPrefixRe is a looser match used for the policy check — it
// matches any path that starts with /{org}/{repo}/releases/download/ regardless
// of whether tag/asset segments are present (e.g. directory listings).
var releasesDownloadPrefixRe = regexp.MustCompile(`^/+([^/]+)/([^/]+)/releases/download/`)

// releaseNotFoundData is the template data passed to the 404 page template
// when a HEAD check against the redirect target returns 404.
type releaseNotFoundData struct {
	Owner string
	Repo  string
	Tag   string
	Asset string
	URL   string
}

// defaultNotFoundTemplate is the built-in HTML template rendered when
// redirect_head_check detects a 404 and no custom template is configured.
const defaultNotFoundTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Release Not Found</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f6f8fa; color: #1f2328; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 1rem; }
  .card { background: #fff; border: 1px solid #d1d9e0; border-radius: 12px; max-width: 520px; width: 100%; padding: 2rem; text-align: center; }
  h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
  .code { font-size: 4rem; font-weight: 700; color: #d1242f; margin-bottom: 0.25rem; }
  .details { color: #656d76; font-size: 0.9rem; margin-top: 1rem; line-height: 1.5; }
  .asset { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace; background: #f6f8fa; border: 1px solid #d1d9e0; border-radius: 6px; padding: 0.15rem 0.4rem; font-size: 0.85rem; word-break: break-all; }
  .repo { font-weight: 600; }
</style>
</head>
<body>
<div class="card">
  <div class="code">404</div>
  <h1>Release Not Found</h1>
  <p class="details">
    The release asset <span class="asset">{{.Asset}}</span>
    from <span class="repo">{{.Owner}}/{{.Repo}}</span>
    {{- if .Tag}} ({{.Tag}}){{end}}
    is not available on the configured mirror.
  </p>
  <p class="details">
    Contact your administrator if you believe this asset should be mirrored.
  </p>
</div>
</body>
</html>
`

var defaultNotFoundTmpl = template.Must(template.New("not-found").Parse(defaultNotFoundTemplate))

// HTTPHeadDoer is the interface used by the releases handler to perform HEAD
// requests. This allows injecting a test client.
type HTTPHeadDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// headCheckClient is the default HEAD-check probe client used by
// NewReleasesHandler for all HEAD availability probes. It disables
// redirect-following so that a mirror responding with a redirect is treated as
// "found" (non-404) and probe credentials are never forwarded to an unintended
// redirect target. A 10-second timeout ensures that an unresponsive mirror
// degrades gracefully to a normal redirect rather than blocking the client
// request indefinitely. When netrc credentials are configured, Basic auth is
// injected per-request via creds.setBasicAuth rather than via a transport wrapper.
var headCheckClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// netrcCreds holds pre-parsed netrc credentials for injecting Basic auth
// on HEAD probes at the request level, rather than via a transport wrapper.
type netrcCreds struct {
	netrc *netrc.Netrc
}

// parseNetrcFile reads and parses the given netrc file path and returns a
// netrcCreds that can be used to look up credentials by hostname. Returns an
// error if the file cannot be read or parsed.
func parseNetrcFile(path string) (*netrcCreds, error) {
	n, err := netrc.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("loading netrc file %q: %w", path, err)
	}
	return &netrcCreds{netrc: n}, nil
}

// lookupMachine finds a machine entry by hostname (case-insensitive).
// Default entries are intentionally ignored to prevent credential leakage
// to unintended hosts.
func (c *netrcCreds) lookupMachine(host string) (login, password string, ok bool) {
	host = strings.ToLower(host)
	for _, m := range c.netrc.Machines() {
		if !m.IsDefault && strings.ToLower(m.Name) == host {
			login = m.Get("login")
			if login != "" {
				return login, m.Get("password"), true
			}
		}
	}
	return "", "", false
}

// setBasicAuth sets Basic auth on req if creds match the request hostname.
// Credentials are only injected when:
//   - the scheme is HTTPS (to prevent sending credentials in cleartext)
//   - the request does not already have an Authorization header
func (c *netrcCreds) setBasicAuth(req *http.Request) {
	if req.URL.Scheme != "https" {
		return
	}
	if _, _, ok := req.BasicAuth(); ok {
		return
	}
	if req.Header.Get("Authorization") != "" {
		return
	}
	if login, password, ok := c.lookupMachine(req.URL.Hostname()); ok {
		req.SetBasicAuth(login, password)
	}
}

// NewReleasesHandler wraps inner with a policy handler for github.com release
// download requests. Paths matching /{org}/{repo}/releases/download/** are
// intercepted when cfg.Releases.Mode is non-empty:
//
//   - "block":    Returns 403 unless the org or org/repo is in the allow list.
//   - "redirect": Returns a 302 redirect to cfg.Releases.RedirectTo + the
//     original path (and query string) unless the org or org/repo is in the
//     allow list. When cfg.Releases.RedirectHeadCheck is true, a HEAD request
//     is made to the target URL first; if the upstream returns 404, a friendly
//     HTML page is returned instead of a redirect.
//
// When cfg.Releases.RedirectHeadCheckNetrc is set, credentials from the
// specified netrc file are sent as Basic auth on HEAD availability probes
// over HTTPS only (plain http:// requests are never authenticated to avoid
// sending credentials in cleartext). Existing Authorization headers on a
// request are preserved and never overwritten.
//
// Any other mode value or an empty mode passes all requests through to inner
// unchanged. The allow list check is always performed before applying the
// policy, so explicitly listed orgs and repos are never affected.
func NewReleasesHandler(inner http.Handler, cfg *config.Config, logger *slog.Logger) http.Handler {
	var creds *netrcCreds
	if cfg.Releases.RedirectHeadCheckNetrc != "" {
		var err error
		creds, err = parseNetrcFile(cfg.Releases.RedirectHeadCheckNetrc)
		if err != nil {
			if logger != nil {
				logger.Error("failed to load netrc for HEAD check, continuing without auth",
					"path", cfg.Releases.RedirectHeadCheckNetrc, "error", err)
			}
		}
	}
	return NewReleasesHandlerWithClient(inner, cfg, logger, headCheckClient, creds)
}

// NewReleasesHandlerWithClient is like NewReleasesHandler but accepts a custom
// HTTP client for HEAD requests and optional pre-parsed netrc credentials,
// enabling testing without real network calls.
func NewReleasesHandlerWithClient(inner http.Handler, cfg *config.Config, logger *slog.Logger, client HTTPHeadDoer, creds *netrcCreds) http.Handler {
	// Pre-load the not-found template once at construction time so it is not
	// re-read and re-parsed on every 404 response.
	notFoundTmpl := defaultNotFoundTmpl
	if cfg.Releases.RedirectNotFoundTemplate != "" {
		customTmpl, err := loadCustomTemplate(cfg.Releases.RedirectNotFoundTemplate)
		if err != nil {
			if logger != nil {
				logger.Error("failed to load custom not-found template, using default",
					"path", cfg.Releases.RedirectNotFoundTemplate, "error", err)
			}
		} else {
			notFoundTmpl = customTmpl
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mode := cfg.Releases.Mode
		if mode == "" {
			inner.ServeHTTP(w, r)
			return
		}

		pm := releasesDownloadPrefixRe.FindStringSubmatch(r.URL.Path)
		if pm == nil {
			inner.ServeHTTP(w, r)
			return
		}

		org, repo := pm[1], pm[2]

		if cfg.IsReleaseAllowed(org, repo) {
			inner.ServeHTTP(w, r)
			return
		}

		switch strings.ToLower(mode) {
		case "block":
			writeError(w, http.StatusForbidden, "Release downloads are not permitted")
		case "redirect":
			redirectTo := strings.TrimRight(cfg.Releases.RedirectTo, "/")
			u, err := url.Parse(redirectTo)
			if redirectTo == "" || err != nil || !u.IsAbs() {
				if logger != nil {
					logger.Error("releases redirect_to must be an absolute URL", "redirect_to", cfg.Releases.RedirectTo)
				}
				writeError(w, http.StatusInternalServerError, "Release redirect is misconfigured")
				return
			}
			target := redirectTo + r.URL.RequestURI()

			if cfg.Releases.RedirectHeadCheck {
				if servedNotFound := headCheckAndServe404(w, r, target, client, creds, notFoundTmpl, logger); servedNotFound {
					return
				}
			}

			http.Redirect(w, r, target, http.StatusFound)
		default:
			if logger != nil {
				logger.Warn("unknown releases mode, passing through", "mode", mode)
			}
			inner.ServeHTTP(w, r)
		}
	})
}

// headCheckAndServe404 issues a HEAD request to target. If the response is 404,
// it renders tmpl and returns true. For any other outcome (non-404 response,
// network error) it returns false and the caller should proceed with the normal
// redirect. When creds is non-nil, Basic auth is injected on the HEAD request
// for HTTPS targets that match a netrc machine entry.
func headCheckAndServe404(w http.ResponseWriter, r *http.Request, target string, client HTTPHeadDoer, creds *netrcCreds, tmpl *template.Template, logger *slog.Logger) bool {
	headReq, err := http.NewRequestWithContext(r.Context(), http.MethodHead, target, nil)
	if err != nil {
		if logger != nil {
			logger.Warn("failed to create HEAD request for redirect target", "target", target, "error", err)
		}
		metrics.ReleasesRedirectHeadCheckTotal.WithLabelValues("error").Inc()
		return false
	}

	if creds != nil {
		creds.setBasicAuth(headReq)
	}

	start := time.Now()
	resp, err := client.Do(headReq)
	dur := time.Since(start)
	metrics.ObserveDecision(metrics.StageRedirectHeadCheck, "unknown", dur)

	if err != nil {
		if logger != nil {
			logger.Warn("HEAD request to redirect target failed", "target", target, "error", err)
		}
		metrics.ReleasesRedirectHeadCheckTotal.WithLabelValues("error").Inc()
		return false
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		metrics.ReleasesRedirectHeadCheckTotal.WithLabelValues("found").Inc()
		return false
	}

	metrics.ReleasesRedirectHeadCheckTotal.WithLabelValues("not_found").Inc()

	// Extract tag/asset from the original path for the template.
	var data releaseNotFoundData
	data.URL = target
	if m := releasesDownloadRe.FindStringSubmatch(r.URL.Path); m != nil {
		data.Owner = m[1]
		data.Repo = m[2]
		data.Tag = m[3]
		data.Asset = m[4]
	} else {
		// Fallback: use the prefix match for owner/repo.
		pm := releasesDownloadPrefixRe.FindStringSubmatch(r.URL.Path)
		if pm != nil {
			data.Owner = pm[1]
			data.Repo = pm[2]
		}
		data.Asset = path.Base(r.URL.Path)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	if err := tmpl.Execute(w, data); err != nil && logger != nil {
		logger.Error("failed to render not-found template", "error", err)
	}
	return true
}

// loadCustomTemplate reads and parses an HTML template from disk.
func loadCustomTemplate(path string) (*template.Template, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return template.New("custom-not-found").Parse(string(b))
}
