package proxy

import (
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/goodtune/ghp/internal/config"
)

// releasesDownloadRe matches github.com release download paths of the form
// /{org}/{repo}/releases/download/{...} and captures org and repo.
var releasesDownloadRe = regexp.MustCompile(`^/([^/]+)/([^/]+)/releases/download/`)

// NewReleasesHandler wraps inner with a policy handler for github.com release
// download requests. Paths matching /{org}/{repo}/releases/download/** are
// intercepted when cfg.Releases.Mode is non-empty:
//
//   - "block":    Returns 403 unless the org or org/repo is in the allow list.
//   - "redirect": Returns a 302 redirect to cfg.Releases.RedirectTo + the
//     original path (and query string) unless the org or org/repo is in the
//     allow list.
//
// Any other mode value or an empty mode passes all requests through to inner
// unchanged. The allow list check is always performed before applying the
// policy, so explicitly listed orgs and repos are never affected.
func NewReleasesHandler(inner http.Handler, cfg *config.Config, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mode := cfg.Releases.Mode
		if mode == "" {
			inner.ServeHTTP(w, r)
			return
		}

		m := releasesDownloadRe.FindStringSubmatch(r.URL.Path)
		if m == nil {
			inner.ServeHTTP(w, r)
			return
		}

		org, repo := m[1], m[2]

		if cfg.IsReleaseAllowed(org, repo) {
			inner.ServeHTTP(w, r)
			return
		}

		switch strings.ToLower(mode) {
		case "block":
			writeError(w, http.StatusForbidden, "Release downloads are not permitted")
		case "redirect":
			redirectTo := strings.TrimRight(cfg.Releases.RedirectTo, "/")
			if redirectTo == "" {
				if logger != nil {
					logger.Error("releases redirect mode enabled but redirect_to is empty")
				}
				writeError(w, http.StatusInternalServerError, "Release redirect is misconfigured")
				return
			}
			target := redirectTo + r.URL.Path
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
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
