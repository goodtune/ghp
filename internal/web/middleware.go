package web

import (
	"net/http"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/proxy"
)

// SessionUsernameMiddleware injects the session username and user ID into the
// access log context slots so that management requests are attributed to the
// logged-in user. The username slot receives the GitHub login; the user ID
// slot receives the internal database identifier.
func SessionUsernameMiddleware(ah *auth.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if session := ah.GetSession(r); session != nil {
				proxy.SetUsername(r, session.Username)
				proxy.SetUserID(r, session.UserID)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeadersMiddleware sets standard security headers on all responses.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// ServerHeaderMiddleware sets the Server and X-GitHub-Proxy-Version response
// headers on all responses. It wraps the ResponseWriter so that the headers are
// forced at WriteHeader time, after any upstream proxy handler has populated
// the header map — ensuring exactly one Server value even when GitHub's own
// "server: github.com" header is copied from the upstream response via Add.
func ServerHeaderMiddleware(version string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			shw := &serverHeaderWriter{ResponseWriter: w, version: version}
			next.ServeHTTP(shw, r)
			if !shw.done {
				shw.setOnce()
			}
		})
	}
}

// serverHeaderWriter wraps http.ResponseWriter and forces the Server header to
// a fixed value immediately before the response headers are written, discarding
// any conflicting value set by downstream handlers (e.g. the GitHub upstream
// "server: github.com" copied by the reverse proxy).
type serverHeaderWriter struct {
	http.ResponseWriter
	version string
	done    bool
}

func (w *serverHeaderWriter) WriteHeader(code int) {
	w.setOnce()
	w.ResponseWriter.WriteHeader(code)
}

func (w *serverHeaderWriter) Write(b []byte) (int, error) {
	w.setOnce()
	return w.ResponseWriter.Write(b)
}

func (w *serverHeaderWriter) setOnce() {
	if !w.done {
		w.Header().Set("Server", "GitHub Proxy")
		if w.version != "" {
			w.Header().Set("X-GitHub-Proxy-Version", w.version)
		}
		w.done = true
	}
}

// Flush implements http.Flusher so that streaming/reverse-proxy flush
// behaviour is preserved through the wrapper.
func (w *serverHeaderWriter) Flush() {
	w.setOnce()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter so that http.ResponseController
// can reach Flush, Hijack, and other optional interfaces on the concrete type.
func (w *serverHeaderWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
