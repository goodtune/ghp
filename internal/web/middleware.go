package web

import (
	"fmt"
	"net/http"
)

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

// ServerHeaderMiddleware sets the Server response header on all responses,
// identifying the software and version to clients.
func ServerHeaderMiddleware(version string) func(http.Handler) http.Handler {
	value := fmt.Sprintf("GitHub Proxy %s", version)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", value)
			next.ServeHTTP(w, r)
		})
	}
}
