package server

import (
	"net/http"
)

// httpsRedirectHandler returns a handler that redirects all HTTP requests
// to their HTTPS equivalent.
func httpsRedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + r.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}
