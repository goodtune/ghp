package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/ghp/internal/config"
)

// TestManagementProxyHandler_RequiresGHPToken checks the wiring used for the
// management host's /api/v3/ and /api/graphql routes (#296): anonymous and
// native-token requests never reach the proxy handler.
func TestManagementProxyHandler_RequiresGHPToken(t *testing.T) {
	tests := []struct {
		name       string
		auth       string
		wantStatus int
		wantNext   bool
	}{
		{name: "anonymous", wantStatus: http.StatusUnauthorized},
		{name: "native", auth: "token gho_realtoken123", wantStatus: http.StatusForbidden},
		{name: "ghx", auth: "Bearer ghx_abc123", wantStatus: http.StatusOK, wantNext: true},
	}
	for _, path := range []string{"/api/v3/user", "/api/graphql"} {
		for _, tc := range tests {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				called := false
				next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					called = true
					w.WriteHeader(http.StatusOK)
				})
				mux := http.NewServeMux()
				h := managementProxyHandler(next, &config.Config{})
				mux.Handle("/api/v3/", h)
				mux.Handle("/api/graphql", h)

				req := httptest.NewRequest(http.MethodGet, path, nil)
				if tc.auth != "" {
					req.Header.Set("Authorization", tc.auth)
				}
				rr := httptest.NewRecorder()
				mux.ServeHTTP(rr, req)
				if rr.Code != tc.wantStatus {
					t.Fatalf("status = %d, want %d", rr.Code, tc.wantStatus)
				}
				if called != tc.wantNext {
					t.Fatalf("next called = %v, want %v", called, tc.wantNext)
				}
			})
		}
	}
}
