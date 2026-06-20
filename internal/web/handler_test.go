package web

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
)

// newTestWebHandler builds a web.Handler backed by an in-memory SQLite store,
// with the given build version string.
func newTestWebHandler(t *testing.T, version string) *Handler {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DevMode: true}
	ah := auth.NewHandler(cfg, newTestAuthStore(t), enc, slog.Default())
	return NewHandler(ah, newTestAuthStore(t), true, version, slog.Default())
}

// TestHandleLoginRendersVersion verifies that the build version is surfaced on
// the login page so operators can identify which image is deployed.
func TestHandleLoginRendersVersion(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		wantInBody string // substring expected in the response body
		wantAbsent bool   // when true, the version block must not be rendered
	}{
		{
			name:       "release version",
			version:    "1.2.3",
			wantInBody: "version 1.2.3",
		},
		{
			name:       "dev version",
			version:    "dev",
			wantInBody: "version dev",
		},
		{
			name:       "empty version omits the block",
			version:    "",
			wantAbsent: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestWebHandler(t, tc.version)

			rr := httptest.NewRecorder()
			h.handleLogin(rr, httptest.NewRequest("GET", "/login", nil))

			if rr.Code != http.StatusOK {
				t.Fatalf("status: got %d, want 200; body: %s", rr.Code, rr.Body.String())
			}

			body := rr.Body.String()
			if tc.wantAbsent {
				if strings.Contains(body, `class="version"`) {
					t.Errorf("expected no version block for empty version, got body:\n%s", body)
				}
				return
			}
			if !strings.Contains(body, tc.wantInBody) {
				t.Errorf("login body missing %q; body:\n%s", tc.wantInBody, body)
			}
		})
	}
}
