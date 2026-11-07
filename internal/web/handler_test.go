package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/permissions"
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

// TestHandleAdminEmbedsCanonicalPermissions verifies that the admin page
// embeds the canonical permission list that the token scope editor offers
// (#350).
func TestHandleAdminEmbedsCanonicalPermissions(t *testing.T) {
	h := newTestWebHandler(t, "dev")

	mux := http.NewServeMux()
	h.auth.RegisterRoutes(mux)
	loginReq := httptest.NewRequest("POST", "/auth/test-login",
		strings.NewReader(`{"username":"alice","role":"admin"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRR := httptest.NewRecorder()
	mux.ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("test-login: got %d; body: %s", loginRR.Code, loginRR.Body.String())
	}

	req := httptest.NewRequest("GET", "/admin", nil)
	for _, c := range loginRR.Result().Cookies() {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.handleAdmin(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rr.Code)
	}

	body := rr.Body.String()
	const marker = "const CANONICAL_PERMISSIONS = "
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("admin body missing %q", marker)
	}
	rest := body[i+len(marker):]
	end := strings.Index(rest, ";")
	if end < 0 {
		t.Fatal("unterminated CANONICAL_PERMISSIONS")
	}
	var got []string
	if err := json.Unmarshal([]byte(rest[:end]), &got); err != nil {
		t.Fatalf("decode CANONICAL_PERMISSIONS: %v", err)
	}
	want := permissions.Names()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CANONICAL_PERMISSIONS: got %v, want %v", got, want)
	}
}
