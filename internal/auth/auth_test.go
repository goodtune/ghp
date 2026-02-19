package auth

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
)

// stubStore implements only the database.Store methods needed for auth tests.
type stubStore struct {
	database.Store
	user        *database.User
	githubToken *database.GitHubToken
}

func (s *stubStore) UpsertUser(_ context.Context, u *database.User) error {
	if u.ID == "" {
		u.ID = "test-user-id"
	}
	s.user = u
	return nil
}

func (s *stubStore) UpsertGitHubToken(_ context.Context, t *database.GitHubToken) error {
	s.githubToken = t
	return nil
}

func (s *stubStore) GetGitHubToken(_ context.Context, _ string) (*database.GitHubToken, error) {
	return s.githubToken, nil
}

// --- 4a: setup_action uses Default() in multi-app mode ---

func TestHandleGitHubCallback_SetupActionMultiApp(t *testing.T) {
	// Create a multi-app registry.
	apps, err := NewMultiAppRegistry([]*AppInfo{
		{Slug: "app-a", AppID: 1, ClientID: "cid-a", ClientSecret: "csec-a"},
		{Slug: "app-b", AppID: 2, ClientID: "cid-b", ClientSecret: "csec-b"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Fake GitHub token exchange + user info endpoints.
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login/oauth/access_token" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "gho_test",
				"refresh_token": "ghr_test",
				"expires_in":    28800,
			})
			return
		}
		if r.URL.Path == "/user" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":    12345,
				"login": "testuser",
				"email": "test@example.com",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ghSrv.Close()

	enc, _ := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	h := NewHandler(&config.Config{}, apps, &stubStore{}, enc, slog.Default())
	h.tokenURL = ghSrv.URL + "/login/oauth/access_token"
	h.userURL = ghSrv.URL + "/user"

	// Simulate a setup_action callback (no state, has code).
	req := httptest.NewRequest("GET", "/auth/github/callback?code=testcode&setup_action=install", nil)
	w := httptest.NewRecorder()
	h.handleGitHubCallback(w, req)

	resp := w.Result()
	// Should NOT be a 400.
	if resp.StatusCode == http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("got 400 Bad Request: %s", body)
	}
	// Should be a redirect (302/303) on success.
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, body = %s", resp.StatusCode, body)
	}
}

// --- 4b: No reflected user input ---

func TestHandleGitHubLogin_NoReflectedInput(t *testing.T) {
	apps, _ := NewMultiAppRegistry([]*AppInfo{
		{Slug: "valid-app", AppID: 1, ClientID: "cid", ClientSecret: "csec"},
	})

	enc, _ := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	h := NewHandler(&config.Config{}, apps, &stubStore{}, enc, slog.Default())

	payload := "<script>alert(1)</script>"
	req := httptest.NewRequest("GET", "/auth/github?app="+url.QueryEscape(payload), nil)
	w := httptest.NewRecorder()
	h.handleGitHubLogin(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), payload) {
		t.Errorf("response body contains reflected input: %s", body)
	}
}

// --- 4c: exchangeCode URL-encodes form body ---

func TestExchangeCode_URLEncodesValues(t *testing.T) {
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capturedBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "gho_test",
			"refresh_token": "ghr_test",
			"expires_in":    28800,
		})
	}))
	defer srv.Close()

	enc, _ := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	apps := NewSingleAppRegistry(&AppInfo{AppID: 1, ClientID: "cid", ClientSecret: "csec"})
	h := NewHandler(&config.Config{}, apps, &stubStore{}, enc, slog.Default())
	h.tokenURL = srv.URL

	// Use values with special characters.
	clientID := "id&with=special"
	clientSecret := "secret&with=special"
	code := "code&with=special"

	_, _, _, err := h.exchangeCode(code, clientID, clientSecret)
	if err != nil {
		t.Fatalf("exchangeCode: %v", err)
	}

	// The body should be properly URL-encoded.
	values, err := url.ParseQuery(capturedBody)
	if err != nil {
		t.Fatalf("body is not valid URL-encoded form: %v", err)
	}
	if values.Get("client_id") != clientID {
		t.Errorf("client_id = %q, want %q", values.Get("client_id"), clientID)
	}
	if values.Get("client_secret") != clientSecret {
		t.Errorf("client_secret = %q, want %q", values.Get("client_secret"), clientSecret)
	}
	if values.Get("code") != code {
		t.Errorf("code = %q, want %q", values.Get("code"), code)
	}
}

// Ensure unused imports don't cause errors.
var _ = time.Now
