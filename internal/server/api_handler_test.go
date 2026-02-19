package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/database"
)

// mockStore implements only the methods needed by handleCreateToken tests.
type mockStore struct {
	database.Store
	getGitHubTokenErr error
	getGitHubToken    *database.GitHubToken
}

func (m *mockStore) GetGitHubToken(_ context.Context, _ string) (*database.GitHubToken, error) {
	return m.getGitHubToken, m.getGitHubTokenErr
}

func (m *mockStore) GetGitHubTokenForApp(_ context.Context, _, _ string) (*database.GitHubToken, error) {
	return m.getGitHubToken, m.getGitHubTokenErr
}

func (m *mockStore) CreateAuditEntry(_ context.Context, _ *database.AuditEntry) error {
	return nil
}

func TestHandleCreateToken_DBErrorReturns500(t *testing.T) {
	ms := &mockStore{
		getGitHubTokenErr: errors.New("database connection lost"),
	}

	apps := auth.NewSingleAppRegistry(&auth.AppInfo{
		AppID: 1, ClientID: "cid", ClientSecret: "csec",
	})
	ah := auth.NewHandler(&config.Config{}, apps, ms, nil, slog.Default())

	// Pre-create a session so RequireAuth passes.
	sessionToken := ah.CreateTestSession("user-1", "testuser", "user")

	api := NewAPI(&config.Config{}, ms, nil, ah, slog.Default())

	body := `{"type":"proxy","repository":"org/repo","scopes":"contents:read"}`
	req := httptest.NewRequest("POST", "/api/tokens", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "ghp_session", Value: sessionToken})

	w := httptest.NewRecorder()
	// Call via the auth middleware chain.
	handler := ah.RequireAuth(http.HandlerFunc(api.handleCreateToken))
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}

	var respBody map[string]string
	json.NewDecoder(resp.Body).Decode(&respBody)
	if msg := respBody["message"]; !strings.Contains(msg, "Internal") {
		t.Errorf("message = %q, want mention of internal error", msg)
	}
}

func TestHandleCreateToken_MissingTokenReturns400(t *testing.T) {
	ms := &mockStore{
		getGitHubTokenErr: nil,
		getGitHubToken:    nil, // no token, no error
	}

	apps := auth.NewSingleAppRegistry(&auth.AppInfo{
		AppID: 1, ClientID: "cid", ClientSecret: "csec",
	})
	ah := auth.NewHandler(&config.Config{}, apps, ms, nil, slog.Default())
	sessionToken := ah.CreateTestSession("user-1", "testuser", "user")

	api := NewAPI(&config.Config{}, ms, nil, ah, slog.Default())

	body := `{"type":"proxy","repository":"org/repo","scopes":"contents:read"}`
	req := httptest.NewRequest("POST", "/api/tokens", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "ghp_session", Value: sessionToken})

	w := httptest.NewRecorder()
	handler := ah.RequireAuth(http.HandlerFunc(api.handleCreateToken))
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}
