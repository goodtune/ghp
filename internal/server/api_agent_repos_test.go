package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/database"
)

// fakeAccountResolver returns a fixed installation account login (#294).
type fakeAccountResolver struct {
	login string
	err   error
	calls int
}

func (f *fakeAccountResolver) InstallationAccountLogin(_ context.Context, _ string, _ int64) (string, error) {
	f.calls++
	return f.login, f.err
}

func newAgentReposAPI(t *testing.T, res *fakeAccountResolver) *API {
	t.Helper()
	a := newTestAPIFull(t)
	a.cfg = &config.Config{}
	a.cfg.Tokens.DefaultDuration = time.Hour
	if res != nil {
		a.installationAccounts = res
	}
	if err := a.store.UpsertUser(context.Background(), &database.User{ID: "user-1", GitHubUsername: "admin", GitHubID: 1}); err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	return a
}

func TestHandleCreateToken_AgentRepositories(t *testing.T) {
	tests := []struct {
		name     string
		resolver *fakeAccountResolver
		body     string
		wantCode int
		wantMsg  string
	}{
		{name: "matching owner", resolver: &fakeAccountResolver{login: "acme"}, body: `{"type":"agent","installation_id":7,"repositories":["acme/api"]}`, wantCode: http.StatusCreated},
		{name: "mixed-case owner", resolver: &fakeAccountResolver{login: "Acme"}, body: `{"type":"agent","installation_id":7,"repositories":["ACME/api"]}`, wantCode: http.StatusCreated},
		{name: "no repositories skips lookup", resolver: &fakeAccountResolver{err: errors.New("unused")}, body: `{"type":"agent","installation_id":7}`, wantCode: http.StatusCreated},
		{name: "owner mismatch", resolver: &fakeAccountResolver{login: "acme"}, body: `{"type":"agent","installation_id":7,"repositories":["acme/api","evil/api"]}`, wantCode: http.StatusBadRequest, wantMsg: "evil/api"},
		{name: "bare name rejected", resolver: &fakeAccountResolver{login: "acme"}, body: `{"type":"agent","installation_id":7,"repositories":["api"]}`, wantCode: http.StatusBadRequest, wantMsg: "expected owner/repo"},
		{name: "account lookup fails closed", resolver: &fakeAccountResolver{err: errors.New("boom")}, body: `{"type":"agent","installation_id":7,"repositories":["acme/api"]}`, wantCode: http.StatusBadGateway},
		{name: "no provider to verify", resolver: nil, body: `{"type":"agent","installation_id":7,"repositories":["acme/api"]}`, wantCode: http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAgentReposAPI(t, tt.resolver)
			req := httptest.NewRequest("POST", "/api/tokens", strings.NewReader(tt.body))
			req = req.WithContext(auth.NewContextWithSession(req.Context(), adminSession()))
			w := httptest.NewRecorder()
			a.handleCreateToken(w, req)
			if w.Code != tt.wantCode {
				t.Fatalf("code = %d, want %d: %s", w.Code, tt.wantCode, w.Body.String())
			}
			if tt.wantMsg != "" && !strings.Contains(w.Body.String(), tt.wantMsg) {
				t.Errorf("body %q does not mention %q", w.Body.String(), tt.wantMsg)
			}
			if tt.wantCode != http.StatusCreated {
				toks, err := a.store.ListAllProxyTokens(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if len(toks) != 0 {
					t.Errorf("expected no token stored, got %d", len(toks))
				}
			}
		})
	}
}

func TestHandleUpdateTokenScopes_AgentRepositories(t *testing.T) {
	tests := []struct {
		name      string
		tokenType string
		body      string
		wantCode  int
		wantCalls int
	}{
		{name: "agent matching owner", tokenType: "agent", body: `{"repositories":["acme/web"]}`, wantCode: http.StatusOK, wantCalls: 1},
		{name: "agent owner mismatch", tokenType: "agent", body: `{"repositories":["evil/web"]}`, wantCode: http.StatusBadRequest, wantCalls: 1},
		{name: "agent scopes only skips lookup", tokenType: "agent", body: `{"scopes":{"contents":"read"}}`, wantCode: http.StatusOK},
		{name: "proxy token not checked", tokenType: "proxy", body: `{"repositories":["evil/web"]}`, wantCode: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &fakeAccountResolver{login: "acme"}
			a := newAgentReposAPI(t, res)
			inst := int64(7)
			pt := &database.ProxyToken{
				TokenHash:   "hash_" + strings.ReplaceAll(tt.name, " ", "_"),
				TokenPrefix: "gha_ar1",
				TokenType:   tt.tokenType,
				ExpiresAt:   timePtrServer(time.Now().Add(time.Hour)),
			}
			if tt.tokenType == "agent" {
				pt.InstallationID = &inst
			}
			if err := a.store.CreateProxyToken(context.Background(), pt); err != nil {
				t.Fatalf("create token: %v", err)
			}
			req := httptest.NewRequest("PATCH", "/api/tokens/"+pt.ID, strings.NewReader(tt.body))
			req.SetPathValue("id", pt.ID)
			req = req.WithContext(auth.NewContextWithSession(req.Context(), adminSession()))
			w := httptest.NewRecorder()
			a.handleUpdateTokenScopes(w, req)
			if w.Code != tt.wantCode {
				t.Fatalf("code = %d, want %d: %s", w.Code, tt.wantCode, w.Body.String())
			}
			if res.calls != tt.wantCalls {
				t.Errorf("resolver calls = %d, want %d", res.calls, tt.wantCalls)
			}
		})
	}
}
