package gitcred

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testSessionToken = "ghpr_test"

// fakeAPI starts an httptest server whose handler first checks the method,
// path and bearer token, then delegates to fn.
func fakeAPI(t *testing.T, method, path string, fn http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			t.Errorf("method = %q, want %q", r.Method, method)
		}
		if r.URL.EscapedPath() != path {
			t.Errorf("path = %q, want %q", r.URL.EscapedPath(), path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testSessionToken {
			t.Errorf("Authorization = %q, want bearer session token", got)
		}
		fn(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeJSONBody(t *testing.T, w http.ResponseWriter, status int, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encoding response: %v", err)
	}
}

func TestClient_ListApps(t *testing.T) {
	tests := []struct {
		name   string
		suffix string
	}{
		{name: "base url", suffix: ""},
		{name: "base url with trailing slash", suffix: "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := fakeAPI(t, http.MethodGet, "/api/apps", func(w http.ResponseWriter, r *http.Request) {
				writeJSONBody(t, w, http.StatusOK, []map[string]any{
					{"id": "11111111-1111-1111-1111-111111111111", "name": "my-app", "app_id": 101, "is_default": true, "client_id": "x"},
					{"id": "22222222-2222-2222-2222-222222222222", "name": "other", "app_id": 102, "is_default": false},
				})
			})
			c := &Client{BaseURL: srv.URL + tt.suffix, Token: testSessionToken}
			apps, err := c.ListApps(context.Background())
			if err != nil {
				t.Fatalf("ListApps() error = %v", err)
			}
			want := []App{
				{ID: "11111111-1111-1111-1111-111111111111", Name: "my-app", AppID: 101, IsDefault: true},
				{ID: "22222222-2222-2222-2222-222222222222", Name: "other", AppID: 102},
			}
			if len(apps) != len(want) {
				t.Fatalf("ListApps() = %+v, want %+v", apps, want)
			}
			for i := range want {
				if apps[i] != want[i] {
					t.Errorf("apps[%d] = %+v, want %+v", i, apps[i], want[i])
				}
			}
		})
	}
}

func TestClient_ListInstallations(t *testing.T) {
	const id = "0b0e0000-0000-4000-8000-000000000001"
	srv := fakeAPI(t, http.MethodGet, "/api/apps/"+id+"/installations", func(w http.ResponseWriter, r *http.Request) {
		writeJSONBody(t, w, http.StatusOK, []map[string]any{
			{"id": 42, "account": map[string]any{"login": "goodtune", "id": 7, "type": "User"}, "permissions": map[string]string{"contents": "read", "metadata": "read"}, "repository_selection": "all"},
		})
	})
	c := &Client{BaseURL: srv.URL, Token: testSessionToken}
	insts, err := c.ListInstallations(context.Background(), id)
	if err != nil {
		t.Fatalf("ListInstallations() error = %v", err)
	}
	if len(insts) != 1 {
		t.Fatalf("ListInstallations() = %+v, want one installation", insts)
	}
	got := insts[0]
	if got.ID != 42 || got.Account.Login != "goodtune" {
		t.Errorf("installation = %+v, want id 42 login goodtune", got)
	}
	if got.Permissions["contents"] != "read" {
		t.Errorf("Permissions[contents] = %q, want read", got.Permissions["contents"])
	}
}

func TestClient_ListInstallations_EscapesID(t *testing.T) {
	srv := fakeAPI(t, http.MethodGet, "/api/apps/a%2Fb/installations", func(w http.ResponseWriter, r *http.Request) {
		writeJSONBody(t, w, http.StatusOK, []any{})
	})
	c := &Client{BaseURL: srv.URL, Token: testSessionToken}
	if _, err := c.ListInstallations(context.Background(), "a/b"); err != nil {
		t.Fatalf("ListInstallations() error = %v", err)
	}
}

func TestClient_CreateToken(t *testing.T) {
	expires := "2026-11-08T12:00:00Z"
	tests := []struct {
		name       string
		req        MintRequest
		wantBody   map[string]any
		absentKeys []string
		expiresAt  any
	}{
		{
			name: "agent",
			req: MintRequest{
				Type: TypeAgent, Repositories: []string{"goodtune/ghp"}, Scopes: "contents:read",
				Duration: "1h0m0s", SessionID: "git-credential:h",
				AppRecordID: "11111111-1111-1111-1111-111111111111", InstallationID: 42,
			},
			wantBody: map[string]any{
				"type": "agent", "repositories": []any{"goodtune/ghp"}, "scopes": "contents:read",
				"duration": "1h0m0s", "session_id": "git-credential:h",
				"app_record_id": "11111111-1111-1111-1111-111111111111", "installation_id": float64(42),
			},
			expiresAt: expires,
		},
		{
			name: "proxy",
			req: MintRequest{
				Type: TypeProxy, Repositories: []string{"goodtune/ghp"}, Scopes: "contents:write",
				Duration: "1h0m0s", SessionID: "git-credential:h",
			},
			wantBody: map[string]any{
				"type": "proxy", "repositories": []any{"goodtune/ghp"}, "scopes": "contents:write",
				"duration": "1h0m0s", "session_id": "git-credential:h",
			},
			absentKeys: []string{"app_record_id", "installation_id"},
			expiresAt:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := fakeAPI(t, http.MethodPost, "/api/tokens", func(w http.ResponseWriter, r *http.Request) {
				if ct := r.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", ct)
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatalf("decoding body: %v", err)
				}
				for k, want := range tt.wantBody {
					gotJSON, _ := json.Marshal(body[k])
					wantJSON, _ := json.Marshal(want)
					if string(gotJSON) != string(wantJSON) {
						t.Errorf("body[%q] = %s, want %s", k, gotJSON, wantJSON)
					}
				}
				for _, k := range tt.absentKeys {
					if _, ok := body[k]; ok {
						t.Errorf("body has key %q, want absent", k)
					}
				}
				writeJSONBody(t, w, http.StatusCreated, map[string]any{
					"token": "gha_secret", "id": "tok-1", "type": tt.req.Type,
					"repositories": []string{"goodtune/ghp"}, "scopes": map[string]string{"contents": "read"},
					"expires_at": tt.expiresAt, "session_id": "git-credential:h",
				})
			})
			c := &Client{BaseURL: srv.URL, Token: testSessionToken}
			got, err := c.CreateToken(context.Background(), tt.req)
			if err != nil {
				t.Fatalf("CreateToken() error = %v", err)
			}
			if got.Token != "gha_secret" || got.ID != "tok-1" || got.Type != tt.req.Type {
				t.Errorf("CreateToken() = %+v", got)
			}
			if len(got.Repositories) != 1 || got.Repositories[0] != "goodtune/ghp" {
				t.Errorf("Repositories = %v", got.Repositories)
			}
			if got.Scopes["contents"] != "read" {
				t.Errorf("Scopes = %v", got.Scopes)
			}
			if tt.expiresAt == nil {
				if got.ExpiresAt != nil {
					t.Errorf("ExpiresAt = %v, want nil", got.ExpiresAt)
				}
				return
			}
			want, _ := time.Parse(time.RFC3339, expires)
			if got.ExpiresAt == nil || !got.ExpiresAt.Equal(want) {
				t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, want)
			}
		})
	}
}

func TestClient_Errors(t *testing.T) {
	sentinels := []error{ErrUnauthorized, ErrForbidden, ErrRateLimited}
	tests := []struct {
		name           string
		status         int
		retryAfter     string
		body           string
		want           error
		wantRetryAfter string
		wantContains   string
	}{
		{name: "401", status: http.StatusUnauthorized, body: `{"message":"Invalid token"}`, want: ErrUnauthorized, wantContains: "Invalid token"},
		{name: "403", status: http.StatusForbidden, body: `{"message":"Admin role required"}`, want: ErrForbidden, wantContains: "Admin role required"},
		{name: "429", status: http.StatusTooManyRequests, retryAfter: "1", body: `{"message":"slow down"}`, want: ErrRateLimited, wantRetryAfter: "1", wantContains: "slow down"},
		{name: "400", status: http.StatusBadRequest, body: `{"message":"bad"}`, wantContains: "bad"},
		{name: "500 not json", status: http.StatusInternalServerError, body: "oops", wantContains: "500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := fakeAPI(t, http.MethodGet, "/api/apps", func(w http.ResponseWriter, r *http.Request) {
				if tt.retryAfter != "" {
					w.Header().Set("Retry-After", tt.retryAfter)
				}
				w.WriteHeader(tt.status)
				if _, err := io.WriteString(w, tt.body); err != nil {
					t.Errorf("writing response: %v", err)
				}
			})
			c := &Client{BaseURL: srv.URL, Token: testSessionToken}
			_, err := c.ListApps(context.Background())
			if err == nil {
				t.Fatal("ListApps() error = nil, want error")
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error %T is not *APIError", err)
			}
			if apiErr.Status != tt.status {
				t.Errorf("Status = %d, want %d", apiErr.Status, tt.status)
			}
			if apiErr.RetryAfter != tt.wantRetryAfter {
				t.Errorf("RetryAfter = %q, want %q", apiErr.RetryAfter, tt.wantRetryAfter)
			}
			if !strings.Contains(err.Error(), tt.wantContains) {
				t.Errorf("Error() = %q, want containing %q", err.Error(), tt.wantContains)
			}
			if strings.Contains(err.Error(), testSessionToken) {
				t.Errorf("Error() = %q contains the session token", err.Error())
			}
			for _, s := range sentinels {
				if got := errors.Is(err, s); got != (s == tt.want) {
					t.Errorf("errors.Is(err, %v) = %v", s, got)
				}
			}
		})
	}
}

func TestAPIError_Error(t *testing.T) {
	e := &APIError{Op: "listing apps", Status: 403, Message: "Admin role required"}
	if got, want := e.Error(), "listing apps: server returned 403: Admin role required"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestClient_RevokeToken(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{name: "200", status: http.StatusOK},
		{name: "404", status: http.StatusNotFound, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := fakeAPI(t, http.MethodDelete, "/api/tokens/tok-1", func(w http.ResponseWriter, r *http.Request) {
				if tt.status == http.StatusOK {
					writeJSONBody(t, w, http.StatusOK, map[string]string{"status": "revoked"})
					return
				}
				writeJSONBody(t, w, tt.status, map[string]string{"message": "Token not found"})
			})
			c := &Client{BaseURL: srv.URL, Token: testSessionToken}
			err := c.RevokeToken(context.Background(), "tok-1")
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("RevokeToken() error = %v", err)
				}
				return
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Status != tt.status {
				t.Fatalf("RevokeToken() error = %v, want *APIError with status %d", err, tt.status)
			}
		})
	}
}

func TestClient_ResponseBodyLimit(t *testing.T) {
	srv := fakeAPI(t, http.MethodGet, "/api/apps", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// The client stops reading after 1 MiB, so this write may fail.
		_, _ = io.WriteString(w, `[{"id":"`+strings.Repeat("a", 2<<20)+`"}]`)
	})
	c := &Client{BaseURL: srv.URL, Token: testSessionToken}
	if _, err := c.ListApps(context.Background()); err == nil {
		t.Fatal("ListApps() error = nil for a body over 1 MiB, want error")
	}
}

func TestCapServerText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"short", "boom", "boom"},
		{"exactly 200", strings.Repeat("a", 200), strings.Repeat("a", 200)},
		{"201", strings.Repeat("a", 201), strings.Repeat("a", 200) + "..."},
		// 199 "a" then a 2-byte "é" across byte 200.
		{"rune boundary", strings.Repeat("a", 199) + "éz", strings.Repeat("a", 199) + "..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := capServerText(tt.in); got != tt.want {
				t.Errorf("capServerText = %q, want %q", got, tt.want)
			}
		})
	}
}
