package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/database"
	ghpgithub "github.com/goodtune/ghp/internal/github"
	"github.com/goodtune/ghp/internal/token"
)

func TestHandleCreateToken_BodyTooLarge(t *testing.T) {
	a := &API{}

	// Body must be valid-looking JSON so the decoder reads past the 1 MB limit.
	body := strings.NewReader(`{"repository":"` + strings.Repeat("x", maxRequestBodySize) + `"}`)
	req := httptest.NewRequest("POST", "/api/tokens", body)
	w := httptest.NewRecorder()
	a.handleCreateToken(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected %d, got %d", http.StatusRequestEntityTooLarge, w.Code)
	}
}

func TestHandleCreateToken_InvalidJSON(t *testing.T) {
	a := &API{}

	req := httptest.NewRequest("POST", "/api/tokens", strings.NewReader("not valid json"))
	w := httptest.NewRecorder()
	a.handleCreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestTruncateSessionID(t *testing.T) {
	t.Run("short input unchanged", func(t *testing.T) {
		in := "abc-123"
		if got := truncateSessionID(in); got != in {
			t.Errorf("expected %q, got %q", in, got)
		}
	})
	t.Run("exact limit unchanged", func(t *testing.T) {
		in := strings.Repeat("x", maxSessionIDLength)
		if got := truncateSessionID(in); got != in {
			t.Errorf("expected len %d, got len %d", len(in), len(got))
		}
	})
	t.Run("over limit truncated", func(t *testing.T) {
		in := strings.Repeat("x", maxSessionIDLength+50)
		got := truncateSessionID(in)
		if len(got) != maxSessionIDLength {
			t.Errorf("expected len %d, got len %d", maxSessionIDLength, len(got))
		}
	})
	t.Run("empty input unchanged", func(t *testing.T) {
		if got := truncateSessionID(""); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})
	t.Run("multi-byte rune not split", func(t *testing.T) {
		// Build a string of 3-byte runes (e.g. '€') that exceeds the limit.
		rune3 := "€" // 3 bytes
		in := strings.Repeat(rune3, maxSessionIDLength)
		got := truncateSessionID(in)
		if len(got) > maxSessionIDLength {
			t.Errorf("result exceeds limit: len %d > %d", len(got), maxSessionIDLength)
		}
		// Must be valid UTF-8 with no partial rune.
		if !utf8.ValidString(got) {
			t.Error("result is not valid UTF-8")
		}
		// Length should be a multiple of 3 (each rune is 3 bytes).
		if len(got)%3 != 0 {
			t.Errorf("expected length multiple of 3, got %d", len(got))
		}
	})
}

func TestOAuthScopesToPermissions(t *testing.T) {
	tests := []struct {
		name        string
		scopeHeader string
		wantKeys    []string // permission keys that must be present
		wantAbsent  []string // permission keys that must NOT be present
		wantLevels  map[string]string
	}{
		{
			name:        "empty header returns no permissions",
			scopeHeader: "",
			wantKeys:    nil,
			wantAbsent:  []string{"contents", "pull_requests"},
		},
		{
			name:        "repo scope grants core repo permissions",
			scopeHeader: "repo",
			wantKeys:    []string{"contents", "pull_requests", "issues", "statuses", "checks", "actions", "metadata"},
			wantLevels: map[string]string{
				"contents":      "write",
				"pull_requests": "write",
				"issues":        "write",
				"statuses":      "write",
				"checks":        "write",
				"actions":       "read", // no workflow scope
				"metadata":      "read",
			},
		},
		{
			name:        "repo + workflow grants actions write",
			scopeHeader: "repo, workflow",
			wantLevels: map[string]string{
				"contents": "write",
				"actions":  "write",
			},
		},
		{
			name:        "public_repo grants same permissions as repo",
			scopeHeader: "public_repo",
			wantKeys:    []string{"contents", "pull_requests", "issues"},
		},
		{
			name:        "security_events adds security permissions",
			scopeHeader: "repo, security_events",
			wantKeys:    []string{"security_events", "vulnerability_alerts"},
			wantLevels: map[string]string{
				"security_events":      "write",
				"vulnerability_alerts": "write",
			},
		},
		{
			name:        "write:packages grants packages write",
			scopeHeader: "repo, write:packages",
			wantLevels:  map[string]string{"packages": "write"},
		},
		{
			name:        "read:packages grants packages read",
			scopeHeader: "repo, read:packages",
			wantLevels:  map[string]string{"packages": "read"},
		},
		{
			name:        "read:org grants members read",
			scopeHeader: "repo, read:org",
			wantLevels:  map[string]string{"members": "read"},
		},
		{
			name:        "write:org grants members write",
			scopeHeader: "repo, write:org",
			wantLevels:  map[string]string{"members": "write"},
		},
		{
			name:        "read:discussion grants discussions read",
			scopeHeader: "repo, read:discussion",
			wantLevels:  map[string]string{"discussions": "read"},
		},
		{
			name:        "write:discussion grants discussions write",
			scopeHeader: "repo, write:discussion",
			wantLevels:  map[string]string{"discussions": "write"},
		},
		{
			name:        "repo:status alone grants statuses only",
			scopeHeader: "repo:status",
			wantKeys:    []string{"statuses", "metadata"},
			wantAbsent:  []string{"contents", "pull_requests", "issues"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := oauthScopesToPermissions(tc.scopeHeader)

			for _, key := range tc.wantKeys {
				if _, ok := got[key]; !ok {
					t.Errorf("expected permission %q to be present, got keys: %v", key, sortedKeys(got))
				}
			}
			for _, key := range tc.wantAbsent {
				if _, ok := got[key]; ok {
					t.Errorf("expected permission %q to be absent, got keys: %v", key, sortedKeys(got))
				}
			}
			for perm, level := range tc.wantLevels {
				if got[perm] != level {
					t.Errorf("expected %q = %q, got %q", perm, level, got[perm])
				}
			}
		})
	}
}

func TestDefaultPermissions(t *testing.T) {
	perms := defaultPermissions()
	required := []string{"contents", "pull_requests", "issues", "statuses", "checks", "actions", "metadata"}
	for _, key := range required {
		if _, ok := perms[key]; !ok {
			t.Errorf("defaultPermissions() missing key %q", key)
		}
	}
	// pull_requests must be present (not the legacy "pulls" key).
	if _, ok := perms["pulls"]; ok {
		t.Error("defaultPermissions() must not contain legacy 'pulls' key")
	}
	// Verify it round-trips through reflect (no nil map).
	if !reflect.DeepEqual(perms, defaultPermissions()) {
		t.Error("defaultPermissions() is not deterministic")
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// adminSession returns a minimal admin Session for injecting into test contexts.
func adminSession() *auth.Session {
	return &auth.Session{
		UserID:    "user-1",
		Username:  "admin",
		Role:      "admin",
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func TestHandleCreateToken_AppRecordIDRejectedForProxyToken(t *testing.T) {
	a := &API{}

	body := strings.NewReader(`{"type":"","app_record_id":"some-uuid"}`)
	req := httptest.NewRequest("POST", "/api/tokens", body)
	w := httptest.NewRecorder()
	a.handleCreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	if !strings.Contains(w.Body.String(), "app_record_id is only valid for agent tokens") {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

func TestHandleCreateToken_MultiAppNoDefault_RequiresAppRecordID(t *testing.T) {
	// Two apps loaded, neither is default → agent token without explicit
	// app_record_id must be rejected with a clear 400.
	registry := ghpgithub.NewRegistryWithState([]string{"app-1", "app-2"}, "")
	a := &API{appRegistry: registry, cfg: &config.Config{}}

	body := strings.NewReader(`{"type":"agent","installation_id":1}`)
	req := httptest.NewRequest("POST", "/api/tokens", body)
	req = req.WithContext(auth.NewContextWithSession(req.Context(), adminSession()))
	w := httptest.NewRecorder()
	a.handleCreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	if !strings.Contains(w.Body.String(), "app_record_id is required") {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

func TestHandleCreateApp_BodyTooLarge(t *testing.T) {
	a := &API{}

	body := strings.NewReader(`{"name":"` + strings.Repeat("x", maxRequestBodySize) + `"}`)
	req := httptest.NewRequest("POST", "/api/apps", body)
	w := httptest.NewRecorder()
	a.handleCreateApp(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected %d, got %d", http.StatusRequestEntityTooLarge, w.Code)
	}
}

func TestHandleCreateApp_RequiredFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
		msg  string
	}{
		{"missing name", `{"app_id":1,"private_key":"key"}`, http.StatusBadRequest, "name is required"},
		{"missing app_id", `{"name":"myapp","private_key":"key"}`, http.StatusBadRequest, "app_id must be a positive integer"},
		{"negative app_id", `{"name":"myapp","app_id":-1,"private_key":"key"}`, http.StatusBadRequest, "app_id must be a positive integer"},
		{"missing private_key", `{"name":"myapp","app_id":1}`, http.StatusBadRequest, "private_key is required"},
		{"http base_url", `{"name":"myapp","app_id":1,"private_key":"key","base_url":"http://example.com"}`, http.StatusBadRequest, "scheme must be https"},
		{"base_url with query", `{"name":"myapp","app_id":1,"private_key":"key","base_url":"https://example.com?q=1"}`, http.StatusBadRequest, "query string is not allowed"},
		{"base_url with fragment", `{"name":"myapp","app_id":1,"private_key":"key","base_url":"https://example.com#frag"}`, http.StatusBadRequest, "fragment is not allowed"},
		{"base_url with userinfo", `{"name":"myapp","app_id":1,"private_key":"key","base_url":"https://user:pass@example.com"}`, http.StatusBadRequest, "userinfo is not allowed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := &API{}
			req := httptest.NewRequest("POST", "/api/apps", strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			a.handleCreateApp(w, req)
			if w.Code != tc.want {
				t.Errorf("expected %d, got %d", tc.want, w.Code)
			}
			if !strings.Contains(w.Body.String(), tc.msg) {
				t.Errorf("expected %q in body, got: %s", tc.msg, w.Body.String())
			}
		})
	}
}

func TestHandleUpdateApp_BodyTooLarge(t *testing.T) {
	a := &API{}

	body := strings.NewReader(`{"name":"` + strings.Repeat("x", maxRequestBodySize) + `"}`)
	req := httptest.NewRequest("PUT", "/api/apps/some-id", body)
	w := httptest.NewRecorder()
	a.handleUpdateApp(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected %d, got %d", http.StatusRequestEntityTooLarge, w.Code)
	}
}

func TestHandleCreateCachedRepo_BodyTooLarge(t *testing.T) {
	a := &API{}

	body := strings.NewReader(`{"owner":"` + strings.Repeat("x", maxRequestBodySize) + `"}`)
	req := httptest.NewRequest("POST", "/api/cached-repos", body)
	w := httptest.NewRecorder()
	a.handleCreateCachedRepo(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected %d, got %d", http.StatusRequestEntityTooLarge, w.Code)
	}
}

func TestHandleCreateCachedRepo_InvalidJSON(t *testing.T) {
	a := &API{}

	req := httptest.NewRequest("POST", "/api/cached-repos", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	a.handleCreateCachedRepo(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHandleCreateCachedRepo_RequiredFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
		msg  string
	}{
		{"missing owner", `{"name":"myrepo"}`, http.StatusBadRequest, "owner is required"},
		{"missing name", `{"owner":"myorg"}`, http.StatusBadRequest, "name is required"},
		{"missing both", `{}`, http.StatusBadRequest, "owner is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := &API{}
			req := httptest.NewRequest("POST", "/api/cached-repos", strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			a.handleCreateCachedRepo(w, req)
			if w.Code != tc.want {
				t.Errorf("expected %d, got %d", tc.want, w.Code)
			}
			if !strings.Contains(w.Body.String(), tc.msg) {
				t.Errorf("expected %q in body, got: %s", tc.msg, w.Body.String())
			}
		})
	}
}

func TestHandleGetCachedRepo_InvalidUUID(t *testing.T) {
	a := &API{}

	req := httptest.NewRequest("GET", "/api/cached-repos/not-a-uuid", nil)
	req.SetPathValue("id", "not-a-uuid")
	w := httptest.NewRecorder()
	a.handleGetCachedRepo(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid cached repository ID format") {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

func TestHandleDeleteCachedRepo_InvalidUUID(t *testing.T) {
	a := &API{}

	req := httptest.NewRequest("DELETE", "/api/cached-repos/bad-id", nil)
	req.SetPathValue("id", "bad-id")
	w := httptest.NewRecorder()
	a.handleDeleteCachedRepo(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHandleUpdateCachedRepo_BodyTooLarge(t *testing.T) {
	a := &API{}

	body := strings.NewReader(`{"enabled":` + strings.Repeat(" ", maxRequestBodySize) + `true}`)
	req := httptest.NewRequest("PATCH", "/api/cached-repos/some-id", body)
	w := httptest.NewRecorder()
	a.handleUpdateCachedRepo(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected %d, got %d", http.StatusRequestEntityTooLarge, w.Code)
	}
}

func TestHandleUpdateCachedRepo_InvalidUUID(t *testing.T) {
	a := &API{}

	req := httptest.NewRequest("PATCH", "/api/cached-repos/bad-id", strings.NewReader(`{"enabled":false}`))
	req.SetPathValue("id", "bad-id")
	w := httptest.NewRecorder()
	a.handleUpdateCachedRepo(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func newTestAPIWithStore(t *testing.T) *API {
	t.Helper()
	store, err := database.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	migrator := database.NewMigrator(store, "sqlite")
	if err := migrator.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &API{
		store:  store,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestCachedReposCRUD(t *testing.T) {
	a := newTestAPIWithStore(t)

	// Create
	ctx := auth.NewContextWithSession(context.Background(), &auth.Session{Username: "admin"})
	req := httptest.NewRequest("POST", "/api/cached-repos",
		strings.NewReader(`{"owner":"MyOrg","name":"MyRepo"}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	a.handleCreateCachedRepo(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
	}
	var created map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	id := created["id"].(string)
	// Verify case normalization.
	if created["owner"].(string) != "myorg" {
		t.Errorf("owner not normalized: got %q", created["owner"])
	}
	if created["name"].(string) != "myrepo" {
		t.Errorf("name not normalized: got %q", created["name"])
	}

	// List
	req = httptest.NewRequest("GET", "/api/cached-repos", nil)
	w = httptest.NewRecorder()
	a.handleListCachedRepos(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected %d, got %d", http.StatusOK, w.Code)
	}
	var list []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list: expected 1 item, got %d", len(list))
	}

	// Get
	req = httptest.NewRequest("GET", "/api/cached-repos/"+id, nil)
	req.SetPathValue("id", id)
	w = httptest.NewRecorder()
	a.handleGetCachedRepo(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get: expected %d, got %d", http.StatusOK, w.Code)
	}

	// Update (disable)
	req = httptest.NewRequest("PATCH", "/api/cached-repos/"+id,
		strings.NewReader(`{"enabled":false}`)).WithContext(ctx)
	req.SetPathValue("id", id)
	w = httptest.NewRecorder()
	a.handleUpdateCachedRepo(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("update: expected %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Delete
	req = httptest.NewRequest("DELETE", "/api/cached-repos/"+id, nil).WithContext(ctx)
	req.SetPathValue("id", id)
	w = httptest.NewRecorder()
	a.handleDeleteCachedRepo(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: expected %d, got %d", http.StatusOK, w.Code)
	}

	// Verify deleted
	req = httptest.NewRequest("GET", "/api/cached-repos", nil)
	w = httptest.NewRecorder()
	a.handleListCachedRepos(w, req)
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("list after delete: expected 0 items, got %d", len(list))
	}
}

func TestCachedRepos_DuplicateCreate409(t *testing.T) {
	a := newTestAPIWithStore(t)
	ctx := auth.NewContextWithSession(context.Background(), &auth.Session{Username: "admin"})

	// First create succeeds.
	req := httptest.NewRequest("POST", "/api/cached-repos",
		strings.NewReader(`{"owner":"org","name":"repo"}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	a.handleCreateCachedRepo(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	// Duplicate create returns 409.
	req = httptest.NewRequest("POST", "/api/cached-repos",
		strings.NewReader(`{"owner":"org","name":"repo"}`)).WithContext(ctx)
	w = httptest.NewRecorder()
	a.handleCreateCachedRepo(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate create: expected %d, got %d: %s", http.StatusConflict, w.Code, w.Body.String())
	}
}

func timePtrServer(t time.Time) *time.Time { return &t }

// newTestAPIFull builds an API with a real SQLite store, token service, and
// discard audit log — enough to test handlers that touch all three.
func newTestAPIFull(t *testing.T) *API {
	t.Helper()
	store, err := database.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	migrator := database.NewMigrator(store, "sqlite")
	if err := migrator.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ts := token.NewService(store, 24*time.Hour, false)
	return &API{
		store:        store,
		tokenService: ts,
		auditLog:     newAuditLogWriter(io.Discard),
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestHandleUpdateTokenScopes_InvalidUUID(t *testing.T) {
	a := &API{}
	req := httptest.NewRequest("PATCH", "/api/tokens/not-a-uuid", strings.NewReader(`{"repositories":[]}`))
	req.SetPathValue("id", "not-a-uuid")
	req = req.WithContext(auth.NewContextWithSession(req.Context(), adminSession()))
	w := httptest.NewRecorder()
	a.handleUpdateTokenScopes(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleUpdateTokenScopes_NotFound(t *testing.T) {
	a := newTestAPIFull(t)
	body := strings.NewReader(`{"repositories":["org/repo"]}`)
	req := httptest.NewRequest("PATCH", "/api/tokens/00000000-0000-0000-0000-000000000000", body)
	req.SetPathValue("id", "00000000-0000-0000-0000-000000000000")
	req = req.WithContext(auth.NewContextWithSession(req.Context(), adminSession()))
	w := httptest.NewRecorder()
	a.handleUpdateTokenScopes(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleUpdateTokenScopes_InvalidScopeLevel(t *testing.T) {
	a := newTestAPIFull(t)

	exp := timePtrServer(time.Now().Add(time.Hour))
	pt := &database.ProxyToken{
		TokenHash:   "hash_scope_level_test",
		TokenPrefix: "ghx_sl1",
		TokenType:   "proxy",
		ExpiresAt:   exp,
	}
	if err := a.store.CreateProxyToken(context.Background(), pt); err != nil {
		t.Fatalf("create token: %v", err)
	}

	body := strings.NewReader(`{"scopes":{"contents":"admin"}}`)
	req := httptest.NewRequest("PATCH", "/api/tokens/"+pt.ID, body)
	req.SetPathValue("id", pt.ID)
	req = req.WithContext(auth.NewContextWithSession(req.Context(), adminSession()))
	w := httptest.NewRecorder()
	a.handleUpdateTokenScopes(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleUpdateTokenScopes_RevokedToken(t *testing.T) {
	a := newTestAPIFull(t)

	exp := timePtrServer(time.Now().Add(time.Hour))
	pt := &database.ProxyToken{
		TokenHash:   "hash_revoked_scope_test",
		TokenPrefix: "ghx_rv1",
		TokenType:   "proxy",
		ExpiresAt:   exp,
	}
	if err := a.store.CreateProxyToken(context.Background(), pt); err != nil {
		t.Fatalf("create token: %v", err)
	}
	if err := a.store.RevokeProxyToken(context.Background(), pt.ID); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	body := strings.NewReader(`{"repositories":["org/repo"]}`)
	req := httptest.NewRequest("PATCH", "/api/tokens/"+pt.ID, body)
	req.SetPathValue("id", pt.ID)
	req = req.WithContext(auth.NewContextWithSession(req.Context(), adminSession()))
	w := httptest.NewRecorder()
	a.handleUpdateTokenScopes(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleUpdateTokenScopes_HappyPath(t *testing.T) {
	a := newTestAPIFull(t)

	exp := timePtrServer(time.Now().Add(time.Hour))
	pt := &database.ProxyToken{
		TokenHash:    "hash_scope_update_ok",
		TokenPrefix:  "ghx_ok1",
		TokenType:    "proxy",
		Repositories: json.RawMessage(`["org/old"]`),
		Scopes:       json.RawMessage(`{"contents":"read"}`),
		ExpiresAt:    exp,
	}
	if err := a.store.CreateProxyToken(context.Background(), pt); err != nil {
		t.Fatalf("create token: %v", err)
	}

	body := strings.NewReader(`{"repositories":["org/new"],"scopes":{"contents":"write"}}`)
	req := httptest.NewRequest("PATCH", "/api/tokens/"+pt.ID, body)
	req.SetPathValue("id", pt.ID)
	req = req.WithContext(auth.NewContextWithSession(req.Context(), adminSession()))
	w := httptest.NewRecorder()
	a.handleUpdateTokenScopes(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	repos, _ := resp["repositories"].([]interface{})
	if len(repos) != 1 || repos[0] != "org/new" {
		t.Errorf("repositories = %v, want [org/new]", repos)
	}
	scopes, _ := resp["scopes"].(map[string]interface{})
	if scopes["contents"] != "write" {
		t.Errorf("scopes[contents] = %v, want write", scopes["contents"])
	}
}
