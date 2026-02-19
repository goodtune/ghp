package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeVaultHandler returns an http.Handler that simulates the Vault HTTP API.
// secrets maps path -> data map (e.g. "apps/myapp" -> {"client_id":"...", ...}).
// listKeys maps path -> list of keys (e.g. "apps" -> ["myapp/", "other/"]).
func fakeVaultHandler(t *testing.T, secrets map[string]map[string]interface{}, listKeys map[string][]string) http.Handler {
	t.Helper()
	return fakeVaultHandlerWithLoginCounter(t, secrets, listKeys, nil)
}

func fakeVaultHandlerWithLoginCounter(t *testing.T, secrets map[string]map[string]interface{}, listKeys map[string][]string, loginCount *atomic.Int64) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Login endpoint
		if r.URL.Path == "/v1/auth/approle/login" && r.Method == "POST" {
			if loginCount != nil {
				loginCount.Add(1)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "test-token",
					"lease_duration": 3600,
				},
			})
			return
		}

		// LIST metadata
		if r.Method == "LIST" {
			// Extract path: /v1/{mount}/metadata/{prefix}/{path}
			path := extractMetadataPath(r.URL.Path)
			keys, ok := listKeys[path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"not found"}})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": keys,
				},
			})
			return
		}

		// GET data
		if r.Method == "GET" {
			path := extractDataPath(r.URL.Path)
			data, ok := secrets[path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"not found"}})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": data,
				},
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	})
}

// extractDataPath extracts the path after /v1/{mount}/data/{prefix}/.
func extractDataPath(urlPath string) string {
	// /v1/secret/data/ghp/apps/myapp -> apps/myapp
	parts := strings.SplitN(urlPath, "/data/", 2)
	if len(parts) < 2 {
		return ""
	}
	// strip prefix: ghp/apps/myapp -> apps/myapp
	sub := parts[1]
	if i := strings.Index(sub, "/"); i >= 0 {
		return sub[i+1:]
	}
	return sub
}

// extractMetadataPath extracts the path after /v1/{mount}/metadata/{prefix}/.
func extractMetadataPath(urlPath string) string {
	parts := strings.SplitN(urlPath, "/metadata/", 2)
	if len(parts) < 2 {
		return ""
	}
	sub := parts[1]
	if i := strings.Index(sub, "/"); i >= 0 {
		return sub[i+1:]
	}
	return sub
}

// newTestClient creates a *Client pointing at the given test server,
// with a pre-set token (bypasses login).
func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	c := &Client{
		addr:       srv.URL,
		token:      "test-token",
		httpClient: srv.Client(),
		logger:     slog.Default(),
		mount:      "secret",
		prefix:     "ghp",
		roleID:     "test-role",
		secretID:   "test-secret",
		tokenTTL:   time.Now().Add(1 * time.Hour),
	}
	return c
}

// --- 3a: Slug validation ---

func TestGetApp_RejectsPathTraversal(t *testing.T) {
	c := newTestClient(t, fakeVaultHandler(t, nil, nil))

	badSlugs := []string{"../etc/passwd", "foo/../bar", "foo/bar", "foo%2Fbar", "..", ".", ""}
	for _, slug := range badSlugs {
		t.Run(slug, func(t *testing.T) {
			_, err := c.GetApp(context.Background(), slug)
			if err == nil {
				t.Errorf("expected error for slug %q, got nil", slug)
			}
		})
	}
}

func TestGetApp_AcceptsValidSlugs(t *testing.T) {
	secrets := map[string]map[string]interface{}{
		"apps/my-app":    {"client_id": "c1", "client_secret": "s1", "app_id": 1.0},
		"apps/app_v2":    {"client_id": "c2", "client_secret": "s2", "app_id": 2.0},
		"apps/MyApp123":  {"client_id": "c3", "client_secret": "s3", "app_id": 3.0},
	}
	c := newTestClient(t, fakeVaultHandler(t, secrets, nil))

	validSlugs := []string{"my-app", "app_v2", "MyApp123"}
	for _, slug := range validSlugs {
		t.Run(slug, func(t *testing.T) {
			app, err := c.GetApp(context.Background(), slug)
			if err != nil {
				t.Fatalf("unexpected error for slug %q: %v", slug, err)
			}
			if app.ClientID == "" {
				t.Errorf("expected non-empty ClientID for slug %q", slug)
			}
		})
	}
}

// --- 3b: login uses json.Marshal ---

func TestNewClient_SpecialCharsInCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			// Read and parse the body — it must be valid JSON.
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("login body is not valid JSON: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if body["role_id"] != `role"with\quotes` {
				t.Errorf("role_id = %q, want %q", body["role_id"], `role"with\quotes`)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "tok",
					"lease_duration": 3600,
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := NewClient(Config{
		Addr:     srv.URL,
		RoleID:   `role"with\quotes`,
		SecretID: `secret"with\backslash`,
	}, slog.Default())
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
}

// --- 3c: Validate token/TTL after login ---

func TestNewClient_EmptyTokenRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token":   "",
				"lease_duration": 3600,
			},
		})
	}))
	defer srv.Close()

	_, err := NewClient(Config{Addr: srv.URL, RoleID: "r", SecretID: "s"}, slog.Default())
	if err == nil {
		t.Fatal("expected error for empty client_token")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error = %q, want mention of 'empty'", err.Error())
	}
}

func TestNewClient_ZeroLeaseDurationRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token":   "tok",
				"lease_duration": 0,
			},
		})
	}))
	defer srv.Close()

	_, err := NewClient(Config{Addr: srv.URL, RoleID: "r", SecretID: "s"}, slog.Default())
	if err == nil {
		t.Fatal("expected error for zero lease_duration")
	}
	if !strings.Contains(err.Error(), "lease") {
		t.Errorf("error = %q, want mention of 'lease'", err.Error())
	}
}

// --- 3d: ensureToken race condition ---

func TestEnsureToken_ConcurrentRenewal(t *testing.T) {
	var loginCount atomic.Int64
	handler := fakeVaultHandlerWithLoginCounter(t, nil, nil, &loginCount)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	c := &Client{
		addr:       srv.URL,
		token:      "old-token",
		httpClient: srv.Client(),
		logger:     slog.Default(),
		mount:      "secret",
		prefix:     "ghp",
		roleID:     "r",
		secretID:   "s",
		tokenTTL:   time.Now().Add(-1 * time.Second), // expired
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.ensureToken(context.Background()); err != nil {
				t.Errorf("ensureToken: %v", err)
			}
		}()
	}
	wg.Wait()

	count := loginCount.Load()
	if count > 2 {
		t.Errorf("login called %d times, want at most 2", count)
	}
}

// --- 3e: app_id string case + error propagation ---

func TestGetApp_AppIDAsString(t *testing.T) {
	secrets := map[string]map[string]interface{}{
		"apps/str-app": {"client_id": "c", "client_secret": "s", "app_id": "12345"},
	}
	c := newTestClient(t, fakeVaultHandler(t, secrets, nil))

	app, err := c.GetApp(context.Background(), "str-app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if app.AppID != 12345 {
		t.Errorf("AppID = %d, want 12345", app.AppID)
	}
}

func TestGetApp_AppIDInvalidString(t *testing.T) {
	secrets := map[string]map[string]interface{}{
		"apps/bad-app": {"client_id": "c", "client_secret": "s", "app_id": "abc"},
	}
	c := newTestClient(t, fakeVaultHandler(t, secrets, nil))

	_, err := c.GetApp(context.Background(), "bad-app")
	if err == nil {
		t.Fatal("expected error for non-numeric app_id string")
	}
}

func TestGetApp_AppIDFloat(t *testing.T) {
	secrets := map[string]map[string]interface{}{
		"apps/float-app": {"client_id": "c", "client_secret": "s", "app_id": 12345.0},
	}
	c := newTestClient(t, fakeVaultHandler(t, secrets, nil))

	app, err := c.GetApp(context.Background(), "float-app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if app.AppID != 12345 {
		t.Errorf("AppID = %d, want 12345", app.AppID)
	}
}

// --- 3f: readKV2 nil data check ---

func TestGetEncryptionKey_NilDataMap(t *testing.T) {
	// Vault returns {"data":{"data":null}} — valid JSON but no data map.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "tok",
					"lease_duration": 3600,
				},
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": nil,
			},
		})
	})
	c := newTestClient(t, handler)

	_, err := c.GetEncryptionKey(context.Background())
	if err == nil {
		t.Fatal("expected error for nil data map")
	}
	if !strings.Contains(err.Error(), "no data") {
		t.Errorf("error = %q, want mention of 'no data'", err.Error())
	}
}

// --- 3g: listKV2 descriptive error on 404 ---

func TestListApps_404ReturnsError(t *testing.T) {
	// listKeys has no "apps" entry, so the fake handler returns 404.
	c := newTestClient(t, fakeVaultHandler(t, nil, nil))

	_, err := c.ListApps(context.Background())
	if err == nil {
		t.Fatal("expected error for 404 on list")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want mention of path", err.Error())
	}
}

// --- 3h: LoadAllApps fails on any app error ---

func TestLoadAllApps_FailsOnBadApp(t *testing.T) {
	secrets := map[string]map[string]interface{}{
		"apps/good-app": {"client_id": "c1", "client_secret": "s1", "app_id": 1.0},
		// bad-app is missing client_id
		"apps/bad-app": {"client_secret": "s2", "app_id": 2.0},
	}
	listKeys := map[string][]string{
		"apps": {"good-app/", "bad-app/"},
	}
	c := newTestClient(t, fakeVaultHandler(t, secrets, listKeys))

	_, err := c.LoadAllApps(context.Background())
	if err == nil {
		t.Fatal("expected error when one app is invalid")
	}
	if !strings.Contains(err.Error(), "bad-app") {
		t.Errorf("error = %q, want mention of 'bad-app'", err.Error())
	}
}

func TestLoadAllApps_AllValid(t *testing.T) {
	secrets := map[string]map[string]interface{}{
		"apps/app-a": {"client_id": "c1", "client_secret": "s1", "app_id": 1.0},
		"apps/app-b": {"client_id": "c2", "client_secret": "s2", "app_id": 2.0},
	}
	listKeys := map[string][]string{
		"apps": {"app-a/", "app-b/"},
	}
	c := newTestClient(t, fakeVaultHandler(t, secrets, listKeys))

	apps, err := c.LoadAllApps(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(apps) != 2 {
		t.Errorf("got %d apps, want 2", len(apps))
	}
}

// Prevent unused import of fmt.
var _ = fmt.Sprintf
