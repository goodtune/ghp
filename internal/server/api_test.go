package server

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
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
