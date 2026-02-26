package token

import "testing"

func TestPermissionRegistryContainsPullRequests(t *testing.T) {
	p, ok := PermissionByKey("pull_requests")
	if !ok {
		t.Fatal("pull_requests not found in registry")
	}
	if p.DisplayName != "Pull requests" {
		t.Errorf("display name = %q, want %q", p.DisplayName, "Pull requests")
	}
}

func TestPermissionRegistryCommonSubset(t *testing.T) {
	common := CommonPermissions()
	if len(common) == 0 {
		t.Fatal("common permissions list is empty")
	}
	keys := make(map[string]bool)
	for _, p := range common {
		keys[p.Key] = true
	}
	for _, key := range []string{"actions", "checks", "contents", "issues", "metadata", "pull_requests", "statuses"} {
		if !keys[key] {
			t.Errorf("common permissions missing %q", key)
		}
	}
}

func TestAllPermissionsMatchesSDK(t *testing.T) {
	all := AllPermissions()
	if len(all) < 30 {
		t.Errorf("expected 30+ permissions from SDK, got %d", len(all))
	}
}
