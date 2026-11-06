package proxy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/permissions"
)

// TestEnforcementPermissionsAreCanonical fails when an enforcement table uses
// a permission name that token creation would reject (#293), so the
// canonical list in internal/permissions cannot drift from enforcement.
func TestEnforcementPermissionsAreCanonical(t *testing.T) {
	check := func(where, name, level string) {
		t.Helper()
		if err := permissions.Validate(name, level); err != nil {
			t.Errorf("%s: %v", where, err)
		}
	}
	for _, r := range rules {
		check("scope.go rule "+r.pattern.String(), r.permission, r.level)
	}
	for f, req := range fieldScopeRequirements {
		check("fieldScopeRequirements."+f, req.permission, req.level)
	}
	for m, req := range mutationScopeRequirements {
		check("mutationScopeRequirements."+m, req.permission, req.level)
	}
	for _, c := range []struct{ method, path string }{
		{"POST", "/o/r.git/git-receive-pack"},
		{"POST", "/o/r.git/git-upload-pack"},
	} {
		_, perm, level := GitSmartHTTPScope(c.method, c.path, "")
		check("GitSmartHTTPScope "+c.path, perm, level)
	}
}

func TestParseScopeInfo_StoredUnknownNameResolvesAndWarnsOnce(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	origWarner, origLogger := storedScopeWarner, scopeWarnLogger
	storedScopeWarner = &scopeNameWarner{}
	scopeWarnLogger = func() *slog.Logger { return logger }
	t.Cleanup(func() { storedScopeWarner, scopeWarnLogger = origWarner, origLogger })

	scopes, _ := json.Marshal(map[string]string{"pulls": "write", "contents": "read"})
	pt := &database.ProxyToken{ID: "t1", Repositories: json.RawMessage("null"), Scopes: scopes}

	for i := 0; i < 3; i++ {
		si, err := parseScopeInfo(pt)
		if err != nil {
			t.Fatalf("parseScopeInfo: %v", err)
		}
		if si.Scopes["pulls"] != "write" {
			t.Fatalf("stored scope not preserved: %v", si.Scopes)
		}
	}
	if n := strings.Count(buf.String(), "unknown permission"); n != 1 {
		t.Errorf("expected exactly one warning, got %d: %s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "permission=pulls") {
		t.Errorf("warning should name the permission: %s", buf.String())
	}
	if strings.Contains(buf.String(), "permission=contents") {
		t.Errorf("canonical name should not warn: %s", buf.String())
	}
}
