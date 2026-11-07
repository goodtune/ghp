package expect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func denialBody(t *testing.T, msg string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"message": msg, "documentation_url": DocsURLREST})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestIsGHPDenial_ScopedTokenMessages pins the exact production strings
// added in 0.24.0 (internal/proxy/scope.go, internal/proxy/passthrough.go).
func TestIsGHPDenial_ScopedTokenMessages(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"repo-restricted non-repo path", "Token is restricted to specific repositories; GET /repositories/123 does not target a repository"},
		{"unmapped endpoint", "Endpoint GET /foo/bar is not permitted for scoped tokens (no scope rule matches)"},
		{"passthrough unmapped", `Token is scoped; GET "/o/r/settings" on github.com is not mapped to a repository permission`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !IsGHPDenial(denialBody(t, tt.msg)) {
				t.Errorf("IsGHPDenial(%q) = false, want true", tt.msg)
			}
			if !IsGHPDenialResponse(403, denialBody(t, tt.msg)) {
				t.Errorf("IsGHPDenialResponse(403, %q) = false, want true", tt.msg)
			}
		})
	}
}

// TestIsGHPDenial_NotTooBroad guards the "Endpoint" pattern against
// matching a GitHub message that merely starts with the same word.
func TestIsGHPDenial_NotTooBroad(t *testing.T) {
	for _, msg := range []string{"Endpoint moved", "Not Found", "Resource not accessible by integration"} {
		if IsGHPDenial(denialBody(t, msg)) {
			t.Errorf("IsGHPDenial(%q) = true, want false", msg)
		}
	}
}

var (
	// writeError(w, http.StatusForbidden|StatusUnauthorized, "literal"), or
	// the same with fmt.Sprintf("literal", ...). 5xx errors are not denials.
	writeErrorLit = regexp.MustCompile(`writeError\([^,]+,\s*http\.Status(?:Forbidden|Unauthorized),\s*(?:fmt\.Sprintf\(\s*)?"((?:[^"\\]|\\.)*)"`)
	// Any literal shaped like a token denial, wherever it is built
	// (constants, restDecision.message, and so on).
	tokenLit = regexp.MustCompile(`"((?:Token |Endpoint )(?:[^"\\]|\\.)*)"`)
	verb     = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z]`)
)

// TestDenialPrefixes_CoverProxySource scans internal/proxy for denial
// message literals and fails when the rig would not classify one as a GHP
// denial. Literals are found by two cheap patterns (writeError arguments
// and "Token ..."/"Endpoint ..." literals), so messages built in other
// ways are not covered.
func TestDenialPrefixes_CoverProxySource(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "internal", "proxy", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no internal/proxy sources found")
	}
	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var lits []string
		for _, m := range writeErrorLit.FindAllStringSubmatch(string(src), -1) {
			lits = append(lits, m[1])
		}
		for _, m := range tokenLit.FindAllStringSubmatch(string(src), -1) {
			lits = append(lits, m[1])
		}
		for _, lit := range lits {
			if strings.HasPrefix(lit, "Token type ") && !strings.Contains(lit, "border policy") {
				continue
			}
			msg := verb.ReplaceAllString(strings.ReplaceAll(lit, `\"`, `"`), "X")
			seen++
			if !IsGHPDenial(denialBody(t, msg)) {
				t.Errorf("%s: denial message %q is not recognised by denialPrefixes", filepath.Base(f), lit)
			}
		}
	}
	if seen == 0 {
		t.Fatal("scan found no denial literals; the patterns are stale")
	}
}
