package exec

import (
	"context"
	"net/http"
	"testing"

	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

// TestREST_EmptyHeaderRemovesIt: a header given with an empty value is
// removed, so Authorization: "" sends an anonymous request (BORDER-C46,
// ENT-C50 unauthenticated_denied).
func TestREST_EmptyHeaderRemovesIt(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		wantAuth bool
		wantGP   string
	}{
		{"token by default", nil, true, ""},
		{"empty Authorization removes it", map[string]string{"Authorization": "", "Git-Protocol": "version=2"}, false, "version=2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hasAuth bool
			var gp string
			env, _, tok := newEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, hasAuth = r.Header["Authorization"]
				gp = r.Header.Get("Git-Protocol")
			}))
			s := &scenario.Scenario{ID: "x", Kind: "rest", Path: "/user", Headers: tt.headers}
			if _, err := (restExecutor{}).Run(context.Background(), s, tok, env); err != nil {
				t.Fatal(err)
			}
			if hasAuth != tt.wantAuth || gp != tt.wantGP {
				t.Errorf("Authorization present=%v Git-Protocol=%q, want %v %q", hasAuth, gp, tt.wantAuth, tt.wantGP)
			}
		})
	}
}
