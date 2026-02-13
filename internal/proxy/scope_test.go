package proxy

import (
	"testing"
)

func TestEndpointScope(t *testing.T) {
	tests := []struct {
		method     string
		path       string
		wantPerm   string
		wantLevel  string
	}{
		{"GET", "/repos/org/repo/pulls", "pulls", "read"},
		{"POST", "/repos/org/repo/pulls", "pulls", "write"},
		{"GET", "/repos/org/repo/pulls/123", "pulls", "read"},
		{"PATCH", "/repos/org/repo/pulls/123", "pulls", "write"},
		{"GET", "/repos/org/repo/contents/README.md", "contents", "read"},
		{"PUT", "/repos/org/repo/contents/README.md", "contents", "write"},
		{"GET", "/repos/org/repo/issues", "issues", "read"},
		{"POST", "/repos/org/repo/issues", "issues", "write"},
		{"POST", "/repos/org/repo/issues/42/comments", "issues", "write"},
		{"GET", "/repos/org/repo/issues/42/comments", "issues", "read"},
		{"GET", "/repos/org/repo/commits", "contents", "read"},
		{"GET", "/repos/org/repo/branches", "contents", "read"},
		{"GET", "/repos/org/repo", "metadata", "read"},
		{"GET", "/user", "metadata", "read"},
		{"GET", "/repos/org/repo/pulls/1/files", "pulls", "read"},
		{"POST", "/repos/org/repo/pulls/1/reviews", "pulls", "write"},
		// Unknown endpoint.
		{"GET", "/unknown/path", "", ""},
	}

	for _, tt := range tests {
		perm, level := EndpointScope(tt.method, tt.path)
		if perm != tt.wantPerm || level != tt.wantLevel {
			t.Errorf("EndpointScope(%q, %q) = (%q, %q), want (%q, %q)",
				tt.method, tt.path, perm, level, tt.wantPerm, tt.wantLevel)
		}
	}
}

func TestExtractRepoFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/repos/goodtune/myproject/pulls", "goodtune/myproject"},
		{"/repos/org/repo/contents/README.md", "org/repo"},
		{"/repos/org/repo", "org/repo"},
		{"/user", ""},
		{"/", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := ExtractRepoFromPath(tt.path)
		if got != tt.want {
			t.Errorf("ExtractRepoFromPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}
