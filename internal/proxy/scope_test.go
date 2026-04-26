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
		{"GET", "/repos/org/repo/pulls", "pull_requests", "read"},
		{"POST", "/repos/org/repo/pulls", "pull_requests", "write"},
		{"GET", "/repos/org/repo/pulls/123", "pull_requests", "read"},
		{"PATCH", "/repos/org/repo/pulls/123", "pull_requests", "write"},
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
		{"GET", "/repos/org/repo/pulls/1/files", "pull_requests", "read"},
		{"POST", "/repos/org/repo/pulls/1/reviews", "pull_requests", "write"},

		// Secrets
		{"GET", "/repos/org/repo/actions/secrets", "secrets", "read"},
		{"GET", "/repos/org/repo/actions/secrets/MY_SECRET", "secrets", "read"},
		{"PUT", "/repos/org/repo/actions/secrets/MY_SECRET", "secrets", "write"},
		{"DELETE", "/repos/org/repo/actions/secrets/MY_SECRET", "secrets", "write"},

		// Workflows — must not fall through to the actions catch-all.
		{"GET", "/repos/org/repo/actions/workflows", "workflows", "read"},
		{"GET", "/repos/org/repo/actions/workflows/ci.yml", "workflows", "read"},
		{"POST", "/repos/org/repo/actions/workflows/ci.yml/dispatches", "workflows", "write"},
		{"PUT", "/repos/org/repo/actions/workflows/ci.yml/enable", "workflows", "write"},
		{"PUT", "/repos/org/repo/actions/workflows/ci.yml/disable", "workflows", "write"},

		// Actions (runs/jobs — after specific paths)
		{"GET", "/repos/org/repo/actions/runs", "actions", "read"},
		{"POST", "/repos/org/repo/actions/runs/123/rerun", "actions", "write"},
		{"POST", "/repos/org/repo/actions/runs/123/cancel", "actions", "write"},
		{"POST", "/repos/org/repo/actions/jobs/456/rerun", "actions", "write"},

		// Deployments
		{"GET", "/repos/org/repo/deployments", "deployments", "read"},
		{"POST", "/repos/org/repo/deployments", "deployments", "write"},
		{"GET", "/repos/org/repo/deployments/1/statuses", "deployments", "read"},
		{"POST", "/repos/org/repo/deployments/1/statuses", "deployments", "write"},

		// Environments
		{"GET", "/repos/org/repo/environments", "environments", "read"},
		{"GET", "/repos/org/repo/environments/prod", "environments", "read"},
		{"PUT", "/repos/org/repo/environments/prod", "environments", "write"},
		{"DELETE", "/repos/org/repo/environments/prod", "environments", "write"},

		// Pages
		{"GET", "/repos/org/repo/pages", "pages", "read"},
		{"POST", "/repos/org/repo/pages", "pages", "write"},
		{"PUT", "/repos/org/repo/pages", "pages", "write"},
		{"DELETE", "/repos/org/repo/pages", "pages", "write"},
		{"POST", "/repos/org/repo/pages/builds", "pages", "write"},
		{"GET", "/repos/org/repo/pages/builds", "pages", "read"},
		{"GET", "/repos/org/repo/pages/health", "pages", "read"},

		// Packages
		{"GET", "/orgs/myorg/packages", "packages", "read"},
		{"GET", "/orgs/myorg/packages/npm/mypkg", "packages", "read"},
		{"DELETE", "/orgs/myorg/packages/npm/mypkg", "packages", "write"},
		{"GET", "/users/alice/packages", "packages", "read"},

		// Discussions
		{"GET", "/repos/org/repo/discussions", "discussions", "read"},
		{"POST", "/repos/org/repo/discussions", "discussions", "write"},
		{"PATCH", "/repos/org/repo/discussions/1", "discussions", "write"},
		{"DELETE", "/repos/org/repo/discussions/1", "discussions", "write"},
		{"POST", "/repos/org/repo/discussions/1/comments", "discussions", "write"},

		// Repository webhooks
		{"GET", "/repos/org/repo/hooks", "repository_hooks", "read"},
		{"POST", "/repos/org/repo/hooks", "repository_hooks", "write"},
		{"PATCH", "/repos/org/repo/hooks/1", "repository_hooks", "write"},
		{"DELETE", "/repos/org/repo/hooks/1", "repository_hooks", "write"},
		{"POST", "/repos/org/repo/hooks/1/pings", "repository_hooks", "write"},
		{"POST", "/repos/org/repo/hooks/1/tests", "repository_hooks", "write"},
		{"POST", "/repos/org/repo/hooks/1/deliveries/abc/attempts", "repository_hooks", "write"},
		{"GET", "/repos/org/repo/hooks/1/deliveries", "repository_hooks", "read"},

		// Secret scanning alerts
		{"GET", "/repos/org/repo/secret-scanning/alerts", "secret_scanning_alerts", "read"},
		{"GET", "/repos/org/repo/secret-scanning/alerts/1", "secret_scanning_alerts", "read"},
		{"PATCH", "/repos/org/repo/secret-scanning/alerts/1", "secret_scanning_alerts", "write"},

		// Code scanning and security advisories
		{"GET", "/repos/org/repo/code-scanning/alerts", "security_events", "read"},
		{"GET", "/repos/org/repo/code-scanning/alerts/42", "security_events", "read"},
		{"PATCH", "/repos/org/repo/code-scanning/alerts/42", "security_events", "write"},
		{"POST", "/repos/org/repo/code-scanning/sarifs", "security_events", "write"},
		{"DELETE", "/repos/org/repo/code-scanning/analyses/7", "security_events", "write"},
		{"GET", "/repos/org/repo/security-advisories", "security_events", "read"},
		{"POST", "/repos/org/repo/security-advisories", "security_events", "write"},
		{"PATCH", "/repos/org/repo/security-advisories/GHSA-xxxx", "security_events", "write"},
		{"GET", "/orgs/myorg/security-advisories", "security_events", "read"},

		// Dependabot / vulnerability alerts
		{"GET", "/repos/org/repo/dependabot/alerts", "vulnerability_alerts", "read"},
		{"GET", "/repos/org/repo/dependabot/alerts/9", "vulnerability_alerts", "read"},
		{"PATCH", "/repos/org/repo/dependabot/alerts/9", "vulnerability_alerts", "write"},
		{"GET", "/orgs/myorg/dependabot/alerts", "vulnerability_alerts", "read"},
		{"GET", "/repos/org/repo/vulnerability-alerts", "vulnerability_alerts", "read"},
		{"PUT", "/repos/org/repo/vulnerability-alerts", "vulnerability_alerts", "write"},
		{"DELETE", "/repos/org/repo/vulnerability-alerts", "vulnerability_alerts", "write"},

		// Projects
		{"GET", "/projects/1", "projects", "read"},
		{"POST", "/projects/1/columns", "projects", "write"},
		{"GET", "/repos/org/repo/projects", "projects", "read"},
		{"POST", "/repos/org/repo/projects", "projects", "write"},
		{"GET", "/orgs/myorg/projects", "projects", "read"},
		{"POST", "/orgs/myorg/projects", "projects", "write"},

		// Repository administration
		{"PATCH", "/repos/org/repo", "administration", "write"},
		{"DELETE", "/repos/org/repo", "administration", "write"},
		{"POST", "/repos/org/repo/transfer", "administration", "write"},
		{"GET", "/repos/org/repo/collaborators", "administration", "read"},
		{"GET", "/repos/org/repo/collaborators/alice", "administration", "read"},
		{"PUT", "/repos/org/repo/collaborators/alice", "administration", "write"},
		{"DELETE", "/repos/org/repo/collaborators/alice", "administration", "write"},
		{"GET", "/repos/org/repo/invitations", "administration", "read"},
		{"PATCH", "/repos/org/repo/invitations/1", "administration", "write"},
		{"DELETE", "/repos/org/repo/invitations/1", "administration", "write"},
		{"GET", "/repos/org/repo/branches/main/protection", "administration", "read"},
		{"PUT", "/repos/org/repo/branches/main/protection", "administration", "write"},
		{"PATCH", "/repos/org/repo/branches/main/protection/required_status_checks", "administration", "write"},
		{"DELETE", "/repos/org/repo/branches/main/protection/required_signatures", "administration", "write"},
		{"PUT", "/repos/org/repo/topics", "administration", "write"},

		// Organisation members
		{"GET", "/orgs/myorg/members", "members", "read"},
		{"GET", "/orgs/myorg/members/alice", "members", "read"},
		{"DELETE", "/orgs/myorg/members/alice", "members", "write"},
		{"GET", "/orgs/myorg/memberships/alice", "members", "read"},
		{"PUT", "/orgs/myorg/memberships/alice", "members", "write"},
		{"DELETE", "/orgs/myorg/memberships/alice", "members", "write"},
		{"GET", "/orgs/myorg/invitations", "members", "read"},
		{"POST", "/orgs/myorg/invitations", "members", "write"},
		{"DELETE", "/orgs/myorg/invitations/42", "members", "write"},
		{"GET", "/orgs/myorg/public_members", "members", "read"},
		{"PUT", "/orgs/myorg/public_members/alice", "members", "write"},
		{"DELETE", "/orgs/myorg/public_members/alice", "members", "write"},

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

func TestGitSmartHTTPScope(t *testing.T) {
	tests := []struct {
		method    string
		path      string
		query     string
		wantRepo  string
		wantPerm  string
		wantLevel string
	}{
		// Clone/fetch via info/refs.
		{"GET", "/goodtune/ghp.git/info/refs", "service=git-upload-pack", "goodtune/ghp", "contents", "read"},
		// Push via info/refs.
		{"GET", "/goodtune/ghp.git/info/refs", "service=git-receive-pack", "goodtune/ghp", "contents", "write"},
		// Clone/fetch via POST.
		{"POST", "/goodtune/ghp.git/git-upload-pack", "", "goodtune/ghp", "contents", "read"},
		// Push via POST.
		{"POST", "/goodtune/ghp.git/git-receive-pack", "", "goodtune/ghp", "contents", "write"},
		// info/refs without service param — repo detected but no permission.
		{"GET", "/goodtune/ghp.git/info/refs", "", "goodtune/ghp", "", ""},
		// Non-git path.
		{"GET", "/goodtune/ghp/pulls", "", "", "", ""},
		// Path without .git suffix.
		{"GET", "/goodtune/ghp/info/refs", "service=git-upload-pack", "", "", ""},
		// info/refs with extra query params.
		{"GET", "/org/repo.git/info/refs", "foo=bar&service=git-upload-pack&baz=1", "org/repo", "contents", "read"},
	}

	for _, tt := range tests {
		repo, perm, level := GitSmartHTTPScope(tt.method, tt.path, tt.query)
		if repo != tt.wantRepo || perm != tt.wantPerm || level != tt.wantLevel {
			t.Errorf("GitSmartHTTPScope(%q, %q, %q) = (%q, %q, %q), want (%q, %q, %q)",
				tt.method, tt.path, tt.query, repo, perm, level, tt.wantRepo, tt.wantPerm, tt.wantLevel)
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
