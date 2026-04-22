// Package proxy implements the GitHub API reverse proxy with scope enforcement.
package proxy

import (
	"regexp"
	"strings"
)

// endpointRule maps a URL pattern + method to a permission category and level.
type endpointRule struct {
	pattern    *regexp.Regexp
	method     string // "" means any method matches.
	permission string
	level      string
}

var rules []endpointRule

func init() {
	// Define endpoint-to-permission mappings.
	// Order matters: more specific rules should come first.
	defs := []struct {
		pattern    string
		method     string
		permission string
		level      string
	}{
		// Contents
		{`^/repos/[^/]+/[^/]+/contents(/.*)?$`, "GET", "contents", "read"},
		{`^/repos/[^/]+/[^/]+/contents(/.*)?$`, "PUT", "contents", "write"},
		{`^/repos/[^/]+/[^/]+/contents(/.*)?$`, "DELETE", "contents", "write"},

		// Git refs, trees, blobs, commits (part of contents)
		{`^/repos/[^/]+/[^/]+/git/(refs|trees|blobs|commits|tags)(/.*)?$`, "GET", "contents", "read"},
		{`^/repos/[^/]+/[^/]+/git/(refs|trees|blobs|commits|tags)(/.*)?$`, "POST", "contents", "write"},
		{`^/repos/[^/]+/[^/]+/git/(refs|trees|blobs|commits|tags)(/.*)?$`, "PATCH", "contents", "write"},

		// Branches
		{`^/repos/[^/]+/[^/]+/branches(/.*)?$`, "GET", "contents", "read"},

		// Commits (list/get)
		{`^/repos/[^/]+/[^/]+/commits(/.*)?$`, "GET", "contents", "read"},

		// Compare
		{`^/repos/[^/]+/[^/]+/compare/.*$`, "GET", "contents", "read"},

		// Pull requests
		{`^/repos/[^/]+/[^/]+/pulls(/[0-9]+)?$`, "GET", "pull_requests", "read"},
		{`^/repos/[^/]+/[^/]+/pulls$`, "POST", "pull_requests", "write"},
		{`^/repos/[^/]+/[^/]+/pulls/[0-9]+$`, "PATCH", "pull_requests", "write"},
		{`^/repos/[^/]+/[^/]+/pulls/[0-9]+/merge$`, "PUT", "pull_requests", "write"},
		{`^/repos/[^/]+/[^/]+/pulls/[0-9]+/(files|commits|reviews|comments|requested_reviewers)(/.*)?$`, "GET", "pull_requests", "read"},
		{`^/repos/[^/]+/[^/]+/pulls/[0-9]+/(reviews|comments|requested_reviewers)(/.*)?$`, "POST", "pull_requests", "write"},
		{`^/repos/[^/]+/[^/]+/pulls/[0-9]+/(reviews|comments|requested_reviewers)(/.*)?$`, "PUT", "pull_requests", "write"},
		{`^/repos/[^/]+/[^/]+/pulls/[0-9]+/(reviews|comments|requested_reviewers)(/.*)?$`, "DELETE", "pull_requests", "write"},

		// Issues
		{`^/repos/[^/]+/[^/]+/issues(/[0-9]+)?$`, "GET", "issues", "read"},
		{`^/repos/[^/]+/[^/]+/issues$`, "POST", "issues", "write"},
		{`^/repos/[^/]+/[^/]+/issues/[0-9]+$`, "PATCH", "issues", "write"},
		{`^/repos/[^/]+/[^/]+/issues/[0-9]+/comments(/.*)?$`, "GET", "issues", "read"},
		{`^/repos/[^/]+/[^/]+/issues/[0-9]+/comments(/.*)?$`, "POST", "issues", "write"},
		{`^/repos/[^/]+/[^/]+/issues/[0-9]+/labels(/.*)?$`, "GET", "issues", "read"},
		{`^/repos/[^/]+/[^/]+/issues/[0-9]+/labels(/.*)?$`, "POST", "issues", "write"},
		{`^/repos/[^/]+/[^/]+/issues/[0-9]+/labels(/.*)?$`, "PUT", "issues", "write"},
		{`^/repos/[^/]+/[^/]+/issues/[0-9]+/labels(/.*)?$`, "DELETE", "issues", "write"},
		{`^/repos/[^/]+/[^/]+/issues/[0-9]+/assignees(/.*)?$`, "GET", "issues", "read"},
		{`^/repos/[^/]+/[^/]+/issues/[0-9]+/assignees(/.*)?$`, "POST", "issues", "write"},
		{`^/repos/[^/]+/[^/]+/issues/[0-9]+/assignees(/.*)?$`, "DELETE", "issues", "write"},

		// Statuses and checks
		{`^/repos/[^/]+/[^/]+/statuses/.*$`, "GET", "statuses", "read"},
		{`^/repos/[^/]+/[^/]+/statuses/.*$`, "POST", "statuses", "write"},
		{`^/repos/[^/]+/[^/]+/check-runs(/.*)?$`, "GET", "checks", "read"},
		{`^/repos/[^/]+/[^/]+/check-runs(/.*)?$`, "POST", "checks", "write"},
		{`^/repos/[^/]+/[^/]+/check-suites(/.*)?$`, "GET", "checks", "read"},

		// Secrets — must be matched before the actions catch-all.
		{`^/repos/[^/]+/[^/]+/actions/secrets(/.*)?$`, "GET", "secrets", "read"},
		{`^/repos/[^/]+/[^/]+/actions/secrets(/.*)?$`, "PUT", "secrets", "write"},
		{`^/repos/[^/]+/[^/]+/actions/secrets(/.*)?$`, "DELETE", "secrets", "write"},

		// Workflows — must be matched before the actions catch-all.
		// Controls enabling/disabling workflow definitions and dispatching them.
		{`^/repos/[^/]+/[^/]+/actions/workflows(/.*)?$`, "GET", "workflows", "read"},
		{`^/repos/[^/]+/[^/]+/actions/workflows/[^/]+/(enable|disable)$`, "", "workflows", "write"},
		{`^/repos/[^/]+/[^/]+/actions/workflows/[^/]+/dispatches$`, "POST", "workflows", "write"},

		// Actions (workflow runs, artifacts, caches, runners — after specific paths above)
		{`^/repos/[^/]+/[^/]+/actions(/.*)?$`, "GET", "actions", "read"},
		{`^/repos/[^/]+/[^/]+/actions/(runs|jobs)/[^/]+/(rerun|cancel)$`, "POST", "actions", "write"},

		// Deployments
		{`^/repos/[^/]+/[^/]+/deployments(/.*)?$`, "GET", "deployments", "read"},
		{`^/repos/[^/]+/[^/]+/deployments$`, "POST", "deployments", "write"},
		{`^/repos/[^/]+/[^/]+/deployments/[0-9]+/statuses(/.*)?$`, "GET", "deployments", "read"},
		{`^/repos/[^/]+/[^/]+/deployments/[0-9]+/statuses$`, "POST", "deployments", "write"},

		// Environments
		{`^/repos/[^/]+/[^/]+/environments(/.*)?$`, "GET", "environments", "read"},
		{`^/repos/[^/]+/[^/]+/environments/[^/]+$`, "PUT", "environments", "write"},
		{`^/repos/[^/]+/[^/]+/environments/[^/]+$`, "DELETE", "environments", "write"},

		// Pages
		{`^/repos/[^/]+/[^/]+/pages(/.*)?$`, "GET", "pages", "read"},
		{`^/repos/[^/]+/[^/]+/pages$`, "POST", "pages", "write"},
		{`^/repos/[^/]+/[^/]+/pages$`, "PUT", "pages", "write"},
		{`^/repos/[^/]+/[^/]+/pages$`, "DELETE", "pages", "write"},

		// Packages
		{`^/(orgs|users)/[^/]+/packages(/.*)?$`, "GET", "packages", "read"},
		{`^/(orgs|users)/[^/]+/packages(/.*)?$`, "DELETE", "packages", "write"},

		// Discussions
		{`^/repos/[^/]+/[^/]+/discussions(/.*)?$`, "GET", "discussions", "read"},
		{`^/repos/[^/]+/[^/]+/discussions$`, "POST", "discussions", "write"},
		{`^/repos/[^/]+/[^/]+/discussions/[0-9]+(/.*)?$`, "PATCH", "discussions", "write"},
		{`^/repos/[^/]+/[^/]+/discussions/[0-9]+(/.*)?$`, "DELETE", "discussions", "write"},
		{`^/repos/[^/]+/[^/]+/discussions/[0-9]+/comments(/.*)?$`, "POST", "discussions", "write"},

		// Repository webhooks
		{`^/repos/[^/]+/[^/]+/hooks(/.*)?$`, "GET", "repository_hooks", "read"},
		{`^/repos/[^/]+/[^/]+/hooks$`, "POST", "repository_hooks", "write"},
		{`^/repos/[^/]+/[^/]+/hooks/[0-9]+$`, "PATCH", "repository_hooks", "write"},
		{`^/repos/[^/]+/[^/]+/hooks/[0-9]+$`, "DELETE", "repository_hooks", "write"},

		// Secret scanning alerts
		{`^/repos/[^/]+/[^/]+/secret-scanning(/.*)?$`, "GET", "secret_scanning_alerts", "read"},
		{`^/repos/[^/]+/[^/]+/secret-scanning/alerts/[0-9]+$`, "PATCH", "secret_scanning_alerts", "write"},

		// Projects
		{`^/projects(/.*)?$`, "GET", "projects", "read"},
		{`^/projects(/.*)?$`, "POST", "projects", "write"},
		{`^/projects(/.*)?$`, "PATCH", "projects", "write"},
		{`^/projects(/.*)?$`, "DELETE", "projects", "write"},
		{`^/repos/[^/]+/[^/]+/projects(/.*)?$`, "GET", "projects", "read"},
		{`^/repos/[^/]+/[^/]+/projects$`, "POST", "projects", "write"},
		{`^/orgs/[^/]+/projects(/.*)?$`, "GET", "projects", "read"},
		{`^/orgs/[^/]+/projects$`, "POST", "projects", "write"},

		// Releases
		{`^/repos/[^/]+/[^/]+/releases(/.*)?$`, "GET", "contents", "read"},
		{`^/repos/[^/]+/[^/]+/releases(/.*)?$`, "POST", "contents", "write"},

		// Repository metadata (always allowed with any scope)
		{`^/repos/[^/]+/[^/]+$`, "GET", "metadata", "read"},

		// User endpoint (always allowed)
		{`^/user$`, "", "metadata", "read"},
	}

	for _, d := range defs {
		rules = append(rules, endpointRule{
			pattern:    regexp.MustCompile(d.pattern),
			method:     d.method,
			permission: d.permission,
			level:      d.level,
		})
	}
}

// gitSmartHTTPPattern matches /{owner}/{repo}.git/... paths used by git smart HTTP.
var gitSmartHTTPPattern = regexp.MustCompile(`^/([^/]+/[^/]+)\.git/(.+)$`)

// GitSmartHTTPScope extracts the repository, permission, and level from a git
// smart HTTP request path. Returns empty strings for non-git paths.
//
// Git smart HTTP paths:
//   - GET  /{owner}/{repo}.git/info/refs?service=git-upload-pack  → contents:read
//   - POST /{owner}/{repo}.git/git-upload-pack                    → contents:read
//   - GET  /{owner}/{repo}.git/info/refs?service=git-receive-pack → contents:write
//   - POST /{owner}/{repo}.git/git-receive-pack                   → contents:write
func GitSmartHTTPScope(method, path, query string) (repo, permission, level string) {
	m := gitSmartHTTPPattern.FindStringSubmatch(path)
	if m == nil {
		return "", "", ""
	}
	repo = m[1]
	suffix := m[2]

	switch {
	case suffix == "git-receive-pack" && method == "POST":
		return repo, "contents", "write"
	case suffix == "git-upload-pack" && method == "POST":
		return repo, "contents", "read"
	case suffix == "info/refs":
		// The service query parameter determines the operation.
		service := parseServiceParam(query)
		switch service {
		case "git-receive-pack":
			return repo, "contents", "write"
		case "git-upload-pack":
			return repo, "contents", "read"
		}
	}
	return repo, "", ""
}

// parseServiceParam extracts the "service" value from a raw query string.
func parseServiceParam(query string) string {
	for _, part := range strings.Split(query, "&") {
		if strings.HasPrefix(part, "service=") {
			return strings.TrimPrefix(part, "service=")
		}
	}
	return ""
}

// EndpointScope returns the permission and level required for a given method and path.
// Returns empty strings if the endpoint is not recognized.
func EndpointScope(method, path string) (permission, level string) {
	for _, r := range rules {
		if r.method != "" && r.method != method {
			continue
		}
		if r.pattern.MatchString(path) {
			return r.permission, r.level
		}
	}
	return "", ""
}

// ExtractRepoFromPath extracts the owner/repo from a /repos/{owner}/{repo}/... path.
// Returns empty string if the path doesn't match.
func ExtractRepoFromPath(path string) string {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 4)
	if len(parts) < 3 || parts[0] != "repos" {
		return ""
	}
	return parts[1] + "/" + parts[2]
}
