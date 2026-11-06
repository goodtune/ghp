// Package proxy implements the GitHub API reverse proxy with scope enforcement.
package proxy

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/goodtune/ghp/internal/metrics"
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
		{`^/repos/[^/]+/[^/]+/git/refs/.+$`, "DELETE", "contents", "write"},
		{`^/repos/[^/]+/[^/]+/git/(ref|matching-refs)/.+$`, "GET", "contents", "read"},

		// README, tags, merges and repository dispatch (contents).
		{`^/repos/[^/]+/[^/]+/readme(/.*)?$`, "GET", "contents", "read"},
		{`^/repos/[^/]+/[^/]+/tags$`, "GET", "contents", "read"},
		{`^/repos/[^/]+/[^/]+/merges$`, "POST", "contents", "write"},
		{`^/repos/[^/]+/[^/]+/dispatches$`, "POST", "contents", "write"},

		// Branch protection — must be matched before the branches catch-all.
		{`^/repos/[^/]+/[^/]+/branches/[^/]+/protection(/.*)?$`, "GET", "administration", "read"},
		{`^/repos/[^/]+/[^/]+/branches/[^/]+/protection(/.*)?$`, "PUT", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/branches/[^/]+/protection(/.*)?$`, "POST", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/branches/[^/]+/protection(/.*)?$`, "PATCH", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/branches/[^/]+/protection(/.*)?$`, "DELETE", "administration", "write"},

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
		{`^/repos/[^/]+/[^/]+/pulls/[0-9]+/merge$`, "GET", "pull_requests", "read"},
		{`^/repos/[^/]+/[^/]+/pulls/[0-9]+/update-branch$`, "PUT", "pull_requests", "write"},
		{`^/repos/[^/]+/[^/]+/pulls/comments(/.*)?$`, "GET", "pull_requests", "read"},
		{`^/repos/[^/]+/[^/]+/pulls/comments/[0-9]+(/.*)?$`, "POST", "pull_requests", "write"},
		{`^/repos/[^/]+/[^/]+/pulls/comments/[0-9]+(/.*)?$`, "PATCH", "pull_requests", "write"},
		{`^/repos/[^/]+/[^/]+/pulls/comments/[0-9]+(/.*)?$`, "DELETE", "pull_requests", "write"},
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
		{`^/repos/[^/]+/[^/]+/issues/[0-9]+/(events|timeline|reactions)$`, "GET", "issues", "read"},
		{`^/repos/[^/]+/[^/]+/issues/comments(/.*)?$`, "GET", "issues", "read"},
		{`^/repos/[^/]+/[^/]+/issues/comments/[0-9]+(/.*)?$`, "POST", "issues", "write"},
		{`^/repos/[^/]+/[^/]+/issues/comments/[0-9]+(/.*)?$`, "PATCH", "issues", "write"},
		{`^/repos/[^/]+/[^/]+/issues/comments/[0-9]+(/.*)?$`, "DELETE", "issues", "write"},

		// Repository labels and milestones (issues permission).
		{`^/repos/[^/]+/[^/]+/(labels|milestones)(/.*)?$`, "GET", "issues", "read"},
		{`^/repos/[^/]+/[^/]+/(labels|milestones)$`, "POST", "issues", "write"},
		{`^/repos/[^/]+/[^/]+/(labels|milestones)/[^/]+$`, "PATCH", "issues", "write"},
		{`^/repos/[^/]+/[^/]+/(labels|milestones)/[^/]+$`, "DELETE", "issues", "write"},

		// Statuses and checks
		{`^/repos/[^/]+/[^/]+/statuses/.*$`, "GET", "statuses", "read"},
		{`^/repos/[^/]+/[^/]+/statuses/.*$`, "POST", "statuses", "write"},
		{`^/repos/[^/]+/[^/]+/check-runs(/.*)?$`, "GET", "checks", "read"},
		{`^/repos/[^/]+/[^/]+/check-runs(/.*)?$`, "POST", "checks", "write"},
		{`^/repos/[^/]+/[^/]+/check-runs/[0-9]+$`, "PATCH", "checks", "write"},
		{`^/repos/[^/]+/[^/]+/check-suites(/.*)?$`, "GET", "checks", "read"},
		{`^/repos/[^/]+/[^/]+/check-suites(/.*)?$`, "POST", "checks", "write"},
		{`^/repos/[^/]+/[^/]+/check-suites(/.*)?$`, "PATCH", "checks", "write"},

		// Secrets — must be matched before the actions catch-all.
		{`^/repos/[^/]+/[^/]+/actions/secrets(/.*)?$`, "GET", "secrets", "read"},
		{`^/repos/[^/]+/[^/]+/actions/secrets(/.*)?$`, "PUT", "secrets", "write"},
		{`^/repos/[^/]+/[^/]+/actions/secrets(/.*)?$`, "DELETE", "secrets", "write"},

		// Workflows — must be matched before the actions catch-all.
		// Controls enabling/disabling workflow definitions and dispatching them.
		{`^/repos/[^/]+/[^/]+/actions/workflows(/.*)?$`, "GET", "workflows", "read"},
		{`^/repos/[^/]+/[^/]+/actions/workflows/[^/]+/(enable|disable)$`, "", "workflows", "write"},
		{`^/repos/[^/]+/[^/]+/actions/workflows/[^/]+/dispatches$`, "POST", "workflows", "write"},

		// Actions settings, self-hosted runners and variables — before the
		// actions catch-all. These change repository administration.
		{`^/repos/[^/]+/[^/]+/actions/(permissions|runners)(/.*)?$`, "GET", "administration", "read"},
		{`^/repos/[^/]+/[^/]+/actions/(permissions|runners)(/.*)?$`, "", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/actions/variables(/.*)?$`, "GET", "variables", "read"},
		{`^/repos/[^/]+/[^/]+/actions/variables(/.*)?$`, "", "variables", "write"},

		// Actions (workflow runs, artifacts, caches, runners — after specific paths above).
		// The catch-alls cover all remaining methods so non-GET endpoints
		// (artifact deletes, cache deletes, runner registration, run deletion,
		// etc.) are scoped under actions:write rather than forwarded unscoped.
		{`^/repos/[^/]+/[^/]+/actions(/.*)?$`, "GET", "actions", "read"},
		{`^/repos/[^/]+/[^/]+/actions(/.*)?$`, "POST", "actions", "write"},
		{`^/repos/[^/]+/[^/]+/actions(/.*)?$`, "PUT", "actions", "write"},
		{`^/repos/[^/]+/[^/]+/actions(/.*)?$`, "PATCH", "actions", "write"},
		{`^/repos/[^/]+/[^/]+/actions(/.*)?$`, "DELETE", "actions", "write"},

		// Deployments
		{`^/repos/[^/]+/[^/]+/deployments(/.*)?$`, "GET", "deployments", "read"},
		{`^/repos/[^/]+/[^/]+/deployments$`, "POST", "deployments", "write"},
		{`^/repos/[^/]+/[^/]+/deployments/[0-9]+/statuses(/.*)?$`, "GET", "deployments", "read"},
		{`^/repos/[^/]+/[^/]+/deployments/[0-9]+/statuses$`, "POST", "deployments", "write"},

		// Environments. Write rules cover subpaths like
		// /environments/{name}/deployment-branch-policies and /reviewers.
		{`^/repos/[^/]+/[^/]+/environments(/.*)?$`, "GET", "environments", "read"},
		// Creating or updating an environment itself is administration.
		{`^/repos/[^/]+/[^/]+/environments/[^/]+$`, "PUT", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/environments/[^/]+$`, "DELETE", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/environments/[^/]+(/.*)?$`, "PUT", "environments", "write"},
		{`^/repos/[^/]+/[^/]+/environments/[^/]+(/.*)?$`, "POST", "environments", "write"},
		{`^/repos/[^/]+/[^/]+/environments/[^/]+(/.*)?$`, "PATCH", "environments", "write"},
		{`^/repos/[^/]+/[^/]+/environments/[^/]+(/.*)?$`, "DELETE", "environments", "write"},

		// Pages
		{`^/repos/[^/]+/[^/]+/pages(/.*)?$`, "GET", "pages", "read"},
		{`^/repos/[^/]+/[^/]+/pages(/.*)?$`, "POST", "pages", "write"},
		{`^/repos/[^/]+/[^/]+/pages(/.*)?$`, "PUT", "pages", "write"},
		{`^/repos/[^/]+/[^/]+/pages(/.*)?$`, "PATCH", "pages", "write"},
		{`^/repos/[^/]+/[^/]+/pages(/.*)?$`, "DELETE", "pages", "write"},

		// Packages — covers org, user, and authenticated-user (/user) endpoints.
		{`^/(orgs|users)/[^/]+/packages(/.*)?$`, "GET", "packages", "read"},
		{`^/(orgs|users)/[^/]+/packages(/.*)?$`, "DELETE", "packages", "write"},
		{`^/user/packages(/.*)?$`, "GET", "packages", "read"},
		{`^/user/packages(/.*)?$`, "DELETE", "packages", "write"},

		// Discussions
		{`^/repos/[^/]+/[^/]+/discussions(/.*)?$`, "GET", "discussions", "read"},
		{`^/repos/[^/]+/[^/]+/discussions$`, "POST", "discussions", "write"},
		{`^/repos/[^/]+/[^/]+/discussions/[0-9]+(/.*)?$`, "PATCH", "discussions", "write"},
		{`^/repos/[^/]+/[^/]+/discussions/[0-9]+(/.*)?$`, "DELETE", "discussions", "write"},
		{`^/repos/[^/]+/[^/]+/discussions/[0-9]+/comments(/.*)?$`, "POST", "discussions", "write"},

		// Repository webhooks
		{`^/repos/[^/]+/[^/]+/hooks(/.*)?$`, "GET", "repository_hooks", "read"},
		{`^/repos/[^/]+/[^/]+/hooks(/.*)?$`, "POST", "repository_hooks", "write"},
		{`^/repos/[^/]+/[^/]+/hooks(/.*)?$`, "PUT", "repository_hooks", "write"},
		{`^/repos/[^/]+/[^/]+/hooks(/.*)?$`, "PATCH", "repository_hooks", "write"},
		{`^/repos/[^/]+/[^/]+/hooks(/.*)?$`, "DELETE", "repository_hooks", "write"},

		// Secret scanning alerts
		{`^/repos/[^/]+/[^/]+/secret-scanning(/.*)?$`, "GET", "secret_scanning_alerts", "read"},
		{`^/repos/[^/]+/[^/]+/secret-scanning/alerts/[0-9]+$`, "PATCH", "secret_scanning_alerts", "write"},

		// Code scanning and security advisories (security_events permission).
		{`^/repos/[^/]+/[^/]+/code-scanning(/.*)?$`, "GET", "security_events", "read"},
		{`^/repos/[^/]+/[^/]+/code-scanning/alerts/[0-9]+$`, "PATCH", "security_events", "write"},
		{`^/repos/[^/]+/[^/]+/code-scanning/(sarifs|analyses(/.*)?)$`, "POST", "security_events", "write"},
		{`^/repos/[^/]+/[^/]+/code-scanning/analyses/[0-9]+$`, "DELETE", "security_events", "write"},
		{`^/repos/[^/]+/[^/]+/security-advisories(/.*)?$`, "GET", "security_events", "read"},
		{`^/repos/[^/]+/[^/]+/security-advisories$`, "POST", "security_events", "write"},
		{`^/repos/[^/]+/[^/]+/security-advisories/[^/]+$`, "PATCH", "security_events", "write"},
		{`^/orgs/[^/]+/security-advisories(/.*)?$`, "GET", "security_events", "read"},

		// Dependabot vulnerability alerts (vulnerability_alerts permission).
		{`^/repos/[^/]+/[^/]+/dependabot/alerts(/.*)?$`, "GET", "vulnerability_alerts", "read"},
		{`^/repos/[^/]+/[^/]+/dependabot/alerts/[0-9]+$`, "PATCH", "vulnerability_alerts", "write"},
		{`^/orgs/[^/]+/dependabot/alerts(/.*)?$`, "GET", "vulnerability_alerts", "read"},
		{`^/repos/[^/]+/[^/]+/vulnerability-alerts$`, "GET", "vulnerability_alerts", "read"},
		{`^/repos/[^/]+/[^/]+/vulnerability-alerts$`, "PUT", "vulnerability_alerts", "write"},
		{`^/repos/[^/]+/[^/]+/vulnerability-alerts$`, "DELETE", "vulnerability_alerts", "write"},

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
		{`^/repos/[^/]+/[^/]+/releases/.+$`, "PATCH", "contents", "write"},
		{`^/repos/[^/]+/[^/]+/releases/.+$`, "DELETE", "contents", "write"},

		// Repository administration: settings changes, collaborators, branch
		// protection, invitations, transfers, topics. GET on /repos/{owner}/{repo}
		// is metadata; mutations to the same path are administration.
		{`^/repos/[^/]+/[^/]+$`, "PATCH", "administration", "write"},
		{`^/repos/[^/]+/[^/]+$`, "DELETE", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/transfer$`, "POST", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/collaborators(/.*)?$`, "GET", "administration", "read"},
		{`^/repos/[^/]+/[^/]+/collaborators/[^/]+$`, "PUT", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/collaborators/[^/]+$`, "DELETE", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/invitations(/.*)?$`, "GET", "administration", "read"},
		{`^/repos/[^/]+/[^/]+/invitations/[0-9]+$`, "PATCH", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/invitations/[0-9]+$`, "DELETE", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/topics$`, "PUT", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/keys(/.*)?$`, "GET", "administration", "read"},
		{`^/repos/[^/]+/[^/]+/keys$`, "POST", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/keys/[0-9]+$`, "DELETE", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/rulesets(/.*)?$`, "GET", "administration", "read"},
		{`^/repos/[^/]+/[^/]+/rulesets$`, "POST", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/rulesets/[0-9]+$`, "PUT", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/rulesets/[0-9]+$`, "DELETE", "administration", "write"},
		{`^/repos/[^/]+/[^/]+/forks$`, "POST", "administration", "write"},

		// Organisation membership: members list, memberships, invitations,
		// public members.
		{`^/orgs/[^/]+/members(/.*)?$`, "GET", "members", "read"},
		{`^/orgs/[^/]+/members/[^/]+$`, "DELETE", "members", "write"},
		{`^/orgs/[^/]+/memberships/[^/]+$`, "GET", "members", "read"},
		{`^/orgs/[^/]+/memberships/[^/]+$`, "PUT", "members", "write"},
		{`^/orgs/[^/]+/memberships/[^/]+$`, "DELETE", "members", "write"},
		{`^/orgs/[^/]+/invitations(/.*)?$`, "GET", "members", "read"},
		{`^/orgs/[^/]+/invitations$`, "POST", "members", "write"},
		{`^/orgs/[^/]+/invitations/[0-9]+$`, "DELETE", "members", "write"},
		{`^/orgs/[^/]+/public_members(/.*)?$`, "GET", "members", "read"},
		{`^/orgs/[^/]+/public_members/[^/]+$`, "PUT", "members", "write"},
		{`^/orgs/[^/]+/public_members/[^/]+$`, "DELETE", "members", "write"},

		// Repository metadata (always allowed with any scope)
		{`^/repos/[^/]+/[^/]+$`, "GET", "metadata", "read"},
		{`^/repos/[^/]+/[^/]+/(forks|languages|contributors)$`, "GET", "metadata", "read"},

		// Non-repository metadata endpoints (see nonRepoAllowlist).
		{`^/(user|rate_limit|meta|octocat|zen)?$`, "GET", "metadata", "read"},
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
//
// HEAD is matched as GET: it is the read-only form of the same resource.
func EndpointScope(method, path string) (permission, level string) {
	if method == http.MethodHead {
		method = http.MethodGet
	}
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

// nonRepoAllowlist is the set of paths outside /repos/{owner}/{repo} that a
// scoped token may read (GET or HEAD). They expose only the caller's identity
// and service metadata, which tools such as "gh auth status" need. Every
// other non-repository path is denied for repo-restricted tokens.
var nonRepoAllowlist = map[string]bool{
	"/":           true,
	"/user":       true,
	"/rate_limit": true,
	"/meta":       true,
	"/octocat":    true,
	"/zen":        true,
}

// restDecision is the result of evaluating a REST request for a scoped token.
type restDecision struct {
	allowed bool
	// unmapped is true when the request was denied because no scope rule
	// matched it (deny-by-default).
	unmapped bool
	// repo is the owner/repo extracted from the path, if any.
	repo    string
	message string
}

// decideREST evaluates a REST request on the API host for a scoped token
// (any repo restriction or permission restriction). It is deny-by-default:
//
//  1. GET/HEAD on a nonRepoAllowlist path is allowed.
//  2. A repo-restricted token may only reach /repos/{owner}/{repo} paths for
//     an allowed repository.
//  3. The method and path must match a scope rule; no match is denied.
//  4. A permission-restricted token must hold the rule's permission level
//     (metadata rules need no permission).
//
// Callers must reject unsafe paths (hasUnsafePathSegment) first.
func decideREST(si tokenScopeInfo, method, path string) restDecision {
	if (method == http.MethodGet || method == http.MethodHead) && nonRepoAllowlist[path] {
		return restDecision{allowed: true}
	}

	repo := ExtractRepoFromPath(path)
	if len(si.Repos) > 0 {
		if repo == "" {
			return restDecision{message: fmt.Sprintf(
				"Token is restricted to specific repositories; %s %s does not target a repository", metrics.NormalizeMethod(method), path)}
		}
		if !si.repoAllowed(repo) {
			return restDecision{repo: repo, message: fmt.Sprintf("Token is not scoped to %s", repo)}
		}
	}

	permission, level := EndpointScope(method, path)
	if permission == "" {
		return restDecision{repo: repo, unmapped: true, message: fmt.Sprintf(
			"Endpoint %s %s is not permitted for scoped tokens (no scope rule matches)", metrics.NormalizeMethod(method), path)}
	}
	if permission != "metadata" && len(si.Scopes) > 0 && !si.Scopes.HasPermission(permission, level) {
		return restDecision{repo: repo, message: fmt.Sprintf(
			"Token does not have permission for %s:%s on %s", permission, level, repo)}
	}
	return restDecision{allowed: true, repo: repo}
}

// hasUnsafePathSegment reports whether path contains a "." or ".." segment
// or an empty segment ("//"), or a decoded "?", "#", "%", "\\" or control byte. Such paths could address a different resource
// after normalisation than the one the scope checks saw, so they are
// rejected before any scope evaluation. A single trailing slash is allowed.
func hasUnsafePathSegment(path string) bool {
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c == '?' || c == '#' || c == '%' || c == '\\' || c < 0x20 || c == 0x7f {
			return true
		}
	}
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, seg := range segs {
		switch seg {
		case ".", "..":
			return true
		case "":
			if i != len(segs)-1 {
				return true
			}
		}
	}
	return false
}
