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
		{`^/repos/[^/]+/[^/]+/pulls(/[0-9]+)?$`, "GET", "pulls", "read"},
		{`^/repos/[^/]+/[^/]+/pulls$`, "POST", "pulls", "write"},
		{`^/repos/[^/]+/[^/]+/pulls/[0-9]+$`, "PATCH", "pulls", "write"},
		{`^/repos/[^/]+/[^/]+/pulls/[0-9]+/merge$`, "PUT", "pulls", "write"},
		{`^/repos/[^/]+/[^/]+/pulls/[0-9]+/(files|commits|reviews|comments|requested_reviewers)(/.*)?$`, "GET", "pulls", "read"},
		{`^/repos/[^/]+/[^/]+/pulls/[0-9]+/(reviews|comments|requested_reviewers)(/.*)?$`, "POST", "pulls", "write"},
		{`^/repos/[^/]+/[^/]+/pulls/[0-9]+/(reviews|comments|requested_reviewers)(/.*)?$`, "PUT", "pulls", "write"},
		{`^/repos/[^/]+/[^/]+/pulls/[0-9]+/(reviews|comments|requested_reviewers)(/.*)?$`, "DELETE", "pulls", "write"},

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

		// Actions
		{`^/repos/[^/]+/[^/]+/actions(/.*)?$`, "GET", "actions", "read"},
		{`^/repos/[^/]+/[^/]+/actions/(workflows|runs)/[^/]+/dispatches$`, "POST", "actions", "write"},

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
