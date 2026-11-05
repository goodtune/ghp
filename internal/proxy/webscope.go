package proxy

import (
	"regexp"
	"strings"
)

// githubWebContentsReadPattern matches github.com web paths that download
// repository contents: source archives and release assets.
var githubWebContentsReadPattern = regexp.MustCompile(`^/([^/]+)/([^/]+)/(archive|releases/download)/.+$`)

// GitHubWebScope maps a request on the github.com virtual host to the
// repository, permission and level it needs (goodtune/ghp#292). Git smart
// HTTP paths map as in GitSmartHTTPScope. Archive and release asset
// downloads (GET/HEAD) map to contents:read. Every other path returns an
// empty permission: callers must deny it for scoped tokens. repo is a best
// effort "owner/name" for messages and may be empty.
func GitHubWebScope(method, path, query string) (repo, permission, level string) {
	if repo, permission, level = GitSmartHTTPScope(method, path, query); repo != "" {
		return repo, permission, level
	}
	if m := githubWebContentsReadPattern.FindStringSubmatch(path); m != nil {
		repo = m[1] + "/" + m[2]
		if method == "GET" || method == "HEAD" {
			return repo, "contents", "read"
		}
		return repo, "", ""
	}
	return repoPrefix(path), "", ""
}

// CodeloadScope maps a request on the codeload.github.com virtual host to
// the repository, permission and level it needs. Archive downloads
// (GET/HEAD) map to contents:read; everything else is unmapped.
func CodeloadScope(method, path, _ string) (repo, permission, level string) {
	if m := codeloadArchiveRe.FindStringSubmatch(path); m != nil {
		repo = m[1] + "/" + m[2]
		if method == "GET" || method == "HEAD" {
			return repo, "contents", "read"
		}
		return repo, "", ""
	}
	return repoPrefix(path), "", ""
}

// repoPrefix returns "owner/name" from the first two path segments, or "".
func repoPrefix(path string) string {
	parts := strings.SplitN(strings.TrimLeft(path, "/"), "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "/" + parts[1]
}
