package gitcred

import (
	"errors"
	"regexp"
	"strings"
)

// Target is the GitHub repository a credential request is for.
type Target struct{ Owner, Repo string }

// FullName returns "Owner/Repo" with case preserved.
func (t Target) FullName() string { return t.Owner + "/" + t.Repo }

var (
	ErrNotHTTPS = errors.New("only https remotes are supported")
	ErrNoPath   = errors.New("git did not send a repository path")
	ErrBadPath  = errors.New("repository path is not owner/repo")
)

// nameRE is the character set allowed in an owner or repository name. It
// excludes "/", "%", "\", whitespace and non-ASCII, so a parsed name can
// never smuggle a path separator or encoded segment into a cache key or an
// API request.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ParseTarget extracts owner/repo from the path git sent with the request.
// It needs git's credential.useHttpPath (or the equivalent helper config) so
// that git sends a path at all. Extra trailing segments (e.g. "info/refs")
// are ignored unless one is ".", ".." or empty, and one trailing ".git" is stripped from the repository name.
func ParseTarget(req Request) (Target, error) {
	if req.Protocol != "https" {
		return Target{}, ErrNotHTTPS
	}
	p := strings.TrimPrefix(req.Path, "/")
	segs := strings.Split(p, "/")
	if len(segs) < 2 {
		return Target{}, ErrNoPath
	}
	owner := segs[0]
	repo := strings.TrimSuffix(segs[1], ".git")
	if !validName(owner) || !validName(repo) {
		return Target{}, ErrBadPath
	}
	// The remaining segments are not used, but a "..", "." or empty segment
	// means the path does not plainly name this repository (for example
	// "o/r.git/../../evil/x.git"), so it is refused. One trailing empty
	// segment from a trailing "/" is allowed.
	rest := segs[2:]
	if n := len(rest); n > 0 && rest[n-1] == "" {
		rest = rest[:n-1]
	}
	for _, seg := range rest {
		if seg == "" || seg == "." || seg == ".." {
			return Target{}, ErrBadPath
		}
	}
	return Target{Owner: owner, Repo: repo}, nil
}

func validName(s string) bool {
	return s != "." && s != ".." && nameRE.MatchString(s)
}
