package exec

import (
	"net/http"
	"runtime/debug"
	"strings"
)

// UserAgent returns the User-Agent the rig sends on every HTTP request:
// "ghp-scoperig/<version> (run=<run-id>)", so an operator can isolate one
// run in the instance's access logs.
func UserAgent(version, runID string) string {
	if version == "" {
		version = "dev"
	}
	return "ghp-scoperig/" + version + " (run=" + runID + ")"
}

// Commit is the rig's source revision, stamped at build time by the
// Makefile's scoperig target:
//
//	-ldflags "-X github.com/goodtune/ghp/tools/scoperig/exec.Commit=<sha>[-dirty]"
//
// Go's own VCS stamping is used only when Commit is empty. It is unreliable
// for a build inside a git worktree, where it can resolve the parent checkout
// and report its pseudo-version and revision instead of the worktree's.
var Commit string

// RigVersion is the rig's version for the User-Agent: the first 12
// characters of the stamped Commit (keeping a "-dirty" suffix), else the
// module version when built from a tagged module, else the first 12
// characters of the VCS revision, else "dev".
func RigVersion() string {
	bi, ok := debug.ReadBuildInfo()
	return rigVersion(Commit, bi, ok)
}

// RigCommit is the full revision the rig was built from: the stamped Commit,
// else the VCS revision from the build info (with "-dirty" for a modified
// tree), else "" (for example under go run).
func RigCommit() string {
	bi, ok := debug.ReadBuildInfo()
	return rigCommit(Commit, bi, ok)
}

func rigVersion(stamp string, bi *debug.BuildInfo, ok bool) string {
	if stamp != "" {
		return shortRev(stamp)
	}
	if !ok || bi == nil {
		return "dev"
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			return s.Value[:min(12, len(s.Value))]
		}
	}
	return "dev"
}

func rigCommit(stamp string, bi *debug.BuildInfo, ok bool) string {
	if stamp != "" {
		return stamp
	}
	if !ok || bi == nil {
		return ""
	}
	var rev string
	dirty := false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev != "" && dirty {
		rev += "-dirty"
	}
	return rev
}

// shortRev shortens a revision to 12 characters, keeping a "-dirty" suffix.
func shortRev(rev string) string {
	base, dirty := strings.CutSuffix(rev, "-dirty")
	base = base[:min(12, len(base))]
	if dirty {
		return base + "-dirty"
	}
	return base
}

// userAgentTransport sets User-Agent on every request it sends.
type userAgentTransport struct {
	base http.RoundTripper
	ua   string
}

func (t *userAgentTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.Header.Set("User-Agent", t.ua)
	return BaseTransport(t.base).RoundTrip(r2)
}

// WithUserAgent returns a copy of c (or a default client when c is nil)
// whose transport sets ua on every request. Wrapping at the client means no
// call site can forget the header.
func WithUserAgent(c *http.Client, ua string) *http.Client {
	var cp http.Client
	if c != nil {
		cp = *c
	}
	base := cp.Transport
	if u, ok := base.(*userAgentTransport); ok {
		base = u.base
	}
	cp.Transport = &userAgentTransport{base: base, ua: ua}
	return &cp
}

// BaseTransport returns the transport under any User-Agent wrapper, or
// http.DefaultTransport for nil.
func BaseTransport(rt http.RoundTripper) http.RoundTripper {
	if u, ok := rt.(*userAgentTransport); ok {
		rt = u.base
	}
	if rt == nil {
		return http.DefaultTransport
	}
	return rt
}

// UserAgentOf returns the User-Agent c's transport sets, or "".
func UserAgentOf(c *http.Client) string {
	if c == nil {
		return ""
	}
	if u, ok := c.Transport.(*userAgentTransport); ok {
		return u.ua
	}
	return ""
}

// rewrap puts rt under the same User-Agent wrapper as orig, if any.
func rewrap(orig, rt http.RoundTripper) http.RoundTripper {
	if u, ok := orig.(*userAgentTransport); ok {
		return &userAgentTransport{base: rt, ua: u.ua}
	}
	return rt
}
