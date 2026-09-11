// Package backend defines the upstream backend identifiers that ghp routes
// traffic to. These constants are used as the canonical labels for host-based
// request dispatch, Prometheus metric labelling, and structured access logs.
// Every HTTP request with a recognized/handled Host header is attributed to
// exactly one backend; requests for unknown or unconfigured hosts are rejected
// and not attributed to any backend.
package backend

const (
	// API handles requests to api.github.com — the GitHub REST and GraphQL API.
	// Scope enforcement, credential injection, and audit logging are applied.
	API = "api.github.com"

	// GitHub handles requests to github.com — git smart HTTP (clone/push) and
	// web traffic such as release downloads. Token interception is performed for
	// ghx_/gha_ tokens. Other traffic is generally forwarded transparently,
	// although release downloads may be intercepted or redirected when release
	// controls (releases.mode) are configured.
	GitHub = "github.com"

	// Codeload handles requests to codeload.github.com — repository archive
	// downloads (zip/tarball by ref). Traffic is forwarded transparently to
	// upstream by default; archive download paths may be redirected to a
	// configured caching mirror when codeload.redirect_to is set.
	Codeload = "codeload.github.com"

	// Copilot handles requests to *.githubcopilot.com. Traffic is forwarded
	// transparently without token interception or scope enforcement; only access
	// logging and metrics are applied.
	Copilot = "copilot"

	// Mgmt handles requests to the configured management host. This serves the
	// web dashboard, OAuth login flow, token management API, and embedded docs.
	Mgmt = "management"
)
