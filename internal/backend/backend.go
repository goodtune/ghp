// Package backend defines the four upstream backend identifiers that ghp routes
// traffic to. These constants are used as the canonical labels for host-based
// request dispatch, Prometheus metric labelling, and structured access logs.
// Every HTTP request that enters ghp is attributed to exactly one backend based
// on the Host header of the incoming request.
package backend

const (
	// API handles requests to api.github.com — the GitHub REST and GraphQL API.
	// Scope enforcement, credential injection, and audit logging are applied.
	API = "api.github.com"

	// GitHub handles requests to github.com — git smart HTTP (clone/push) and
	// web traffic such as release downloads. Token interception is performed for
	// ghx_/gha_ tokens; other traffic passes through transparently.
	GitHub = "github.com"

	// Copilot handles requests to *.githubcopilot.com. Traffic is forwarded
	// transparently without token interception or scope enforcement; only access
	// logging and metrics are applied.
	Copilot = "copilot"

	// Mgmt handles requests to the configured management host. This serves the
	// web dashboard, OAuth login flow, token management API, and embedded docs.
	Mgmt = "management"
)
