// Package scenario defines the YAML schema for scope regression rig
// claims, token profiles and scenarios, and loads them from disk.
package scenario

// Claim is one documented behaviour the rig verifies.
type Claim struct {
	ID        string `yaml:"id"`  // "REPO-C05", "GAP-A1"
	Doc       string `yaml:"doc"` // "docs/features/token-scoping.md#repository-restrictions"
	Claim     string `yaml:"claim"`
	Iteration int    `yaml:"iteration"`
	Testable  string `yaml:"testable"` // periodic | manual | never
}

// Profile describes a token the rig mints for scenarios.
type Profile struct {
	Name         string   `yaml:"name"`
	Type         string   `yaml:"type"`         // proxy (agent rejected in iteration 1)
	Repositories []string `yaml:"repositories"` // templated
	Scopes       string   `yaml:"scopes"`
	Duration     string   `yaml:"duration"` // "" only for lifecycle-default
}

// Request is one HTTP request (a rest step, cleanup entry or token_api call).
type Request struct {
	Name    string            `yaml:"name"`
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"` // e.g. raw Authorization for BORDER-C43
	Body    any               `yaml:"body"`
	Expect  *Expect           `yaml:"expect"`
	Capture map[string]string `yaml:"capture"` // name -> "$.json.path"
	// Vhost, if set, sends a rest request to the instance with this TLS
	// SNI and Host header and no /api/v3 prefix (only "github.com").
	Vhost string `yaml:"vhost"`
}

// Expect is the matcher syntax shared by expect: and observed: blocks.
type Expect struct {
	Status          int               `yaml:"status"`
	StatusIn        []int             `yaml:"status_in"`
	BodyContains    []string          `yaml:"body_contains"`
	BodyNotContains []string          `yaml:"body_not_contains"`
	Header          map[string]string `yaml:"header"`
	JSON            map[string]string `yaml:"json"`
	GHPDenial       *bool             `yaml:"ghp_denial"`
	ExitCode        *int              `yaml:"exit_code"`
	ExitCodeIn      []int             `yaml:"exit_code_in"`
	StdoutContains  []string          `yaml:"stdout_contains"`
	StderrContains  []string          `yaml:"stderr_contains"`
}

// Scenario is one test case.
type Scenario struct {
	ID          string    `yaml:"id"`
	Claim       string    `yaml:"claim"`
	Doc         string    `yaml:"doc"`
	Description string    `yaml:"description"`
	Profile     string    `yaml:"profile"` // "" allowed for token_api
	Kind        string    `yaml:"kind"`    // rest | graphql | gh | token_api
	KnownIssue  string    `yaml:"known_issue"`
	Observed    *Expect   `yaml:"observed"`
	Requires    []string  `yaml:"requires"` // repo_w_push repo_create github_vhost agent_installation
	Cleanup     []Request `yaml:"cleanup"`
	Expect      *Expect   `yaml:"expect"`
	// kind-specific
	Steps     []Request         `yaml:"steps"`  // rest (single request = one step)
	Method    string            `yaml:"method"` // rest shorthand
	Path      string            `yaml:"path"`
	Vhost     string            `yaml:"vhost"` // rest shorthand; see Request.Vhost
	Headers   map[string]string `yaml:"headers"`
	Body      any               `yaml:"body"`
	Query     string            `yaml:"query"` // graphql
	Variables map[string]any    `yaml:"variables"`
	Args      []string          `yaml:"args"`    // gh
	Repo      string            `yaml:"repo"`    // gh: A | B | W
	Request   *Request          `yaml:"request"` // token_api
	Poll      *Poll             `yaml:"poll"`    // LIFE-C40
	File      string            `yaml:"-"`       // source file for error messages
	// shorthand is set by Normalise when Steps was built from the rest
	// shorthand fields (method, path, vhost, ...).
	shorthand bool
}

// Poll configures repeated requests until the expectation matches.
type Poll struct {
	Interval string `yaml:"interval"` // "2s"
	Timeout  string `yaml:"timeout"`  // "35s"
}

// Tree is the fully loaded scenario tree.
type Tree struct {
	Claims    map[string]Claim
	Profiles  map[string]Profile
	Scenarios []*Scenario // sorted by ID
}
