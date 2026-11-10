// Package report classifies scenario outcomes, rolls them up per claim,
// computes the confidence figure and renders the run report.
package report

// Status is the outcome of one scenario or the roll-up of one claim.
type Status string

// Scenario and claim statuses (spec §3.6).
const (
	StatusPass         Status = "PASS"
	StatusFail         Status = "FAIL"
	StatusError        Status = "ERROR"
	StatusKnown        Status = "KNOWN"
	StatusKnownFixed   Status = "KNOWN-FIXED"
	StatusKnownChanged Status = "KNOWN-CHANGED"
	StatusGap          Status = "GAP"
)

// ScenarioResult is everything the report shows about one scenario.
type ScenarioResult struct {
	ID, Claim, KnownIssue string
	Status                Status
	Detail                string // one line for the table
	HTTPStatus            int    // last observed HTTP status; 0 for gh or none
	GHPMessage            string
	GHExit                *int
	FirstDeniedExchange   string // "POST /api/graphql 403 <message>"
	Error                 string
	GapReason             string   // unmet requires
	Residue               []string // cleanup failures (object URLs)
	// Reasons are rig-generated, fixed-vocabulary reasons (no response,
	// error or config text) for the --claims paste-back line. Not in the
	// JSON report.
	Reasons []string
}

// ClaimResult is the roll-up of all scenarios for one claim.
type ClaimResult struct {
	ID        string
	Status    Status
	Scenarios []ScenarioResult
}

// Summary holds the claim counts over base and the confidence figure.
// Pass, Fail, Known, Error and Gap count base claims only (Error counts
// base claims with at least one ERROR scenario; those claims are also FAIL).
// Covered counts base claims with at least one runnable scenario result.
type Summary struct {
	Pass, Fail, Known, Error, Gap, Base, Covered int
	Confidence, Coverage                         float64
	Manual, Untestable, Gaps                     []string
}

// Report is one rig run.
type Report struct {
	RunID, StartedAt, Instance, GHPVersion, GHVersion, RigCommit string
	Summary                                                      Summary
	Claims                                                       []ClaimResult
	Tokens                                                       struct {
		Created, Revoked int
		LeftoverIDs      []string
	}
	// Latency is the advisory latency section; nil means not configured.
	// It never affects ExitCode.
	Latency *Latency
}

// ExitCode returns 1 if any scenario is FAIL or KNOWN-CHANGED, else 2 if any
// scenario is ERROR, left cleanup residue, or a token was left unrevoked,
// else 0 (spec §3.7). Exit code 3 is decided before a report exists.
func ExitCode(r *Report) int {
	fail, errs := false, len(r.Tokens.LeftoverIDs) > 0
	for _, c := range r.Claims {
		for _, s := range c.Scenarios {
			switch s.Status {
			case StatusFail, StatusKnownChanged:
				fail = true
			case StatusError:
				errs = true
			}
			if len(s.Residue) > 0 {
				errs = true
			}
		}
	}
	switch {
	case fail:
		return 1
	case errs:
		return 2
	}
	return 0
}
