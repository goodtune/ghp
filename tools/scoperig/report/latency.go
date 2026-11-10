package report

// Latency status values.
const (
	LatencyOK            = "ok"
	LatencyNotConfigured = "not_configured"
	LatencyUnavailable   = "unavailable"
)

// Advisory flags in StageLatency.Flags.
const (
	FlagOverBudget = "over-budget" // p99 above the stage's budget
	FlagLowSamples = "low-samples" // fewer than 100 samples in the window
)

// Latency is the per-stage latency GHP reported in Prometheus over the run
// window. It is advisory: budget flags never change the exit code.
type Latency struct {
	// Status is LatencyOK, LatencyNotConfigured or LatencyUnavailable.
	Status string
	// Error explains LatencyUnavailable.
	Error string
	// Version and Revision come from ghp_build_info.
	Version, Revision string
	// Window is the run window in seconds that the increase was taken over.
	WindowSeconds int
	Stages        []StageLatency
	// Notes are advisory remarks on the section (for example why a
	// derived row was omitted).
	Notes []string
}

// StageLatency is one stage (or the end-to-end request) for one token type.
// Quantiles and the mean are in seconds; rows with no samples carry zeros.
type StageLatency struct {
	Stage, TokenType    string
	Samples             int
	Mean, P50, P95, P99 float64
	// BudgetP99 is the advisory p99 budget in seconds; 0 means no budget.
	BudgetP99 float64
	// Flags are advisory warnings: FlagOverBudget, FlagLowSamples.
	Flags []string
	// Estimate marks a derived row whose quantiles are estimated, not
	// measured (total_excl_body_read, #360).
	Estimate bool
}
