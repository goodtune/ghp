package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/goodtune/ghp/tools/scoperig/redact"
)

// WriteTable writes the human-readable report (spec §3.6). Output is
// deterministic: rows are sorted by claim then scenario ID and carry no
// timings. KNOWN-CHANGED scenarios are listed in their own section above the
// table. All free text passes through redact.String.
func (r *Report) WriteTable(w io.Writer) error {
	ew := &errWriter{w: w}
	n := 0
	var changed []ScenarioResult
	for _, c := range r.Claims {
		for _, s := range c.Scenarios {
			n++
			if s.Status == StatusKnownChanged {
				changed = append(changed, s)
			}
		}
	}
	instance := clean(r.Instance)
	if r.GHPVersion != "" {
		instance += " (" + clean(r.GHPVersion) + ")"
	}
	ew.printf("scoperig run %s  instance=%s  scenarios=%d\n\n", clean(r.RunID), instance, n)

	if len(changed) > 0 {
		ew.printf("changed (%d):\n", len(changed))
		for _, s := range changed {
			ew.printf("  %s  %s  %s\n", clean(s.ID), s.Status, clean(s.Detail))
		}
		ew.printf("\n")
	}

	tw := tabwriter.NewWriter(ew, 0, 0, 2, ' ', 0)
	if len(changed) > 0 {
		_, _ = fmt.Fprintf(tw, "CLAIM\tSCENARIO\tSTATUS\tDETAIL (%d listed above)\n", len(changed))
	} else {
		_, _ = fmt.Fprintln(tw, "CLAIM\tSCENARIO\tSTATUS\tDETAIL")
	}
	for _, c := range r.Claims {
		for _, s := range c.Scenarios {
			if s.Status == StatusKnownChanged {
				continue
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", clean(c.ID), clean(s.ID), s.Status, clean(s.Detail))
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	sm := r.Summary
	ew.printf("\nclaims: %d PASS, %d FAIL (of which %d ERROR), %d KNOWN, %d GAP   manual: %s   untestable: %s\n",
		sm.Pass, sm.Fail, sm.Error, sm.Known, sm.Gap, list(sm.Manual), list(sm.Untestable))
	ew.printf("confidence: %s   (PASS / (base - KNOWN))\n", sm.ConfidenceText())
	ew.printf("coverage: %s   (base claims with a runnable scenario / base)\n", sm.CoverageText())
	ew.printf("coverage gaps (%d): %s\n", len(sm.Gaps), list(sm.Gaps))
	ew.printf("tokens: %d created, %d revoked, %d leftover", r.Tokens.Created, r.Tokens.Revoked, len(r.Tokens.LeftoverIDs))
	if len(r.Tokens.LeftoverIDs) > 0 {
		ew.printf(" (%s)", list(r.Tokens.LeftoverIDs))
	}
	ew.printf("\n")
	if ew.err != nil {
		return ew.err
	}
	return r.writeLatency(ew)
}

// writeLatency writes the advisory Latency section.
func (r *Report) writeLatency(ew *errWriter) error {
	l := r.Latency
	switch {
	case l == nil || l.Status == LatencyNotConfigured:
		ew.printf("\nlatency: not configured (metrics.prometheus_url)\n")
		return ew.err
	case l.Status != LatencyOK:
		ew.printf("\nlatency: unavailable (%s)\n", clean(redact.String(l.Error)))
		return ew.err
	}
	ver := clean(l.Version)
	if ver == "" {
		ver = "unknown"
	}
	if l.Revision != "" {
		ver += " " + clean(l.Revision)
	}
	ew.printf("\nlatency (advisory, does not change the exit code; ghp %s; window %ds):\n", ver, l.WindowSeconds)
	tw := tabwriter.NewWriter(ew, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "STAGE\tTOKEN_TYPE\tSAMPLES\tMEAN\tP50\tP95\tP99\tP99 BUDGET\tFLAGS")
	over, low := 0, 0
	for _, s := range l.Stages {
		budget, flags := "-", "-"
		if s.BudgetP99 > 0 {
			budget = "< " + seconds(s.BudgetP99)
		}
		if len(s.Flags) > 0 {
			flags = "WARN " + strings.Join(s.Flags, ",")
		}
		for _, f := range s.Flags {
			switch f {
			case FlagOverBudget:
				over++
			case FlagLowSamples:
				low++
			}
		}
		mean, p50, p95, p99 := "n/a", "n/a", "n/a", "n/a"
		if s.Samples > 0 {
			mean, p50, p95, p99 = seconds(s.Mean), seconds(s.P50), seconds(s.P95), seconds(s.P99)
		}
		stage := clean(s.Stage)
		if s.Estimate {
			stage += " (est.)"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", stage, clean(s.TokenType), s.Samples,
			mean, p50, p95, p99, budget, flags)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	ew.printf("latency warnings: %d over budget, %d low samples (< 100)\n", over, low)
	for _, s := range l.Stages {
		if s.Estimate {
			ew.printf("(est.) quantiles estimated from histograms (total minus request_body_read); the mean is exact\n")
			break
		}
	}
	for _, n := range l.Notes {
		ew.printf("latency note: %s\n", clean(redact.String(n)))
	}
	return ew.err
}

// seconds formats a duration in seconds as µs, ms or s.
func seconds(v float64) string {
	switch {
	case v == 0:
		return "0"
	case v < 0.001:
		return fmt.Sprintf("%.0fµs", v*1e6)
	case v < 1:
		return fmt.Sprintf("%.2fms", v*1e3)
	}
	return fmt.Sprintf("%.2fs", v)
}

func clean(s string) string { return oneLine(s) }

func list(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = clean(x)
	}
	return strings.Join(out, " ")
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	e.err = err
	return n, err
}

func (e *errWriter) printf(f string, a ...any) { _, _ = fmt.Fprintf(e, f, a...) }

type jsonObservation struct {
	Status              int    `json:"status"`
	GHPMessage          string `json:"ghp_message"`
	GHExit              *int   `json:"gh_exit"`
	FirstDeniedExchange string `json:"first_denied_exchange"`
}

type jsonScenario struct {
	ID          string          `json:"id"`
	Status      Status          `json:"status"`
	KnownIssue  string          `json:"known_issue"`
	Detail      string          `json:"detail"`
	Observation jsonObservation `json:"observation"`
	Error       string          `json:"error"`
	GapReason   string          `json:"gap_reason"`
	Residue     []string        `json:"residue"`
}

type jsonClaim struct {
	ID        string         `json:"id"`
	Status    Status         `json:"status"`
	Scenarios []jsonScenario `json:"scenarios"`
}

type jsonReport struct {
	RunID      string `json:"run_id"`
	StartedAt  string `json:"started_at"`
	Instance   string `json:"instance"`
	GHPVersion string `json:"ghp_version"`
	GHVersion  string `json:"gh_version"`
	RigCommit  string `json:"rig_commit"`
	Summary    struct {
		Pass       int      `json:"pass"`
		Fail       int      `json:"fail"`
		Known      int      `json:"known"`
		Error      int      `json:"error"`
		Gap        int      `json:"gap"`
		Base       int      `json:"base"`
		Confidence float64  `json:"confidence"`
		Covered    int      `json:"covered"`
		Coverage   float64  `json:"coverage"`
		Manual     []string `json:"manual"`
		Untestable []string `json:"untestable"`
	} `json:"summary"`
	CoverageGaps []string    `json:"coverage_gaps"`
	Claims       []jsonClaim `json:"claims"`
	Tokens       struct {
		Created     int      `json:"created"`
		Revoked     int      `json:"revoked"`
		LeftoverIDs []string `json:"leftover_ids"`
	} `json:"tokens"`
	Latency jsonLatency `json:"latency"`
}

type jsonStageLatency struct {
	Stage            string   `json:"stage"`
	TokenType        string   `json:"token_type"`
	Samples          int      `json:"samples"`
	MeanSeconds      float64  `json:"mean_seconds"`
	P50Seconds       float64  `json:"p50_seconds"`
	P95Seconds       float64  `json:"p95_seconds"`
	P99Seconds       float64  `json:"p99_seconds"`
	BudgetP99Seconds float64  `json:"budget_p99_seconds"`
	Flags            []string `json:"flags"`
	Estimate         bool     `json:"estimate,omitempty"`
}

type jsonLatency struct {
	Status        string             `json:"status"`
	Error         string             `json:"error"`
	Version       string             `json:"version"`
	Revision      string             `json:"revision"`
	WindowSeconds int                `json:"window_seconds"`
	Stages        []jsonStageLatency `json:"stages"`
	Notes         []string           `json:"notes,omitempty"`
}

func latencyJSON(l *Latency) jsonLatency {
	j := jsonLatency{Status: LatencyNotConfigured, Stages: make([]jsonStageLatency, 0)}
	if l == nil {
		return j
	}
	j.Status, j.Error = redact.String(l.Status), redact.String(l.Error)
	j.Version, j.Revision, j.WindowSeconds = redact.String(l.Version), redact.String(l.Revision), l.WindowSeconds
	for _, s := range l.Stages {
		j.Stages = append(j.Stages, jsonStageLatency{Stage: redact.String(s.Stage), TokenType: redact.String(s.TokenType),
			Samples: s.Samples, MeanSeconds: s.Mean, P50Seconds: s.P50, P95Seconds: s.P95, P99Seconds: s.P99,
			BudgetP99Seconds: s.BudgetP99, Flags: cleanList(s.Flags), Estimate: s.Estimate})
	}
	for _, n := range l.Notes {
		j.Notes = append(j.Notes, redact.String(n))
	}
	return j
}

func cleanList(xs []string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, redact.String(x))
	}
	return out
}

// WriteJSON writes the machine-readable report with the field names of spec
// §3.6. Lists are never null. No token values: every string is redacted.
func (r *Report) WriteJSON(w io.Writer) error {
	var j jsonReport
	j.RunID, j.StartedAt, j.Instance = redact.String(r.RunID), redact.String(r.StartedAt), redact.String(r.Instance)
	j.GHPVersion, j.GHVersion, j.RigCommit = redact.String(r.GHPVersion), redact.String(r.GHVersion), redact.String(r.RigCommit)
	sm := r.Summary
	j.Summary.Pass, j.Summary.Fail, j.Summary.Known, j.Summary.Error = sm.Pass, sm.Fail, sm.Known, sm.Error
	j.Summary.Gap, j.Summary.Base, j.Summary.Confidence = sm.Gap, sm.Base, sm.Confidence
	j.Summary.Covered, j.Summary.Coverage = sm.Covered, sm.Coverage
	j.Summary.Manual, j.Summary.Untestable = cleanList(sm.Manual), cleanList(sm.Untestable)
	j.CoverageGaps = cleanList(sm.Gaps)
	j.Claims = make([]jsonClaim, 0, len(r.Claims))
	for _, c := range r.Claims {
		jc := jsonClaim{ID: redact.String(c.ID), Status: c.Status, Scenarios: make([]jsonScenario, 0, len(c.Scenarios))}
		for _, s := range c.Scenarios {
			jc.Scenarios = append(jc.Scenarios, jsonScenario{
				ID: redact.String(s.ID), Status: s.Status, KnownIssue: redact.String(s.KnownIssue),
				Detail: redact.String(s.Detail), Error: redact.String(s.Error), GapReason: redact.String(s.GapReason),
				Residue: cleanList(s.Residue),
				Observation: jsonObservation{Status: s.HTTPStatus, GHPMessage: redact.String(s.GHPMessage),
					GHExit: s.GHExit, FirstDeniedExchange: redact.String(s.FirstDeniedExchange)},
			})
		}
		j.Claims = append(j.Claims, jc)
	}
	j.Tokens.Created, j.Tokens.Revoked, j.Tokens.LeftoverIDs = r.Tokens.Created, r.Tokens.Revoked, cleanList(r.Tokens.LeftoverIDs)
	j.Latency = latencyJSON(r.Latency)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(j)
}
