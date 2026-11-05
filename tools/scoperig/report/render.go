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
	fmt.Fprintln(tw, "CLAIM\tSCENARIO\tSTATUS\tDETAIL")
	for _, c := range r.Claims {
		for _, s := range c.Scenarios {
			if s.Status == StatusKnownChanged {
				continue
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", clean(c.ID), clean(s.ID), s.Status, clean(s.Detail))
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	sm := r.Summary
	ew.printf("\nclaims: %d PASS, %d FAIL, %d KNOWN, %d GAP (%d with ERROR)   manual: %s   untestable: %s\n",
		sm.Pass, sm.Fail, sm.Known, sm.Gap, sm.Error, list(sm.Manual), list(sm.Untestable))
	ew.printf("confidence: %s   (PASS / (base - KNOWN))\n", sm.ConfidenceText())
	ew.printf("coverage gaps (%d): %s\n", len(sm.Gaps), list(sm.Gaps))
	ew.printf("tokens: %d created, %d revoked, %d leftover", r.Tokens.Created, r.Tokens.Revoked, len(r.Tokens.LeftoverIDs))
	if len(r.Tokens.LeftoverIDs) > 0 {
		ew.printf(" (%s)", list(r.Tokens.LeftoverIDs))
	}
	ew.printf("\n")
	return ew.err
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

func (e *errWriter) printf(f string, a ...any) { fmt.Fprintf(e, f, a...) }

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
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(j)
}
