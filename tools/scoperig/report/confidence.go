package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

// RollUp groups results by claim and decides each claim's status: FAIL if any
// scenario is FAIL, ERROR or KNOWN-CHANGED; else KNOWN if any is KNOWN or
// KNOWN-FIXED; else PASS if every runnable (non-GAP) scenario is PASS; else
// GAP. Claims with no scenario are GAP. Output is sorted by claim ID, and
// scenarios within a claim by scenario ID.
func RollUp(t *scenario.Tree, results []ScenarioResult) []ClaimResult {
	by := map[string][]ScenarioResult{}
	for id := range t.Claims {
		by[id] = nil
	}
	for _, r := range results {
		by[r.Claim] = append(by[r.Claim], r)
	}
	out := make([]ClaimResult, 0, len(by))
	for id, rs := range by {
		sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
		out = append(out, ClaimResult{ID: id, Status: rollUp(rs), Scenarios: rs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func rollUp(rs []ScenarioResult) Status {
	known, runnable := false, false
	for _, r := range rs {
		switch r.Status {
		case StatusFail, StatusError, StatusKnownChanged:
			return StatusFail
		case StatusKnown, StatusKnownFixed:
			known = true
		}
		if r.Status != StatusGap {
			runnable = true
		}
	}
	switch {
	case known:
		return StatusKnown
	case runnable:
		return StatusPass
	}
	return StatusGap
}

// inBase reports whether a claim counts toward the confidence base.
func inBase(c scenario.Claim) bool {
	return c.Testable == "periodic" && !strings.HasPrefix(c.ID, "GAP-")
}

// Summarise counts base claims by status and lists manual, untestable and
// coverage-gap (base claims with no scenario at all) claims.
func Summarise(t *scenario.Tree, claims []ClaimResult) Summary {
	var s Summary
	for _, cr := range claims {
		c, ok := t.Claims[cr.ID]
		if !ok {
			continue
		}
		switch c.Testable {
		case "manual":
			s.Manual = append(s.Manual, c.ID)
		case "never":
			s.Untestable = append(s.Untestable, c.ID)
		}
		if !inBase(c) {
			continue
		}
		s.Base++
		switch cr.Status {
		case StatusPass:
			s.Pass++
		case StatusFail:
			s.Fail++
		case StatusKnown:
			s.Known++
		case StatusGap:
			s.Gap++
		}
		for _, r := range cr.Scenarios {
			if r.Status == StatusError {
				s.Error++
				break
			}
		}
		if len(cr.Scenarios) == 0 {
			s.Gaps = append(s.Gaps, c.ID)
		}
	}
	s.Confidence = Confidence(s.Pass, s.Known, s.Base)
	return s
}

// Confidence is PASS / (base - KNOWN), or 0 when the denominator is not positive.
func Confidence(pass, known, base int) float64 {
	d := base - known
	if d <= 0 {
		return 0
	}
	return float64(pass) / float64(d)
}

// ConfidenceText renders the formula, e.g. "26/(50-1) = 53.1%".
func (s Summary) ConfidenceText() string {
	return fmt.Sprintf("%d/(%d-%d) = %.1f%%", s.Pass, s.Base, s.Known, s.Confidence*100)
}
