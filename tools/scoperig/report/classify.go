package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/redact"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

// Classify decides a scenario's status and a one-line detail.
//
//   - rigErr != nil (or no observation) -> ERROR.
//   - Not known: expect holds -> PASS, else FAIL.
//   - Known: observed holds -> KNOWN; else expect holds -> KNOWN-FIXED;
//     else KNOWN-CHANGED.
//
// A 5xx observation is ERROR unless the matching expectation names that
// status. The one exception is KNOWN-CHANGED: a known scenario that matches
// neither block stays KNOWN-CHANGED (spec §3.6 example, "got 502"), which
// already exits non-zero and flags the change for review.
func Classify(s *scenario.Scenario, o *expect.Observation, rigErr error) (Status, string) {
	if rigErr != nil {
		return StatusError, oneLine(rigErr.Error())
	}
	if o == nil {
		return StatusError, "no observation"
	}
	expErrs := expect.Match(s.Expect, o)
	if s.KnownIssue != "" {
		obsErrs := expect.Match(s.Observed, o)
		switch {
		case len(obsErrs) == 0:
			if e := upstreamError(s.Observed, o, nil); e != "" {
				return StatusError, e
			}
			return StatusKnown, oneLine(s.KnownIssue)
		case len(expErrs) == 0:
			if e := upstreamError(s.Expect, o, nil); e != "" {
				return StatusError, e
			}
			return StatusKnownFixed, "remove known_issue and observed: from " + oneLine(s.ID)
		default:
			return StatusKnownChanged, oneLine("observed " + joinErrs(obsErrs) + "; expect " + joinErrs(expErrs))
		}
	}
	if e := upstreamError(s.Expect, o, expErrs); e != "" {
		return StatusError, e
	}
	if len(expErrs) > 0 {
		return StatusFail, oneLine(joinErrs(expErrs))
	}
	return StatusPass, passDetail(s, o)
}

// upstreamError returns a detail when o is a 5xx that e does not name.
func upstreamError(e *scenario.Expect, o *expect.Observation, errs []error) string {
	if o.Status < 500 || o.Status > 599 {
		return ""
	}
	if len(errs) == 0 && e != nil && (e.Status == o.Status || slices.Contains(e.StatusIn, o.Status)) {
		return ""
	}
	d := fmt.Sprintf("upstream %d", o.Status)
	if len(errs) > 0 {
		d += ": " + joinErrs(errs)
	}
	return oneLine(d)
}

func passDetail(s *scenario.Scenario, o *expect.Observation) string {
	var parts []string
	if o.GHExit != nil {
		parts = append(parts, fmt.Sprintf("exit %d", *o.GHExit))
	}
	if o.Status != 0 {
		parts = append(parts, fmt.Sprint(o.Status))
	}
	if m := expect.GHPMessage(o.Body); m != "" {
		parts = append(parts, m)
	}
	return oneLine(strings.Join(parts, " "))
}

func joinErrs(errs []error) string {
	s := make([]string, len(errs))
	for i, e := range errs {
		s[i] = e.Error()
	}
	return strings.Join(s, "; ")
}

// oneLine redacts s and collapses line breaks so it fits one table row.
func oneLine(s string) string {
	return strings.Join(strings.Fields(redact.String(s)), " ")
}

// NewResult classifies s and fills the observation fields of a result.
func NewResult(s *scenario.Scenario, o *expect.Observation, rigErr error) ScenarioResult {
	st, detail := Classify(s, o, rigErr)
	r := ScenarioResult{ID: s.ID, Claim: s.Claim, KnownIssue: s.KnownIssue, Status: st, Detail: detail}
	if rigErr != nil {
		r.Error = oneLine(rigErr.Error())
	}
	if o != nil {
		r.HTTPStatus = o.Status
		r.GHPMessage = oneLine(expect.GHPMessage(o.Body))
		if o.GHExit != nil {
			v := *o.GHExit
			r.GHExit = &v
		}
		for _, x := range o.Exchanges {
			if x.Status == 401 || x.Status == 403 {
				r.FirstDeniedExchange = oneLine(fmt.Sprintf("%s %s %d %s", x.Method, x.Path, x.Status, expect.GHPMessage([]byte(x.ResponseBody))))
				break
			}
		}
	}
	return r
}
