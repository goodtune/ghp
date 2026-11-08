package report

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

func TestConfidence(t *testing.T) {
	tests := []struct {
		pass, known, base int
		want              float64
		text              string
	}{
		{26, 1, 50, 26.0 / 49.0, "26/(50-1) = 53.1%"},
		{25, 1, 50, 25.0 / 49.0, "25/(50-1) = 51.0%"},
		{0, 0, 0, 0, "0/(0-0) = 0.0%"},
		{0, 3, 3, 0, "0/(3-3) = 0.0%"},
		{4, 0, 4, 1, "4/(4-0) = 100.0%"},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			got := Confidence(tt.pass, tt.known, tt.base)
			if got != tt.want {
				t.Errorf("Confidence = %v, want %v", got, tt.want)
			}
			s := Summary{Pass: tt.pass, Known: tt.known, Base: tt.base, Confidence: got}
			if txt := s.ConfidenceText(); txt != tt.text {
				t.Errorf("text = %q, want %q", txt, tt.text)
			}
		})
	}
}

func testTree() *scenario.Tree {
	c := func(id, testable string) scenario.Claim { return scenario.Claim{ID: id, Testable: testable} }
	return &scenario.Tree{Claims: map[string]scenario.Claim{
		"C-PASS": c("C-PASS", "periodic"), "C-FAIL": c("C-FAIL", "periodic"), "C-ERR": c("C-ERR", "periodic"),
		"C-CHG": c("C-CHG", "periodic"), "C-KNOWN": c("C-KNOWN", "periodic"), "C-FIXED": c("C-FIXED", "periodic"),
		"C-GAPREQ": c("C-GAPREQ", "periodic"), "C-NONE": c("C-NONE", "periodic"), "C-MIXED": c("C-MIXED", "periodic"),
		"GAP-A1": c("GAP-A1", "periodic"), "C-MAN": c("C-MAN", "manual"), "C-NEV": c("C-NEV", "never"),
	}}
}

func testResults() []ScenarioResult {
	r := func(id, claim string, s Status) ScenarioResult {
		return ScenarioResult{ID: id, Claim: claim, Status: s}
	}
	return []ScenarioResult{
		r("C-PASS.b", "C-PASS", StatusPass), r("C-PASS.a", "C-PASS", StatusPass),
		r("C-FAIL.a", "C-FAIL", StatusFail), r("C-FAIL.b", "C-FAIL", StatusKnown),
		r("C-ERR.a", "C-ERR", StatusError), r("C-CHG.a", "C-CHG", StatusKnownChanged),
		r("C-KNOWN.a", "C-KNOWN", StatusKnown), r("C-KNOWN.b", "C-KNOWN", StatusPass),
		r("C-FIXED.a", "C-FIXED", StatusKnownFixed),
		{ID: "C-GAPREQ.a", Claim: "C-GAPREQ", Status: StatusGap, GapReason: "requires repo_create"},
		r("C-MIXED.a", "C-MIXED", StatusPass), {ID: "C-MIXED.b", Claim: "C-MIXED", Status: StatusGap, GapReason: "requires github_vhost"},
		r("GAP-A1.a", "GAP-A1", StatusKnown),
	}
}

func TestRollUp(t *testing.T) {
	claims := RollUp(testTree(), testResults())
	got := map[string]Status{}
	var order []string
	for _, c := range claims {
		got[c.ID] = c.Status
		order = append(order, c.ID)
	}
	want := map[string]Status{
		"C-PASS": StatusPass, "C-FAIL": StatusFail, "C-ERR": StatusFail, "C-CHG": StatusFail,
		"C-KNOWN": StatusKnown, "C-FIXED": StatusKnown, "C-GAPREQ": StatusGap, "C-NONE": StatusGap,
		"C-MIXED": StatusPass, "GAP-A1": StatusKnown, "C-MAN": StatusGap, "C-NEV": StatusGap,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("roll-up = %v\nwant %v", got, want)
	}
	wantOrder := []string{"C-CHG", "C-ERR", "C-FAIL", "C-FIXED", "C-GAPREQ", "C-KNOWN", "C-MAN", "C-MIXED", "C-NEV", "C-NONE", "C-PASS", "GAP-A1"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Errorf("order = %v", order)
	}
	if claims[10].Scenarios[0].ID != "C-PASS.a" {
		t.Errorf("scenarios not sorted: %v", claims[10].Scenarios)
	}
}

func TestSummarise(t *testing.T) {
	tree := testTree()
	s := Summarise(tree, RollUp(tree, testResults()))
	// base excludes C-MAN, C-NEV but counts the periodic GAP-A1 probe: 10 claims.
	// Covered: every base claim with a non-GAP scenario (not C-GAPREQ, C-NONE).
	want := Summary{Pass: 2, Fail: 3, Known: 3, Error: 1, Gap: 2, Base: 10, Covered: 8,
		Confidence: 2.0 / 7.0, Coverage: 0.8, Manual: []string{"C-MAN"}, Untestable: []string{"C-NEV"}, Gaps: []string{"C-NONE"}}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("summary = %+v\nwant %+v", s, want)
	}
	if fmt.Sprint(s.ConfidenceText()) != "2/(10-3) = 28.6%" {
		t.Errorf("text = %s", s.ConfidenceText())
	}
	if s.CoverageText() != "8/10 = 80.0%" {
		t.Errorf("coverage text = %s", s.CoverageText())
	}
}

// TestSummarise_GapProbe checks that a periodic GAP probe moves confidence:
// PASS raises it, FAIL lowers it, and manual or never GAP claims stay out.
func TestSummarise_GapProbe(t *testing.T) {
	tests := []struct {
		name     string
		testable string
		status   Status
		wantText string
	}{
		{"periodic pass", "periodic", StatusPass, "2/(2-0) = 100.0%"},
		{"periodic fail", "periodic", StatusFail, "1/(2-0) = 50.0%"},
		{"manual excluded", "manual", StatusFail, "1/(1-0) = 100.0%"},
		{"never excluded", "never", StatusFail, "1/(1-0) = 100.0%"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := &scenario.Tree{Claims: map[string]scenario.Claim{
				"C-PASS": {ID: "C-PASS", Testable: "periodic"},
				"GAP-A2": {ID: "GAP-A2", Testable: tt.testable},
			}}
			res := []ScenarioResult{
				{ID: "C-PASS.a", Claim: "C-PASS", Status: StatusPass},
				{ID: "GAP-A2.a", Claim: "GAP-A2", Status: tt.status},
			}
			s := Summarise(tree, RollUp(tree, res))
			if got := s.ConfidenceText(); got != tt.wantText {
				t.Errorf("confidence = %s, want %s", got, tt.wantText)
			}
		})
	}
}

func TestCoverage(t *testing.T) {
	tests := []struct {
		covered, base int
		want          float64
		text          string
	}{
		{8, 10, 0.8, "8/10 = 80.0%"},
		{0, 0, 0, "0/0 = 0.0%"},
		{3, 3, 1, "3/3 = 100.0%"},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			got := Coverage(tt.covered, tt.base)
			if got != tt.want {
				t.Errorf("Coverage = %v, want %v", got, tt.want)
			}
			s := Summary{Covered: tt.covered, Base: tt.base, Coverage: got}
			if txt := s.CoverageText(); txt != tt.text {
				t.Errorf("text = %q, want %q", txt, tt.text)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	mk := func(sts ...Status) *Report {
		var rs []ScenarioResult
		for i, s := range sts {
			rs = append(rs, ScenarioResult{ID: fmt.Sprint("C.", i), Claim: "C", Status: s})
		}
		return &Report{Claims: []ClaimResult{{ID: "C", Scenarios: rs}}}
	}
	tests := []struct {
		name string
		r    *Report
		want int
	}{
		{"empty", &Report{}, 0},
		{"pass known fixed gap", mk(StatusPass, StatusKnown, StatusKnownFixed, StatusGap), 0},
		{"fail", mk(StatusPass, StatusFail), 1},
		{"changed", mk(StatusKnownChanged), 1},
		{"fail beats error", mk(StatusError, StatusFail), 1},
		{"error", mk(StatusPass, StatusError), 2},
		{"residue", func() *Report {
			r := mk(StatusPass)
			r.Claims[0].Scenarios[0].Residue = []string{"https://x/issues/1"}
			return r
		}(), 2},
		{"leftover token", func() *Report { r := mk(StatusPass); r.Tokens.LeftoverIDs = []string{"id1"}; return r }(), 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.r); got != tt.want {
				t.Errorf("ExitCode = %d, want %d", got, tt.want)
			}
		})
	}
}
