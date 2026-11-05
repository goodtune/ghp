package report

import (
	"errors"
	"strings"
	"testing"

	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/ghdebug"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

func intp(i int) *int { return &i }

func TestClassify(t *testing.T) {
	denial := []byte(`{"message":"Token is not scoped to o/b"}`)
	tests := []struct {
		name   string
		s      *scenario.Scenario
		o      *expect.Observation
		err    error
		want   Status
		detail string
	}{
		{"pass", &scenario.Scenario{ID: "X.a", Expect: &scenario.Expect{Status: 403}}, &expect.Observation{Status: 403, Body: denial}, nil, StatusPass, "403 Token is not scoped to o/b"},
		{"fail", &scenario.Scenario{ID: "X.a", Expect: &scenario.Expect{Status: 403}}, &expect.Observation{Status: 200}, nil, StatusFail, "status: want 403, got 200"},
		{"rig error", &scenario.Scenario{ID: "X.a", Expect: &scenario.Expect{Status: 403}}, nil, errors.New("revoke call failed: 500"), StatusError, "revoke call failed: 500"},
		{"rig error redacted", &scenario.Scenario{ID: "X.a"}, nil, errors.New("bad ghx_abcdefghijklmnop"), StatusError, "bad ghx_[REDACTED]"},
		{"nil observation", &scenario.Scenario{ID: "X.a", Expect: &scenario.Expect{Status: 403}}, nil, nil, StatusError, "no observation"},
		{"known", &scenario.Scenario{ID: "X.a", KnownIssue: "https://x/1", Expect: &scenario.Expect{Status: 200}, Observed: &scenario.Expect{Status: 403}}, &expect.Observation{Status: 403}, nil, StatusKnown, "https://x/1"},
		{"known fixed", &scenario.Scenario{ID: "X.a", KnownIssue: "https://x/1", Expect: &scenario.Expect{Status: 200}, Observed: &scenario.Expect{Status: 403}}, &expect.Observation{Status: 200}, nil, StatusKnownFixed, "remove known_issue and observed: from X.a"},
		{"known changed", &scenario.Scenario{ID: "X.a", KnownIssue: "https://x/1", Expect: &scenario.Expect{Status: 403}, Observed: &scenario.Expect{Status: 200}}, &expect.Observation{Status: 404}, nil, StatusKnownChanged, "observed status: want 200, got 404; expect status: want 403, got 404"},
		{"5xx is error", &scenario.Scenario{ID: "X.a", Expect: &scenario.Expect{Status: 403}}, &expect.Observation{Status: 502}, nil, StatusError, "upstream 502: status: want 403, got 502"},
		{"5xx matched by body only is error", &scenario.Scenario{ID: "X.a", Expect: &scenario.Expect{BodyContains: []string{"x"}}}, &expect.Observation{Status: 500, Body: []byte("x")}, nil, StatusError, "upstream 500"},
		{"5xx named is pass", &scenario.Scenario{ID: "X.a", Expect: &scenario.Expect{StatusIn: []int{500, 502}}}, &expect.Observation{Status: 502}, nil, StatusPass, "502"},
		{"gh pass", &scenario.Scenario{ID: "X.a", Kind: "gh", Expect: &scenario.Expect{ExitCode: intp(0)}}, &expect.Observation{GHExit: intp(0)}, nil, StatusPass, "exit 0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, detail := Classify(tt.s, tt.o, tt.err)
			if got != tt.want {
				t.Errorf("status = %s, want %s (detail %q)", got, tt.want, detail)
			}
			if !strings.HasPrefix(detail, tt.detail) {
				t.Errorf("detail = %q, want prefix %q", detail, tt.detail)
			}
		})
	}
}

func TestClassify_Known(t *testing.T) {
	s := &scenario.Scenario{ID: "GAP-A7.dotdot-path", KnownIssue: "https://github.com/goodtune/ghp/issues/295",
		Expect: &scenario.Expect{StatusIn: []int{403, 404}}, Observed: &scenario.Expect{Status: 200}}
	for _, tt := range []struct {
		status int
		want   Status
	}{{200, StatusKnown}, {404, StatusKnownFixed}, {403, StatusKnownFixed}, {401, StatusKnownChanged}, {502, StatusKnownChanged}} {
		t.Run(string(tt.want), func(t *testing.T) {
			got, _ := Classify(s, &expect.Observation{Status: tt.status}, nil)
			if got != tt.want {
				t.Errorf("status %d: got %s, want %s", tt.status, got, tt.want)
			}
		})
	}
}

func TestNewResult(t *testing.T) {
	s := &scenario.Scenario{ID: "GH-C51.pr-list", Claim: "GH-C51", Kind: "gh", Expect: &scenario.Expect{ExitCode: intp(0)}}
	o := &expect.Observation{GHExit: intp(1), Exchanges: []ghdebug.Exchange{
		{Method: "GET", Path: "/api/v3/repos/o/a", Status: 200},
		{Method: "POST", Path: "/api/graphql", Status: 403, ResponseBody: `{"message":"denied ghx_abcdefghijk"}`},
	}}
	r := NewResult(s, o, nil)
	if r.Status != StatusFail || r.GHExit == nil || *r.GHExit != 1 {
		t.Fatalf("got %+v", r)
	}
	if want := "POST /api/graphql 403 denied ghx_[REDACTED]"; r.FirstDeniedExchange != want {
		t.Errorf("first denied = %q, want %q", r.FirstDeniedExchange, want)
	}
}
