package scenario

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func intp(n int) *int { return &n }

func TestValidate_MetricDelta(t *testing.T) {
	ok := MetricDelta{Name: "ghp_enterprise_exception_total", Labels: map[string]string{"outcome": "header_omitted"}, Min: intp(1)}
	tests := []struct {
		name    string
		reqs    []string
		deltas  []MetricDelta
		wantErr string
	}{
		{"valid", []string{"ghp_metrics"}, []MetricDelta{ok}, ""},
		{"needs ghp_metrics", nil, []MetricDelta{ok}, "metric_delta needs requires: [ghp_metrics]"},
		{"needs a name", []string{"ghp_metrics"}, []MetricDelta{{Min: intp(1)}}, "metric_delta[0]: name is required"},
		{"bad name", []string{"ghp_metrics"}, []MetricDelta{{Name: "x{y}", Min: intp(1)}}, "not a Prometheus metric name"},
		{"needs a bound", []string{"ghp_metrics"}, []MetricDelta{{Name: "ghp_x"}}, "min or max is required"},
		{"min above max", []string{"ghp_metrics"}, []MetricDelta{{Name: "ghp_x", Min: intp(2), Max: intp(1)}}, "min 2 is above max 1"},
		{"interference needs max", []string{"ghp_metrics"}, []MetricDelta{{Name: "ghp_x", Min: intp(1), Interference: true}}, "interference needs max"},
		{"negative", []string{"ghp_metrics"}, []MetricDelta{{Name: "ghp_x", Max: intp(-1)}}, "must not be negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scenario{ID: "C1.x", Claim: "C1", Profile: "all", Kind: "rest", Method: "GET", Path: "/user",
				Requires: tt.reqs, MetricDelta: tt.deltas}
			errs := Validate(withScenarios(s), nil)
			if tt.wantErr == "" {
				if len(errs) != 0 {
					t.Fatalf("unexpected errors: %v", errs)
				}
				return
			}
			requireErr(t, errs, tt.wantErr)
		})
	}
}

func TestValidate_DeploymentCapabilitiesKnown(t *testing.T) {
	for _, c := range DeploymentCapabilities {
		reqs := []string{c}
		if c != "ghp_metrics" {
			reqs = append(reqs, "ghp_metrics")
		}
		s := &Scenario{ID: "C1.x", Claim: "C1", Profile: "all", Kind: "rest", Method: "GET", Path: "/user", Requires: reqs}
		if errs := Validate(withScenarios(s), nil); len(errs) != 0 {
			t.Errorf("requires %s: %v", c, errs)
		}
	}
}

func TestValidate_EnterpriseTemplates(t *testing.T) {
	s := &Scenario{ID: "C1.x", Claim: "C1", Profile: "all", Kind: "rest", Method: "GET",
		Path: "/repos/{{.Enterprise.RestrictedRepo}}/{{.Enterprise.OmitRepo}}/{{.Enterprise.TeamDeniedRepo}}/{{.Enterprise.IdentityRepo}}/{{.Enterprise.UnauthenticatedRepo}}"}
	if errs := Validate(withScenarios(s), nil); len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
}

func TestMetricDelta_YAML(t *testing.T) {
	var s Scenario
	src := "metric_delta:\n  - {name: ghp_x_total, labels: {outcome: a}, min: 1, max: 0}\n"
	if err := yaml.Unmarshal([]byte(src), &s); err != nil {
		t.Fatal(err)
	}
	if len(s.MetricDelta) != 1 || s.MetricDelta[0].Name != "ghp_x_total" || s.MetricDelta[0].Labels["outcome"] != "a" ||
		*s.MetricDelta[0].Min != 1 || *s.MetricDelta[0].Max != 0 {
		t.Fatalf("decoded %+v", s.MetricDelta)
	}
}
