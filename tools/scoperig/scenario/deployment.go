package scenario

import (
	"fmt"
	"regexp"
	"slices"
)

// DeploymentCapabilities are operator-declared instance features (rig
// config, never probed). Undeclared means false, so their scenarios
// report GAP. See docs/development/scope-regression-rig-enterprise.md.
var DeploymentCapabilities = []string{
	"anonymous_git",                        // instance.anonymous_git
	"ghp_metrics",                          // instance.metrics_url
	"enterprise_restriction",               // metrics_url + enterprise_restriction.restricted_repo
	"enterprise_exception_omit",            // + omit_repo
	"enterprise_exception_team_denied",     // + team_denied_repo
	"enterprise_exception_identity",        // + identity_repo
	"enterprise_exception_unauthenticated", // + unauthenticated_repo
}

func init() {
	for _, c := range DeploymentCapabilities {
		validCapabilities[c] = true
	}
}

// EnterpriseVals are the instance.enterprise_restriction target
// repositories ("owner/name"), as {{.Enterprise.*}} in templates.
type EnterpriseVals struct {
	RestrictedRepo, OmitRepo, TeamDeniedRepo, IdentityRepo, UnauthenticatedRepo string
}

// placeholderEnterprise fills PlaceholderVars.
var placeholderEnterprise = EnterpriseVals{
	RestrictedRepo: "ent-owner/restricted", OmitRepo: "ent-owner/omit", TeamDeniedRepo: "ent-owner/team-denied",
	IdentityRepo: "ent-owner/identity", UnauthenticatedRepo: "ent-owner/unauthenticated",
}

// MetricDelta asserts how much a GHP Prometheus metric changes across a
// scenario. The rig scrapes instance.metrics_url before and after, and
// sums every sample of Name whose labels include Labels. Min and Max are
// inclusive bounds on the change; at least one is required.
type MetricDelta struct {
	Name   string            `yaml:"name"`
	Labels map[string]string `yaml:"labels"`
	Min    *int              `yaml:"min"`
	Max    *int              `yaml:"max"`
	// Interference marks a change above Max as other traffic on the
	// instance, not a defect: the scenario is ERROR (rerun on a quiet
	// instance) instead of FAIL. Needs Max.
	Interference bool `yaml:"interference"`
}

var metricNameRE = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

// checkMetricDelta validates s.MetricDelta.
func checkMetricDelta(s *Scenario) []string {
	if len(s.MetricDelta) == 0 {
		return nil
	}
	var msgs []string
	add := func(format string, a ...any) { msgs = append(msgs, fmt.Sprintf(format, a...)) }
	if !slices.Contains(s.Requires, "ghp_metrics") {
		add("metric_delta needs requires: [ghp_metrics]")
	}
	for i, d := range s.MetricDelta {
		w := fmt.Sprintf("metric_delta[%d]", i)
		switch {
		case d.Name == "":
			add("%s: name is required", w)
		case !metricNameRE.MatchString(d.Name):
			add("%s: %q is not a Prometheus metric name", w, d.Name)
		}
		if d.Min == nil && d.Max == nil {
			add("%s: min or max is required", w)
		}
		if (d.Min != nil && *d.Min < 0) || (d.Max != nil && *d.Max < 0) {
			add("%s: min and max must not be negative", w)
		}
		if d.Interference && d.Max == nil {
			add("%s: interference needs max", w)
		}
		if d.Min != nil && d.Max != nil && *d.Min > *d.Max {
			add("%s: min %d is above max %d", w, *d.Min, *d.Max)
		}
	}
	return msgs
}
