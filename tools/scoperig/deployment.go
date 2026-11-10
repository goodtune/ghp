package main

// Operator-declared deployment features (ENT-C50, BORDER-C46): capability
// derivation, the GHP metrics scrape behind metric_delta, and the --claims
// paste-back summary. Design: docs/superpowers/specs/2026-11-10-rig-enterprise-design.md.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/goodtune/ghp/tools/scoperig/redact"
	"github.com/goodtune/ghp/tools/scoperig/report"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

// repoSpecRE is an "owner/name" repository.
var repoSpecRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// loadDeployment validates the deployment fields of fc into c.
func loadDeployment(c *Config, fc fileConfig) error {
	in := fc.Instance
	c.AnonymousGit = in.AnonymousGit
	c.MetricsURL = strings.TrimSpace(in.MetricsURL)
	if c.MetricsURL != "" {
		u, err := url.Parse(c.MetricsURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("instance.metrics_url must be an http(s) URL without credentials, query or fragment (the GHP metrics listener, for example http://ghp.internal:9136/metrics)")
		}
	}
	er := in.EnterpriseRestriction
	for _, f := range []struct {
		key string
		in  string
		out *string
	}{
		{"restricted_repo", er.RestrictedRepo, &c.Enterprise.RestrictedRepo},
		{"omit_repo", er.OmitRepo, &c.Enterprise.OmitRepo},
		{"team_denied_repo", er.TeamDeniedRepo, &c.Enterprise.TeamDeniedRepo},
		{"identity_repo", er.IdentityRepo, &c.Enterprise.IdentityRepo},
		{"unauthenticated_repo", er.UnauthenticatedRepo, &c.Enterprise.UnauthenticatedRepo},
	} {
		v := strings.TrimSpace(f.in)
		if v != "" && !repoSpecRE.MatchString(v) {
			return fmt.Errorf("instance.enterprise_restriction.%s must be owner/name, got %q", f.key, v)
		}
		*f.out = v
	}
	return nil
}

// deploymentCapabilities derives the operator-declared capabilities. Nothing
// is probed. Every key in scenario.DeploymentCapabilities is present.
func deploymentCapabilities(c *Config) Capabilities {
	e := c.Enterprise
	metrics := c.MetricsURL != ""
	restriction := metrics && e.RestrictedRepo != ""
	return Capabilities{
		"anonymous_git":                        c.AnonymousGit,
		"ghp_metrics":                          metrics,
		"enterprise_restriction":               restriction,
		"enterprise_exception_omit":            restriction && e.OmitRepo != "",
		"enterprise_exception_team_denied":     restriction && e.TeamDeniedRepo != "",
		"enterprise_exception_identity":        restriction && e.IdentityRepo != "",
		"enterprise_exception_unauthenticated": restriction && e.UnauthenticatedRepo != "",
	}
}

// metricSet is one scrape of the GHP metrics listener.
type metricSet map[string]*dto.MetricFamily

// maxScrape caps a metrics response.
const maxScrape = 16 << 20

func parseMetrics(r io.Reader) (metricSet, error) {
	p := expfmt.NewTextParser(model.UTF8Validation)
	fams, err := p.TextToMetricFamilies(r)
	if err != nil {
		return nil, fmt.Errorf("parse metrics: %w", err)
	}
	return metricSet(fams), nil
}

// scrapeMetrics reads u (text exposition format). It sends no credential.
func scrapeMetrics(ctx context.Context, hc *http.Client, u string) (metricSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain;version=0.0.4")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scrape instance.metrics_url: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scrape instance.metrics_url: status %d", resp.StatusCode)
	}
	return parseMetrics(io.LimitReader(resp.Body, maxScrape))
}

// sum adds every sample of name whose labels include want. A histogram or
// summary sample count is addressed as <family>_count. Absent is 0.
func (m metricSet) sum(name string, want map[string]string) float64 {
	fam, count := m[name], false
	if fam == nil {
		if base, ok := strings.CutSuffix(name, "_count"); ok {
			if f := m[base]; f != nil && (f.GetType() == dto.MetricType_HISTOGRAM || f.GetType() == dto.MetricType_SUMMARY) {
				fam, count = f, true
			}
		}
	}
	if fam == nil {
		return 0
	}
	var total float64
	for _, s := range fam.GetMetric() {
		if !hasLabels(s, want) {
			continue
		}
		switch {
		case count && s.GetHistogram() != nil:
			total += float64(s.GetHistogram().GetSampleCount())
		case count && s.GetSummary() != nil:
			total += float64(s.GetSummary().GetSampleCount())
		case s.GetCounter() != nil:
			total += s.GetCounter().GetValue()
		case s.GetGauge() != nil:
			total += s.GetGauge().GetValue()
		case s.GetUntyped() != nil:
			total += s.GetUntyped().GetValue()
		}
	}
	return total
}

func hasLabels(s *dto.Metric, want map[string]string) bool {
	for k, v := range want {
		found := false
		for _, lp := range s.GetLabel() {
			if lp.GetName() == k && lp.GetValue() == v {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// checkMetricDeltas returns one message per delta outside its bounds.
func checkMetricDeltas(before, after metricSet, deltas []scenario.MetricDelta) []string {
	var msgs []string
	for _, d := range deltas {
		got := after.sum(d.Name, d.Labels) - before.sum(d.Name, d.Labels)
		if d.Min != nil && got < float64(*d.Min) {
			msgs = append(msgs, fmt.Sprintf("metric %s: want change >= %d, got %g", series(d), *d.Min, got))
		}
		if d.Max != nil && got > float64(*d.Max) {
			msgs = append(msgs, fmt.Sprintf("metric %s: want change <= %d, got %g", series(d), *d.Max, got))
		}
	}
	return msgs
}

// series names d for a report line. The "ghp_" prefix is dropped: report
// text passes through redact.String, which masks anything shaped like
// "ghp_" plus eight word characters, metric names included.
func series(d scenario.MetricDelta) string {
	keys := make([]string, 0, len(d.Labels))
	for k := range d.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%q", k, d.Labels[k])
	}
	return strings.TrimPrefix(d.Name, "ghp_") + "{" + strings.Join(parts, ",") + "}"
}

// metricsBefore scrapes before a scenario with metric_delta. ok is false
// (and the message set) when the scenario must be reported as ERROR.
func metricsBefore(ctx context.Context, s *scenario.Scenario, deps runDeps) (metricSet, string) {
	if len(s.MetricDelta) == 0 {
		return nil, ""
	}
	if deps.Scrape == nil {
		return nil, "metric_delta: instance.metrics_url is not set"
	}
	m, err := deps.Scrape(ctx)
	if err != nil {
		return nil, "metric_delta (before): " + err.Error()
	}
	return m, ""
}

// applyMetricDeltas scrapes again and turns a PASS into FAIL (or ERROR when
// the scrape fails) if a delta is out of range. Other statuses keep theirs
// with the metric messages appended to the detail.
func applyMetricDeltas(ctx context.Context, s *scenario.Scenario, deps runDeps, before metricSet, r report.ScenarioResult) report.ScenarioResult {
	if len(s.MetricDelta) == 0 || before == nil {
		return r
	}
	after, err := deps.Scrape(ctx)
	if err != nil {
		msg := redact.String("metric_delta (after): " + err.Error())
		if r.Status == report.StatusPass {
			r.Status, r.Error = report.StatusError, msg
			r.Detail = msg
		}
		return r
	}
	msgs := checkMetricDeltas(before, after, s.MetricDelta)
	if len(msgs) == 0 {
		return r
	}
	detail := strings.Join(msgs, "; ")
	if r.Status == report.StatusPass {
		r.Status, r.Detail = report.StatusFail, detail
		return r
	}
	r.Detail = strings.TrimSpace(r.Detail + "; " + detail)
	return r
}

// splitList splits a comma-separated flag value, dropping empty items.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// checkClaims rejects --claims entries that are not in claims.yaml.
func checkClaims(t *scenario.Tree, ids []string) error {
	for _, id := range ids {
		if _, ok := t.Claims[id]; !ok {
			return fmt.Errorf("--claims: unknown claim %s", id)
		}
	}
	return nil
}

// restrictClaims keeps only the claims named in ids (all when ids is empty).
func restrictClaims(claims []report.ClaimResult, ids []string) []report.ClaimResult {
	if len(ids) == 0 {
		return claims
	}
	keep := map[string]bool{}
	for _, id := range ids {
		keep[id] = true
	}
	out := make([]report.ClaimResult, 0, len(ids))
	for _, c := range claims {
		if keep[c.ID] {
			out = append(out, c)
		}
	}
	return out
}

// writePasteBack writes the one-line machine-readable result for --claims.
// It holds no instance host and no token: only statuses and redacted detail.
func writePasteBack(w io.Writer, rep *report.Report, code int) error {
	type sc struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Detail string `json:"detail,omitempty"`
	}
	out := struct {
		RunID      string            `json:"run_id"`
		GHPVersion string            `json:"ghp_version"`
		ExitCode   int               `json:"exit_code"`
		Claims     map[string]string `json:"claims"`
		Scenarios  []sc              `json:"scenarios"`
		Tokens     string            `json:"tokens"`
	}{RunID: rep.RunID, GHPVersion: rep.GHPVersion, ExitCode: code, Claims: map[string]string{}, Scenarios: []sc{},
		Tokens: fmt.Sprintf("%d created, %d revoked, %d leftover", rep.Tokens.Created, rep.Tokens.Revoked, len(rep.Tokens.LeftoverIDs))}
	for _, c := range rep.Claims {
		out.Claims[c.ID] = string(c.Status)
		for _, s := range c.Scenarios {
			out.Scenarios = append(out.Scenarios, sc{ID: s.ID, Status: string(s.Status), Detail: redact.String(s.Detail)})
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "\nscoperig-result: %s\n", b)
	return err
}
