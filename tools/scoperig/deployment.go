package main

// Operator-declared deployment features (ENT-C50, BORDER-C46): capability
// derivation, the GHP metrics scrape behind metric_delta, and the --claims
// paste-back summary. Design: docs/superpowers/specs/2026-11-10-rig-enterprise-design.md.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/goodtune/ghp/internal/asciiutil"
	"github.com/goodtune/ghp/tools/scoperig/exec"
	"github.com/goodtune/ghp/tools/scoperig/expect"
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

// checkMetricDeltas returns one message per delta outside its bounds:
// fails are defects; interference holds changes above max on a delta
// marked interference (other traffic on the instance).
func checkMetricDeltas(before, after metricSet, deltas []scenario.MetricDelta) (fails, interference []string) {
	for _, d := range deltas {
		got := after.sum(d.Name, d.Labels) - before.sum(d.Name, d.Labels)
		if d.Min != nil && got < float64(*d.Min) {
			fails = append(fails, fmt.Sprintf("metric %s: want change >= %d, got %g", series(d), *d.Min, got))
		}
		if d.Max != nil && got > float64(*d.Max) {
			if d.Interference {
				interference = append(interference, fmt.Sprintf("metric %s: changed by %g, more than this request's %d: other traffic on the instance; rerun when it is quiet", series(d), got, *d.Max))
			} else {
				fails = append(fails, fmt.Sprintf("metric %s: want change <= %d, got %g", series(d), *d.Max, got))
			}
		}
	}
	return fails, interference
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
			r.Reasons = []string{reasonScrape}
		}
		return r
	}
	msgs, inter := checkMetricDeltas(before, after, s.MetricDelta)
	failR, interR := metricDeltaReasons(before, after, s.MetricDelta)
	if len(inter) > 0 {
		// The counters cannot be attributed to this request: not a verdict.
		detail := strings.Join(inter, "; ")
		r.Status, r.Detail, r.Error = report.StatusError, detail, detail
		r.Reasons = interR
		return r
	}
	if len(msgs) == 0 {
		return r
	}
	detail := strings.Join(msgs, "; ")
	if r.Status == report.StatusPass {
		r.Status, r.Detail = report.StatusFail, detail
		r.Reasons = failR
		return r
	}
	r.Detail = strings.TrimSpace(r.Detail + "; " + detail)
	r.Reasons = append(r.Reasons, failR...)
	return r
}

// Paste-back reasons. Every reason is built by the rig from a fixed
// vocabulary and from scenario YAML only: never from a response, an error
// message, scraped output or a config value.
const (
	reasonTransport = "transport_error"
	reasonScrape    = "metrics_scrape_error"
	reasonOther     = "other"
)

// yamlToken prints a scenario YAML value, or "<template>" when it is
// templated (it could expand to a config value).
func yamlToken(v string) string {
	if strings.Contains(v, "{{") {
		return "<template>"
	}
	return v
}

// verdictReasons explains a non-PASS verdict from the scenario's own
// expectation and the observed status. rerr other than a step failure is a
// transport error.
func verdictReasons(s *scenario.Scenario, obs *expect.Observation, rerr error) []string {
	var sf exec.StepFailure
	if rerr != nil && !errors.As(rerr, &sf) {
		return []string{reasonTransport}
	}
	e := s.VerdictExpect()
	if obs == nil || e == nil || rerr != nil {
		return []string{reasonOther}
	}
	var out []string
	if e.Status != 0 && obs.Status != e.Status {
		out = append(out, fmt.Sprintf("http_status want=%d got=%d", e.Status, obs.Status))
	}
	if len(e.StatusIn) > 0 && !slices.Contains(e.StatusIn, obs.Status) {
		ws := make([]string, len(e.StatusIn))
		for i, v := range e.StatusIn {
			ws[i] = fmt.Sprint(v)
		}
		out = append(out, fmt.Sprintf("http_status want_in=%s got=%d", strings.Join(ws, ","), obs.Status))
	}
	if e.GHPDenial != nil {
		if got := expect.IsGHPDenialResponse(obs.Status, obs.Body); got != *e.GHPDenial {
			out = append(out, fmt.Sprintf("ghp_denial want=%t got=%t", *e.GHPDenial, got))
		}
	}
	for _, c := range e.BodyContains {
		if !bytes.Contains(obs.Body, []byte(c)) {
			out = append(out, "body_contains mismatch")
			break
		}
	}
	for _, c := range e.BodyNotContains {
		if bytes.Contains(obs.Body, []byte(c)) {
			out = append(out, "body_not_contains mismatch")
			break
		}
	}
	keys := make([]string, 0, len(e.Header))
	for k := range e.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if obs.Header.Get(k) != e.Header[k] {
			out = append(out, "header "+yamlToken(k)+" mismatch")
		}
	}
	if len(out) == 0 {
		return []string{reasonOther}
	}
	return out
}

// metricReason is one metric_delta reason.
func metricReason(d scenario.MetricDelta, got float64) string {
	keys := make([]string, 0, len(d.Labels))
	for k := range d.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%q", yamlToken(k), yamlToken(d.Labels[k]))
	}
	want := ""
	switch {
	case d.Min != nil && got < float64(*d.Min):
		want = fmt.Sprintf("want_delta>=%d", *d.Min)
	case d.Max != nil:
		want = fmt.Sprintf("want_delta<=%d", *d.Max)
	}
	return fmt.Sprintf("metric %s{%s} %s got_delta=%g", yamlToken(d.Name), strings.Join(parts, ","), want, got)
}

// metricDeltaReasons mirrors checkMetricDeltas with paste-back reasons.
func metricDeltaReasons(before, after metricSet, deltas []scenario.MetricDelta) (fails, interference []string) {
	for _, d := range deltas {
		got := after.sum(d.Name, d.Labels) - before.sum(d.Name, d.Labels)
		switch {
		case d.Min != nil && got < float64(*d.Min):
			fails = append(fails, metricReason(d, got))
		case d.Max != nil && got > float64(*d.Max) && d.Interference:
			interference = append(interference, "interference "+metricReason(d, got))
		case d.Max != nil && got > float64(*d.Max):
			fails = append(fails, metricReason(d, got))
		}
	}
	return fails, interference
}

// gapReasons names the unmet capabilities (names from scenario YAML).
func gapReasons(reqs []string, caps Capabilities) []string {
	var out []string
	for _, r := range reqs {
		if !caps[r] {
			out = append(out, "capability_missing "+yamlToken(r))
		}
	}
	return out
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

// pasteBackHosts lists the hosts writePasteBack must hide: the instance
// host, the GHP_SERVER_URL host and the metrics_url host, each with and
// without its port.
func pasteBackHosts(c *Config) []string {
	out := []string{c.Instance.Host}
	for _, raw := range []string{c.ServerURL, c.MetricsURL} {
		if u, err := url.Parse(raw); err == nil {
			out = append(out, u.Host)
		}
	}
	return withBareHosts(out)
}

// withBareHosts adds the port-less name of every host:port entry.
func withBareHosts(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		if h == "" {
			continue
		}
		out = append(out, h)
		if name, _, err := net.SplitHostPort(h); err == nil && name != "" {
			out = append(out, name)
		}
	}
	return out
}

// pasteScrub hides deployment details in the paste-back line: configured
// hosts become <host>, configured enterprise repositories (and their bare
// owners) become <repo>, and IP address literals become <addr>. Matching is
// ASCII case-insensitive. The JSON report keeps the full detail.
type pasteScrub struct {
	hosts []string
	repos []string // owner/name
}

func newPasteScrub(c *Config) pasteScrub {
	e := c.Enterprise
	var repos []string
	for _, r := range []string{e.RestrictedRepo, e.OmitRepo, e.TeamDeniedRepo, e.IdentityRepo, e.UnauthenticatedRepo, c.RepoA, c.RepoB, c.RepoW} {
		if r != "" {
			repos = append(repos, r)
		}
	}
	return pasteScrub{hosts: pasteBackHosts(c), repos: repos}
}

// ipCandidate finds text that may be an IP literal, with an optional port;
// net.ParseIP confirms it, so times such as 15:04:25 are left alone.
var ipCandidate = regexp.MustCompile(`\[[0-9A-Fa-f:.]+\](?::\d+)?|[0-9A-Fa-f]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f.]*|\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?`)

func (p pasteScrub) apply(s string) string {
	hs := withBareHosts(p.hosts)
	sort.Slice(hs, func(i, j int) bool { return len(hs[i]) > len(hs[j]) })
	for _, h := range hs {
		s = replaceFold(s, h, "<host>", false)
	}
	var parts []string
	for _, r := range p.repos {
		s = replaceFold(s, r, "<repo>", true)
		s = replaceFold(s, strings.Replace(r, "/", "%2F", 1), "<repo>", true)
		if o, n, ok := strings.Cut(r, "/"); ok {
			parts = append(parts, o, n)
		}
	}
	for _, x := range parts {
		s = replaceFold(s, x, "<repo>", true)
	}
	return ipCandidate.ReplaceAllStringFunc(s, func(m string) string {
		host := strings.TrimSuffix(strings.TrimPrefix(m, "["), "]")
		if h, _, err := net.SplitHostPort(m); err == nil {
			host = h
		}
		if net.ParseIP(host) != nil {
			return "<addr>"
		}
		return m
	})
}

// replaceFold replaces old in s, ASCII case-insensitively (asciiutil, never
// Unicode folding). With bounded, a match must not touch a name character
// (letter, digit, '-' or '_') on either side; '.' is a boundary, so
// "R.git" and a sentence-ending "R." match.
func replaceFold(s, old, repl string, bounded bool) string {
	if old == "" {
		return s
	}
	ls, lo := asciiutil.ToLower(s), asciiutil.ToLower(old)
	var b strings.Builder
	i := 0
	for {
		j := strings.Index(ls[i:], lo)
		if j < 0 {
			break
		}
		j += i
		k := j + len(lo)
		if bounded && ((j > 0 && isNameByte(s[j-1])) || (k < len(s) && isNameByte(s[k]))) {
			b.WriteString(s[i : j+1])
			i = j + 1
			continue
		}
		b.WriteString(s[i:j])
		b.WriteString(repl)
		i = k
	}
	b.WriteString(s[i:])
	return b.String()
}

func isNameByte(c byte) bool {
	return c == '-' || c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// writePasteBack writes the one-line machine-readable result for --claims.
// It is an allowlist: run id, GHP version, exit code, token counts, and per
// scenario only its id, status and rig-generated reasons (Reasons, else
// "other"). No Detail, Error or other free text. The finished line also
// passes through scrub as a second layer.
func writePasteBack(w io.Writer, rep *report.Report, code int, scrub pasteScrub) error {
	type sc struct {
		ID      string   `json:"id"`
		Status  string   `json:"status"`
		Reasons []string `json:"reasons,omitempty"`
	}
	out := struct {
		RunID      string            `json:"run_id"`
		GHPVersion string            `json:"ghp_version"`
		ExitCode   int               `json:"exit_code"`
		Claims     map[string]string `json:"claims"`
		Scenarios  []sc              `json:"scenarios"`
		Tokens     string            `json:"tokens"`
		Note       string            `json:"note,omitempty"`
	}{RunID: rep.RunID, GHPVersion: rep.GHPVersion, ExitCode: code, Claims: map[string]string{}, Scenarios: []sc{},
		Tokens: fmt.Sprintf("%d created, %d revoked, %d leftover", rep.Tokens.Created, rep.Tokens.Revoked, len(rep.Tokens.LeftoverIDs))}
	for _, c := range rep.Claims {
		out.Claims[c.ID] = string(c.Status)
		for _, s := range c.Scenarios {
			reasons := s.Reasons
			if len(reasons) == 0 && s.Status != report.StatusPass {
				reasons = []string{reasonOther}
			}
			if slices.Contains(reasons, reasonOther) {
				out.Note = "see the JSON report locally"
			}
			out.Scenarios = append(out.Scenarios, sc{ID: s.ID, Status: string(s.Status), Reasons: reasons})
		}
	}
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false) // keep "<host>" readable when pasted
	if err := enc.Encode(out); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "\nscoperig-result: %s", scrub.apply(b.String()))
	return err
}
