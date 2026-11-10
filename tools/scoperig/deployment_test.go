package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/report"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

func writeDeploymentCfg(t *testing.T, extra string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	body := "instance:\n  host: ghp.example.test\n" + extra + "fixtures:\n  repo_a: o/a\n  repo_b: o/b\n  repo_w: o/w\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfig_Deployment(t *testing.T) {
	full := `  anonymous_git: true
  metrics_url: http://ghp.example.test:9136/metrics
  enterprise_restriction:
    restricted_repo: ent/restricted
    omit_repo: ext/omit
    team_denied_repo: ext/team
    identity_repo: ext/identity
    unauthenticated_repo: ext/anon
`
	tests := []struct {
		name    string
		extra   string
		wantErr string
	}{
		{"none declared", "", ""},
		{"all declared", full, ""},
		{"bad metrics scheme", "  metrics_url: ftp://h/metrics\n", "instance.metrics_url"},
		{"metrics credentials", "  metrics_url: https://u:p@h/metrics\n", "instance.metrics_url"},
		{"metrics query", "  metrics_url: https://h/metrics?x=1\n", "instance.metrics_url"},
		{"bad repo", "  enterprise_restriction:\n    omit_repo: noslash\n", "instance.enterprise_restriction.omit_repo"},
		{"repo with path", "  enterprise_restriction:\n    identity_repo: a/b/c\n", "instance.enterprise_restriction.identity_repo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := LoadConfig(envMap(nil), writeDeploymentCfg(t, tt.extra))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.extra == full {
				want := scenario.EnterpriseVals{RestrictedRepo: "ent/restricted", OmitRepo: "ext/omit",
					TeamDeniedRepo: "ext/team", IdentityRepo: "ext/identity", UnauthenticatedRepo: "ext/anon"}
				if !c.AnonymousGit || c.MetricsURL != "http://ghp.example.test:9136/metrics" || c.Enterprise != want {
					t.Fatalf("got anonymous_git=%v metrics_url=%q enterprise=%+v", c.AnonymousGit, c.MetricsURL, c.Enterprise)
				}
			}
		})
	}
}

func TestDeploymentCapabilities(t *testing.T) {
	all := scenario.EnterpriseVals{RestrictedRepo: "e/r", OmitRepo: "x/o", TeamDeniedRepo: "x/t", IdentityRepo: "x/i", UnauthenticatedRepo: "x/u"}
	tests := []struct {
		name string
		c    Config
		want []string // capabilities that must be true; every other one false
	}{
		{"nothing declared", Config{}, nil},
		{"anonymous git only", Config{AnonymousGit: true}, []string{"anonymous_git"}},
		{"repos without metrics", Config{Enterprise: all}, nil},
		{"metrics without restricted repo", Config{MetricsURL: "http://m/metrics", Enterprise: scenario.EnterpriseVals{OmitRepo: "x/o"}},
			[]string{"ghp_metrics"}},
		{"restriction only", Config{MetricsURL: "http://m/metrics", Enterprise: scenario.EnterpriseVals{RestrictedRepo: "e/r"}},
			[]string{"ghp_metrics", "enterprise_restriction"}},
		{"everything", Config{AnonymousGit: true, MetricsURL: "http://m/metrics", Enterprise: all},
			[]string{"anonymous_git", "ghp_metrics", "enterprise_restriction", "enterprise_exception_omit",
				"enterprise_exception_team_denied", "enterprise_exception_identity", "enterprise_exception_unauthenticated"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deploymentCapabilities(&tt.c)
			if len(got) != len(scenario.DeploymentCapabilities) {
				t.Fatalf("got %d capabilities, want %d", len(got), len(scenario.DeploymentCapabilities))
			}
			want := map[string]bool{}
			for _, w := range tt.want {
				want[w] = true
			}
			for _, c := range scenario.DeploymentCapabilities {
				if got[c] != want[c] {
					t.Errorf("%s = %v, want %v", c, got[c], want[c])
				}
			}
		})
	}
}

const sampleMetrics = `# HELP ghp_enterprise_exception_total x
# TYPE ghp_enterprise_exception_total counter
ghp_enterprise_exception_total{outcome="header_omitted"} 3
ghp_enterprise_exception_total{outcome="team_denied"} 1
# HELP ghp_proxy_decision_duration_seconds x
# TYPE ghp_proxy_decision_duration_seconds histogram
ghp_proxy_decision_duration_seconds_bucket{stage="enterprise_exception",token_type="proxy",vhost="management",le="+Inf"} 4
ghp_proxy_decision_duration_seconds_sum{stage="enterprise_exception",token_type="proxy",vhost="management"} 0.01
ghp_proxy_decision_duration_seconds_count{stage="enterprise_exception",token_type="proxy",vhost="management"} 4
ghp_proxy_decision_duration_seconds_bucket{stage="enterprise_exception",token_type="unknown",vhost="web",le="+Inf"} 2
ghp_proxy_decision_duration_seconds_sum{stage="enterprise_exception",token_type="unknown",vhost="web"} 0.01
ghp_proxy_decision_duration_seconds_count{stage="enterprise_exception",token_type="unknown",vhost="web"} 2
ghp_proxy_decision_duration_seconds_bucket{stage="total",token_type="proxy",vhost="management",le="+Inf"} 9
ghp_proxy_decision_duration_seconds_sum{stage="total",token_type="proxy",vhost="management"} 0.01
ghp_proxy_decision_duration_seconds_count{stage="total",token_type="proxy",vhost="management"} 9
`

func TestParseMetrics_Sum(t *testing.T) {
	set, err := parseMetrics(strings.NewReader(sampleMetrics))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		metric string
		labels map[string]string
		want   float64
	}{
		{"counter by label", "ghp_enterprise_exception_total", map[string]string{"outcome": "header_omitted"}, 3},
		{"counter all", "ghp_enterprise_exception_total", nil, 4},
		{"absent series is zero", "ghp_enterprise_exception_total", map[string]string{"outcome": "identity_substituted"}, 0},
		{"absent family is zero", "ghp_nope_total", nil, 0},
		{"histogram count summed", "ghp_proxy_decision_duration_seconds_count", map[string]string{"stage": "enterprise_exception"}, 6},
		{"histogram count narrowed", "ghp_proxy_decision_duration_seconds_count", map[string]string{"stage": "enterprise_exception", "vhost": "web"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := set.sum(tt.metric, tt.labels); got != tt.want {
				t.Errorf("sum = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckMetricDeltas(t *testing.T) {
	before, _ := parseMetrics(strings.NewReader("ghp_x_total{outcome=\"a\"} 1\nghp_x_total{outcome=\"b\"} 5\n"))
	after, _ := parseMetrics(strings.NewReader("ghp_x_total{outcome=\"a\"} 2\nghp_x_total{outcome=\"b\"} 5\n"))
	one, zero := 1, 0
	tests := []struct {
		name string
		d    scenario.MetricDelta
		want string // "" = holds
	}{
		{"min holds", scenario.MetricDelta{Name: "ghp_x_total", Labels: map[string]string{"outcome": "a"}, Min: &one}, ""},
		{"max holds", scenario.MetricDelta{Name: "ghp_x_total", Labels: map[string]string{"outcome": "b"}, Max: &zero}, ""},
		{"min fails", scenario.MetricDelta{Name: "ghp_x_total", Labels: map[string]string{"outcome": "b"}, Min: &one},
			`metric x_total{outcome="b"}: want change >= 1, got 0`},
		{"max fails", scenario.MetricDelta{Name: "ghp_x_total", Labels: map[string]string{"outcome": "a"}, Max: &zero},
			`metric x_total{outcome="a"}: want change <= 0, got 1`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := checkMetricDeltas(before, after, []scenario.MetricDelta{tt.d})
			switch {
			case tt.want == "" && len(got) != 0:
				t.Errorf("got %v, want none", got)
			case tt.want != "" && (len(got) != 1 || got[0] != tt.want):
				t.Errorf("got %v, want [%s]", got, tt.want)
			}
		})
	}
}

func TestSplitList(t *testing.T) {
	if got := splitList(" ENT-C50, BORDER-C46 ,,"); strings.Join(got, "|") != "ENT-C50|BORDER-C46" {
		t.Errorf("splitList = %v", got)
	}
}

// --- end-to-end against the fake instance ---

// fakeMetrics is a GHP metrics listener whose counters the fake instance
// moves when it sees enterprise traffic.
type fakeMetrics struct {
	mu   sync.Mutex
	vals map[string]float64 // series text -> value
	ts   *httptest.Server
}

func newFakeMetrics(t *testing.T) *fakeMetrics {
	m := &fakeMetrics{vals: map[string]float64{}}
	m.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" || r.Header.Get("Authorization") != "" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		for k, v := range m.vals {
			_, _ = fmt.Fprintf(w, "%s %v\n", k, v)
		}
	}))
	t.Cleanup(m.ts.Close)
	return m
}

func (m *fakeMetrics) inc(outcome string) { m.incAt("management", "proxy", outcome) }

func (m *fakeMetrics) incAt(vhost, tokenType, outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vals[fmt.Sprintf(`ghp_proxy_decision_duration_seconds_count{stage="enterprise_exception",token_type=%q,vhost=%q}`, tokenType, vhost)]++
	if outcome != "" {
		m.vals[fmt.Sprintf(`ghp_enterprise_exception_total{outcome=%q}`, outcome)]++
	}
}

// newFakeGHPVhost is newFakeGHP with a certificate that also covers
// github.com, so the github_vhost probe and vhost scenarios work.
func newFakeGHPVhost(t *testing.T) *fakeGHP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"github.com"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGHP{t: t, tokens: map[string]*fakeTok{}}
	f.ts = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.ts.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	f.ts.StartTLS()
	t.Cleanup(f.ts.Close)
	return f
}

// writeEnterpriseTree writes claims, profiles, the checked-in
// rig/scenarios/enterprise.yaml and a config with extra instance lines.
func writeEnterpriseTree(t *testing.T, host, extra string) (root, cfg string) {
	t.Helper()
	src, err := os.ReadFile("../../rig/scenarios/enterprise.yaml")
	if err != nil {
		t.Fatal(err)
	}
	root = t.TempDir()
	files := map[string]string{
		"claims.yaml": `
- {id: ENT-C50, doc: d.md, claim: c, iteration: 3, testable: periodic}
- {id: BORDER-C46, doc: d.md, claim: c, iteration: 3, testable: periodic}
- {id: REPO-C06, doc: d.md, claim: c, iteration: 1, testable: periodic}
`,
		"profiles.yaml":             testProfiles,
		"scenarios/enterprise.yaml": string(src),
		"scenarios/s.yaml": `
- id: REPO-C06.own-repo
  claim: REPO-C06
  profile: repo-A
  kind: rest
  method: GET
  path: /repos/{{.RepoA}}/commits
  expect: {status: 200}
`,
		"config.yaml": fmt.Sprintf("instance:\n  host: %s\n  token_create_rate: 20/min\n%sfixtures:\n  repo_a: goodtune/ghp-scoperig-a\n  repo_b: goodtune/ghp-scoperig-b\n  repo_w: goodtune/ghp-scoperig-w\n", host, extra),
	}
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, filepath.Join(root, "config.yaml")
}

const entDecl = `  anonymous_git: true
  metrics_url: %s/metrics
  enterprise_restriction:
    restricted_repo: ent/restricted
    omit_repo: ext/omit
    team_denied_repo: ext/team
    identity_repo: ext/identity
    unauthenticated_repo: ext/anon
`

// wireEnterprise makes the fake instance act like GHP with an enterprise
// policy and anonymous_git: each target moves its documented counter
// (unless move is false) and anonymous git is refused with 401.
func wireEnterprise(t *testing.T, f *fakeGHP, m *fakeMetrics, move bool) {
	outcome := map[string]string{"ent/restricted": "", "ext/omit": "header_omitted", "ext/team": "team_denied",
		"ext/identity": "identity_substituted", "ext/anon": "unauthenticated_denied"}
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Host != "github.com" {
			if o, ok := outcome[strings.TrimPrefix(r.URL.Path, "/api/v3/repos/")]; ok {
				if !f.tokenOK(r) {
					t.Errorf("enterprise request %s without a valid token", r.URL.Path)
				}
				if move {
					m.inc(o)
				}
				writeJSONResp(w, 200, map[string]any{"id": 1})
				return true
			}
			return false
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("vhost request %s carries Authorization; want anonymous", r.URL.Path)
		}
		switch {
		case r.Header.Get("Git-Protocol") != "":
			w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
			writeJSONResp(w, 401, map[string]string{"message": "Anonymous git access is not permitted"})
		case r.URL.Path == "/ext/anon":
			if move {
				m.incAt("web", "unknown", "unauthenticated_denied")
			}
			_, _ = io.WriteString(w, "<html>repo</html>")
		default:
			_, _ = io.WriteString(w, "001e# service=git-upload-pack\n")
		}
		return true
	}
}

type pasteBack struct {
	ExitCode  int               `json:"exit_code"`
	Claims    map[string]string `json:"claims"`
	Scenarios []struct {
		ID, Status, Detail string
	} `json:"scenarios"`
}

func parsePasteBack(t *testing.T, stdout string) pasteBack {
	t.Helper()
	for _, l := range strings.Split(stdout, "\n") {
		if rest, ok := strings.CutPrefix(l, "scoperig-result: "); ok {
			var pb pasteBack
			if err := json.Unmarshal([]byte(rest), &pb); err != nil {
				t.Fatalf("paste-back line: %v\n%s", err, l)
			}
			return pb
		}
	}
	t.Fatalf("no scoperig-result line in:\n%s", stdout)
	return pasteBack{}
}

func runEnterprise(t *testing.T, extra func(metricsURL string) string, move bool) (cliResult, map[string]map[string]any, pasteBack) {
	t.Helper()
	f := newFakeGHPVhost(t)
	m := newFakeMetrics(t)
	wireEnterprise(t, f, m, move)
	root, cfg := writeEnterpriseTree(t, f.host(), extra(m.ts.URL))
	out := filepath.Join(t.TempDir(), "r.json")
	deps := fakeDeps(f, nil)
	res := runCLI(t, fakeEnv(f, root), deps, "run", "--config", cfg, "--out", out, "--claims", "ENT-C50,BORDER-C46")
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report: %v\n%s\n%s", err, res.stdout, res.stderr)
	}
	if left := f.liveRunTokens(); len(left) != 0 {
		t.Errorf("tokens left live: %v", left)
	}
	return res, statusesByID(t, raw), parsePasteBack(t, res.stdout)
}

var entScenarioIDs = []string{
	"ENT-C50.header-injected", "ENT-C50.exception-header-omitted", "ENT-C50.exception-team-denied",
	"ENT-C50.exception-identity-substituted", "ENT-C50.exception-unauthenticated-denied",
	"BORDER-C46.anonymous-git-401", "BORDER-C46.no-git-protocol-not-blocked",
}

func TestRun_EnterpriseUndeclaredIsGap(t *testing.T) {
	res, got, pb := runEnterprise(t, func(string) string { return "" }, true)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0\n%s\n%s", res.code, res.stdout, res.stderr)
	}
	if len(got) != len(entScenarioIDs) {
		t.Errorf("report has %d scenarios, want only the %d selected: %v", len(got), len(entScenarioIDs), got)
	}
	for _, id := range entScenarioIDs {
		if got[id]["status"] != "GAP" {
			t.Errorf("%s = %v, want GAP", id, got[id]["status"])
		}
	}
	if pb.Claims["ENT-C50"] != "GAP" || pb.Claims["BORDER-C46"] != "GAP" || len(pb.Claims) != 2 || pb.ExitCode != 0 {
		t.Errorf("paste-back = %+v", pb)
	}
	if strings.Contains(res.stdout, "REPO-C06") {
		t.Errorf("--claims output lists an unselected claim:\n%s", res.stdout)
	}
}

func TestRun_EnterpriseDeclaredPass(t *testing.T) {
	res, got, pb := runEnterprise(t, func(u string) string { return fmt.Sprintf(entDecl, u) }, true)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0\n%s\n%s", res.code, res.stdout, res.stderr)
	}
	for _, id := range entScenarioIDs {
		if got[id]["status"] != "PASS" {
			t.Errorf("%s = %v (%v), want PASS", id, got[id]["status"], got[id]["detail"])
		}
	}
	if pb.Claims["ENT-C50"] != "PASS" || pb.Claims["BORDER-C46"] != "PASS" || len(pb.Scenarios) != len(entScenarioIDs) {
		t.Errorf("paste-back = %+v", pb)
	}
}

func TestRun_EnterpriseCounterNotMovingFails(t *testing.T) {
	res, got, pb := runEnterprise(t, func(u string) string { return fmt.Sprintf(entDecl, u) }, false)
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", res.code, res.stdout, res.stderr)
	}
	for _, id := range entScenarioIDs[:5] {
		if got[id]["status"] != "FAIL" || !strings.Contains(fmt.Sprint(got[id]["detail"]), "want change >= 1, got 0") {
			t.Errorf("%s = %v (%v), want FAIL on the metric", id, got[id]["status"], got[id]["detail"])
		}
	}
	if got["BORDER-C46.anonymous-git-401"]["status"] != "PASS" {
		t.Errorf("BORDER-C46 = %v, want PASS (no metric)", got["BORDER-C46.anonymous-git-401"]["status"])
	}
	if pb.ExitCode != 1 || pb.Claims["ENT-C50"] != "FAIL" {
		t.Errorf("paste-back = %+v", pb)
	}
}

func TestRun_MetricsUnreachableIsError(t *testing.T) {
	res, got, _ := runEnterprise(t, func(string) string {
		return fmt.Sprintf(entDecl, "http://127.0.0.1:1")
	}, true)
	if res.code != 2 {
		t.Fatalf("exit = %d, want 2\n%s\n%s", res.code, res.stdout, res.stderr)
	}
	if st := got["ENT-C50.header-injected"]["status"]; st != "ERROR" {
		t.Errorf("header-injected = %v, want ERROR", st)
	}
}

func TestRun_OnlyAcceptsGlobList(t *testing.T) {
	f := newFakeGHP(t)
	root, cfg := writeTree(t, f.host(), testScenarios)
	out := filepath.Join(t.TempDir(), "r.json")
	runCLI(t, fakeEnv(f, root), fakeDeps(f, nil), "run", "--config", cfg, "--out", out, "--only", "REPO-C06.*, PERM-C15.*")
	raw, _ := os.ReadFile(out)
	got := statusesByID(t, raw)
	if len(got) != 2 || got["REPO-C06.own-repo"] == nil || got["PERM-C15.residue"] == nil {
		t.Errorf("scenarios = %v, want REPO-C06.own-repo and PERM-C15.residue", got)
	}
}

func TestRun_ClaimsUnknownExits3(t *testing.T) {
	f := newFakeGHP(t)
	root, cfg := writeTree(t, f.host(), testScenarios)
	res := runCLI(t, fakeEnv(f, root), fakeDeps(f, nil), "run", "--config", cfg, "--claims", "NOPE-C1")
	if res.code != 3 || !strings.Contains(res.stderr, "unknown claim NOPE-C1") {
		t.Errorf("exit = %d stderr = %s, want 3 and unknown claim", res.code, res.stderr)
	}
}

func TestWritePasteBack_ScrubsHosts(t *testing.T) {
	rep := &report.Report{RunID: "r", Claims: []report.ClaimResult{{ID: "ENT-C50", Status: report.StatusFail, Scenarios: []report.ScenarioResult{{
		ID: "ENT-C50.header-injected", Status: report.StatusError,
		Detail: `metric_delta (before): scrape instance.metrics_url: Get "http://metrics.corp.test:9136/metrics": dial tcp: lookup metrics.corp.test; also https://ghp.corp.test/api/v3 and api.corp.test:8443`,
	}}}}}
	var b strings.Builder
	if err := writePasteBack(&b, rep, 2, []string{"ghp.corp.test", "metrics.corp.test:9136", "api.corp.test:8443", ""}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"corp.test", "9136", "8443"} {
		if strings.Contains(b.String(), h) {
			t.Errorf("paste-back line contains %q:\n%s", h, b.String())
		}
	}
	if !strings.Contains(b.String(), "<host>") {
		t.Errorf("want <host> placeholder:\n%s", b.String())
	}
}

func TestPasteBackHosts(t *testing.T) {
	c := &Config{ServerURL: "https://ghp.corp.test", MetricsURL: "http://m.corp.test:9136/metrics",
		Instance: scenario.InstanceVals{Host: "api.corp.test:8443"}}
	got := strings.Join(pasteBackHosts(c), ",")
	for _, w := range []string{"ghp.corp.test", "m.corp.test:9136", "m.corp.test", "api.corp.test:8443", "api.corp.test"} {
		if !strings.Contains(","+got+",", ","+w+",") {
			t.Errorf("hosts %q missing %q", got, w)
		}
	}
}

func TestCheckMetricDeltas_Interference(t *testing.T) {
	before, _ := parseMetrics(strings.NewReader("ghp_x_total 1\n"))
	after, _ := parseMetrics(strings.NewReader("ghp_x_total 3\n"))
	one := 1
	d := scenario.MetricDelta{Name: "ghp_x_total", Min: &one, Max: &one, Interference: true}
	fails, inter := checkMetricDeltas(before, after, []scenario.MetricDelta{d})
	if len(fails) != 0 || len(inter) != 1 || !strings.Contains(inter[0], "other traffic") {
		t.Errorf("fails=%v interference=%v", fails, inter)
	}
	d.Interference = false
	if fails, inter = checkMetricDeltas(before, after, []scenario.MetricDelta{d}); len(fails) != 1 || len(inter) != 0 {
		t.Errorf("without interference: fails=%v interference=%v", fails, inter)
	}
}

func TestRun_EnterpriseConcurrentTrafficIsError(t *testing.T) {
	f := newFakeGHPVhost(t)
	m := newFakeMetrics(t)
	wireEnterprise(t, f, m, true)
	inner := f.intercept
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/v3/repos/ext/omit" {
			m.inc("header_omitted") // a second, concurrent request
		}
		return inner(w, r)
	}
	root, cfg := writeEnterpriseTree(t, f.host(), fmt.Sprintf(entDecl, m.ts.URL))
	out := filepath.Join(t.TempDir(), "r.json")
	res := runCLI(t, fakeEnv(f, root), fakeDeps(f, nil), "run", "--config", cfg, "--out", out, "--claims", "ENT-C50")
	raw, _ := os.ReadFile(out)
	got := statusesByID(t, raw)
	if res.code != 2 || got["ENT-C50.exception-header-omitted"]["status"] != "ERROR" {
		t.Errorf("exit=%d header-omitted=%v (%v), want 2 and ERROR", res.code,
			got["ENT-C50.exception-header-omitted"]["status"], got["ENT-C50.exception-header-omitted"]["detail"])
	}
}
