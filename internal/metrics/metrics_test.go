package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/database"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

func getCounterValue(t *testing.T, counter *prometheus.CounterVec, labels prometheus.Labels) float64 {
	t.Helper()
	var m io_prometheus_client.Metric
	c, err := counter.GetMetricWith(labels)
	if err != nil {
		t.Fatalf("GetMetricWith: %v", err)
	}
	if err := c.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return m.GetCounter().GetValue()
}

func TestObserveProxyRequest_REST(t *testing.T) {
	userID := "testuser"
	pt := &database.ProxyToken{
		TokenType: "ghx",
		UserID:    &userID,
	}

	labels := prometheus.Labels{
		"backend":    "api.github.com",
		"method":     "GET",
		"status":     "200",
		"token_type": "ghx",
		"type":       "rest",
		"user":       "testuser",
		"app":        "",
	}

	before := getCounterValue(t, ProxyRequestTotal, labels)
	ObserveProxyRequest("api.github.com", pt, "GET", 200, 100*time.Millisecond, "rest", "testuser")
	after := getCounterValue(t, ProxyRequestTotal, labels)

	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObserveProxyRequest_GraphQL(t *testing.T) {
	userID := "testuser"
	pt := &database.ProxyToken{
		TokenType: "ghx",
		UserID:    &userID,
	}

	labels := prometheus.Labels{
		"backend":    "api.github.com",
		"method":     "POST",
		"status":     "200",
		"token_type": "ghx",
		"type":       "graphql",
		"user":       "testuser",
		"app":        "",
	}

	before := getCounterValue(t, ProxyRequestTotal, labels)
	ObserveProxyRequest("api.github.com", pt, "POST", 200, 50*time.Millisecond, "graphql", "testuser")
	after := getCounterValue(t, ProxyRequestTotal, labels)

	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObserveProxyRequest_Git(t *testing.T) {
	userID := "testuser"
	pt := &database.ProxyToken{
		TokenType: "ghx",
		UserID:    &userID,
	}

	labels := prometheus.Labels{
		"backend":    "github.com",
		"method":     "POST",
		"status":     "200",
		"token_type": "ghx",
		"type":       "git",
		"user":       "testuser",
		"app":        "",
	}

	before := getCounterValue(t, ProxyRequestTotal, labels)
	ObserveProxyRequest("github.com", pt, "POST", 200, 200*time.Millisecond, "git", "testuser")
	after := getCounterValue(t, ProxyRequestTotal, labels)

	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObserveProxyRequest_WithInstallationID(t *testing.T) {
	userID := "testuser"
	installID := int64(12345)
	pt := &database.ProxyToken{
		TokenType:      "gha",
		UserID:         &userID,
		InstallationID: &installID,
	}

	labels := prometheus.Labels{
		"backend":    "api.github.com",
		"method":     "GET",
		"status":     "200",
		"token_type": "gha",
		"type":       "rest",
		"user":       "testuser",
		"app":        "12345",
	}

	before := getCounterValue(t, ProxyRequestTotal, labels)
	ObserveProxyRequest("api.github.com", pt, "GET", 200, 100*time.Millisecond, "rest", "testuser")
	after := getCounterValue(t, ProxyRequestTotal, labels)

	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObserveProxyRequest_NilPt(t *testing.T) {
	// Should not panic.
	ObserveProxyRequest("api.github.com", nil, "GET", 200, 100*time.Millisecond, "rest", "")
}

func getHistogramCount(t *testing.T, h *prometheus.HistogramVec, labels prometheus.Labels) uint64 {
	t.Helper()
	var m io_prometheus_client.Metric
	obs, err := h.GetMetricWith(labels)
	if err != nil {
		t.Fatalf("GetMetricWith: %v", err)
	}
	if err := obs.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}

func TestObserveDecision_AllStages(t *testing.T) {
	stages := []string{
		StageTotal,
		StageTokenExtraction,
		StageBorderPolicyCheck,
		StageTokenResolution,
		StageUsernameResolution,
		StageScopeParsing,
		StageScopeEnforcement,
		StageGitHubTokenResolution,
		StageUpstreamRoundtrip,
		StageRedirectHeadCheck,
		StageCacheLookup,
		StageGraphQLAnalysis,
		StageForwardProxySelection,
	}

	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			labels := prometheus.Labels{
				"stage":      stage,
				"token_type": "proxy",
				"vhost":      VhostAPI,
			}
			before := getHistogramCount(t, ProxyDecisionDuration, labels)
			ObserveDecision(WithVhost(context.Background(), VhostAPI), stage, "proxy", 1*time.Millisecond)
			after := getHistogramCount(t, ProxyDecisionDuration, labels)
			if after-before != 1 {
				t.Errorf("expected histogram sample count to increment by 1, got %d", after-before)
			}
		})
	}
}

func TestObserveDecision_EmptyTokenType(t *testing.T) {
	labels := prometheus.Labels{
		"stage":      StageTokenExtraction,
		"token_type": "unknown",
		"vhost":      VhostUnknown,
	}
	before := getHistogramCount(t, ProxyDecisionDuration, labels)
	ObserveDecision(context.Background(), StageTokenExtraction, "", 500*time.Microsecond)
	after := getHistogramCount(t, ProxyDecisionDuration, labels)
	if after-before != 1 {
		t.Errorf("expected histogram sample count to increment by 1, got %d", after-before)
	}
}

func getGaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m io_prometheus_client.Metric
	if err := g.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return m.GetGauge().GetValue()
}

func getCounterValueSimple(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m io_prometheus_client.Metric
	if err := c.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return m.GetCounter().GetValue()
}

func TestBlockAnonymousGitEnabled_Gauge(t *testing.T) {
	BlockAnonymousGitEnabled.Set(1)
	if got := getGaugeValue(t, BlockAnonymousGitEnabled); got != 1 {
		t.Errorf("expected gauge value 1, got %f", got)
	}
	BlockAnonymousGitEnabled.Set(0)
	if got := getGaugeValue(t, BlockAnonymousGitEnabled); got != 0 {
		t.Errorf("expected gauge value 0, got %f", got)
	}
}

func TestBlockAnonymousGitTotal_Counter(t *testing.T) {
	before := getCounterValueSimple(t, BlockAnonymousGitTotal)
	BlockAnonymousGitTotal.Inc()
	after := getCounterValueSimple(t, BlockAnonymousGitTotal)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestReleasesRedirectHeadCheckTotal(t *testing.T) {
	results := []string{"found", "not_found", "error"}
	for _, result := range results {
		t.Run(result, func(t *testing.T) {
			labels := prometheus.Labels{"result": result}
			before := getCounterValue(t, ReleasesRedirectHeadCheckTotal, labels)
			ReleasesRedirectHeadCheckTotal.WithLabelValues(result).Inc()
			after := getCounterValue(t, ReleasesRedirectHeadCheckTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestEnterpriseExceptionTotal(t *testing.T) {
	outcomes := []string{"header_omitted", "identity_substituted", "team_denied", "unauthenticated_denied", "identity_error"}
	for _, outcome := range outcomes {
		t.Run(outcome, func(t *testing.T) {
			labels := prometheus.Labels{"outcome": outcome}
			before := getCounterValue(t, EnterpriseExceptionTotal, labels)
			EnterpriseExceptionTotal.WithLabelValues(outcome).Inc()
			after := getCounterValue(t, EnterpriseExceptionTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestAgentRepoNarrowingFailedTotal(t *testing.T) {
	for _, reason := range []string{"owner_mismatch", "malformed", "lookup_failed", "empty_login"} {
		t.Run(reason, func(t *testing.T) {
			labels := prometheus.Labels{"reason": reason}
			before := getCounterValue(t, AgentRepoNarrowingFailedTotal, labels)
			AgentRepoNarrowingFailedTotal.WithLabelValues(reason).Inc()
			if after := getCounterValue(t, AgentRepoNarrowingFailedTotal, labels); after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestCodeloadRedirectTotal(t *testing.T) {
	tests := []struct {
		name    string
		owner   string
		repo    string
		archive string
		result  string
	}{
		{"redirect tar.gz", "actions", "checkout", "tar.gz", "redirect"},
		{"redirect zip", "actions", "checkout", "zip", "redirect"},
		{"passthrough legacy.tar.gz", "goodtune", "ghp", "legacy.tar.gz", "passthrough"},
		{"passthrough legacy.zip", "goodtune", "ghp", "legacy.zip", "passthrough"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := prometheus.Labels{
				"owner":   tt.owner,
				"repo":    tt.repo,
				"archive": tt.archive,
				"result":  tt.result,
			}
			before := getCounterValue(t, CodeloadRedirectTotal, labels)
			CodeloadRedirectTotal.WithLabelValues(tt.owner, tt.repo, tt.archive, tt.result).Inc()
			after := getCounterValue(t, CodeloadRedirectTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestObserveDecision_RedirectHeadCheck(t *testing.T) {
	labels := prometheus.Labels{
		"stage":      StageRedirectHeadCheck,
		"token_type": "unknown",
		"vhost":      VhostWeb,
	}
	before := getHistogramCount(t, ProxyDecisionDuration, labels)
	ObserveDecision(WithVhost(context.Background(), VhostWeb), StageRedirectHeadCheck, "", 10*time.Millisecond)
	after := getHistogramCount(t, ProxyDecisionDuration, labels)
	if after-before != 1 {
		t.Errorf("expected histogram sample count to increment by 1, got %d", after-before)
	}
}

func TestObserveClientRequest(t *testing.T) {
	labels := prometheus.Labels{
		"client":     "10.1.2.3",
		"backend":    "api.github.com",
		"token_type": "proxy",
		"status":     "200",
	}
	before := getCounterValue(t, ClientRequestTotal, labels)
	ObserveClientRequest("10.1.2.3", "api.github.com", "proxy", 200)
	after := getCounterValue(t, ClientRequestTotal, labels)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObserveClientRequest_UnknownDefaults(t *testing.T) {
	labels := prometheus.Labels{
		"client":     "unknown",
		"backend":    "github.com",
		"token_type": "unknown",
		"status":     "404",
	}
	before := getCounterValue(t, ClientRequestTotal, labels)
	ObserveClientRequest("", "github.com", "", 404)
	after := getCounterValue(t, ClientRequestTotal, labels)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObservePassthroughRequest(t *testing.T) {
	tests := []struct {
		name      string
		tokenType string
		wantType  string
	}{
		{"gho", "gho", "gho"},
		{"ghp", "ghp", "ghp"},
		{"ghu", "ghu", "ghu"},
		{"ghs", "ghs", "ghs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := prometheus.Labels{
				"backend":    "api.github.com",
				"method":     "GET",
				"status":     "200",
				"token_type": tt.wantType,
				"type":       "rest",
				"user":       "testuser",
				"app":        "",
			}
			before := getCounterValue(t, ProxyRequestTotal, labels)
			ObservePassthroughRequest("api.github.com", "GET", 200, 100*time.Millisecond, "rest", tt.tokenType, "testuser")
			after := getCounterValue(t, ProxyRequestTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestObservePassthroughRequest_UnknownUser(t *testing.T) {
	labels := prometheus.Labels{
		"backend":    "github.com",
		"method":     "POST",
		"status":     "200",
		"token_type": "gho",
		"type":       "git",
		"user":       "unknown",
		"app":        "",
	}
	before := getCounterValue(t, ProxyRequestTotal, labels)
	ObservePassthroughRequest("github.com", "POST", 200, 100*time.Millisecond, "git", "gho", "")
	after := getCounterValue(t, ProxyRequestTotal, labels)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObservePassthroughRequest_UnknownTokenType(t *testing.T) {
	labels := prometheus.Labels{
		"backend":    "api.github.com",
		"method":     "GET",
		"status":     "200",
		"token_type": "unknown",
		"type":       "rest",
		"user":       "unknown",
		"app":        "",
	}
	before := getCounterValue(t, ProxyRequestTotal, labels)
	ObservePassthroughRequest("api.github.com", "GET", 200, 100*time.Millisecond, "rest", "", "")
	after := getCounterValue(t, ProxyRequestTotal, labels)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestCacheFetchTotal(t *testing.T) {
	results := []string{"hit", "miss", "rejected", "error"}
	for _, result := range results {
		t.Run(result, func(t *testing.T) {
			labels := prometheus.Labels{"result": result}
			before := getCounterValue(t, CacheFetchTotal, labels)
			CacheFetchTotal.WithLabelValues(result).Inc()
			after := getCounterValue(t, CacheFetchTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestCacheLsRefsTotal(t *testing.T) {
	before := getCounterValueSimple(t, CacheLsRefsTotal)
	CacheLsRefsTotal.Inc()
	after := getCounterValueSimple(t, CacheLsRefsTotal)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestCacheWarmTotal(t *testing.T) {
	for _, result := range []string{"success", "error"} {
		t.Run(result, func(t *testing.T) {
			labels := prometheus.Labels{"result": result}
			before := getCounterValue(t, CacheWarmTotal, labels)
			CacheWarmTotal.WithLabelValues(result).Inc()
			after := getCounterValue(t, CacheWarmTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestCacheReposActive(t *testing.T) {
	CacheReposActive.Set(5)
	if got := getGaugeValue(t, CacheReposActive); got != 5 {
		t.Errorf("expected gauge value 5, got %f", got)
	}
	CacheReposActive.Set(0)
	if got := getGaugeValue(t, CacheReposActive); got != 0 {
		t.Errorf("expected gauge value 0, got %f", got)
	}
}

func TestCacheRequestTotal(t *testing.T) {
	labels := prometheus.Labels{"owner": "testorg", "repo": "testrepo", "result": "nocache"}
	before := getCounterValue(t, CacheRequestTotal, labels)
	CacheRequestTotal.WithLabelValues("testorg", "testrepo", "nocache").Inc()
	after := getCounterValue(t, CacheRequestTotal, labels)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}

	// Verify bypass label works too.
	bypassLabels := prometheus.Labels{"owner": "testorg", "repo": "testrepo", "result": "bypass"}
	beforeBypass := getCounterValue(t, CacheRequestTotal, bypassLabels)
	CacheRequestTotal.WithLabelValues("testorg", "testrepo", "bypass").Inc()
	afterBypass := getCounterValue(t, CacheRequestTotal, bypassLabels)
	if afterBypass-beforeBypass != 1 {
		t.Errorf("expected bypass counter to increment by 1, got %f", afterBypass-beforeBypass)
	}
}

func TestCachePackfileTotal(t *testing.T) {
	for _, result := range []string{"hit", "miss", "passthrough"} {
		labels := prometheus.Labels{"owner": "testorg", "repo": "testrepo", "user": "testuser", "result": result}
		before := getCounterValue(t, CachePackfileTotal, labels)
		CachePackfileTotal.WithLabelValues("testorg", "testrepo", "testuser", result).Inc()
		after := getCounterValue(t, CachePackfileTotal, labels)
		if after-before != 1 {
			t.Errorf("expected %s counter to increment by 1, got %f", result, after-before)
		}
	}
}

func TestCachePackfileBytesTotal(t *testing.T) {
	for _, result := range []string{"hit", "miss", "passthrough"} {
		labels := prometheus.Labels{"owner": "testorg", "repo": "testrepo", "user": "testuser", "result": result}
		before := getCounterValue(t, CachePackfileBytesTotal, labels)
		CachePackfileBytesTotal.WithLabelValues("testorg", "testrepo", "testuser", result).Add(1024)
		after := getCounterValue(t, CachePackfileBytesTotal, labels)
		if after-before != 1024 {
			t.Errorf("expected %s bytes counter to increment by 1024, got %f", result, after-before)
		}
	}
}

func TestObserveDecision_CacheLookup(t *testing.T) {
	labels := prometheus.Labels{
		"stage":      StageCacheLookup,
		"token_type": "proxy",
		"vhost":      VhostWeb,
	}
	before := getHistogramCount(t, ProxyDecisionDuration, labels)
	ObserveDecision(WithVhost(context.Background(), VhostWeb), StageCacheLookup, "proxy", 5*time.Millisecond)
	after := getHistogramCount(t, ProxyDecisionDuration, labels)
	if after-before != 1 {
		t.Errorf("expected histogram sample count to increment by 1, got %d", after-before)
	}
}

func getGaugeVecValue(t *testing.T, g *prometheus.GaugeVec, labels prometheus.Labels) float64 {
	t.Helper()
	gauge, err := g.GetMetricWith(labels)
	if err != nil {
		t.Fatalf("GetMetricWith: %v", err)
	}
	return getGaugeValue(t, gauge)
}

func TestCacheEvictionTotal(t *testing.T) {
	labels := prometheus.Labels{"owner": "testorg", "repo": "testrepo"}
	before := getCounterValue(t, CacheEvictionTotal, labels)
	CacheEvictionTotal.WithLabelValues("testorg", "testrepo").Inc()
	after := getCounterValue(t, CacheEvictionTotal, labels)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestCacheResponseSizeBytes(t *testing.T) {
	labels := prometheus.Labels{"owner": "testorg", "repo": "testrepo"}
	CacheResponseSizeBytes.WithLabelValues("testorg", "testrepo").Set(1048576)
	got := getGaugeVecValue(t, CacheResponseSizeBytes, labels)
	if got != 1048576 {
		t.Errorf("expected gauge value 1048576, got %f", got)
	}
}

func TestSetBuildInfo(t *testing.T) {
	// Inject a fake debug.ReadBuildInfo that returns a known revision.
	orig := runtimeDebugReadBuildInfo
	t.Cleanup(func() { runtimeDebugReadBuildInfo = orig })

	runtimeDebugReadBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "abc123"},
			},
		}, true
	}

	SetBuildInfo("1.2.3")

	labels := prometheus.Labels{
		"version":   "1.2.3",
		"revision":  "abc123",
		"goversion": runtime.Version(),
		"goos":      runtime.GOOS,
		"goarch":    runtime.GOARCH,
	}

	gauge, err := BuildInfo.GetMetricWith(labels)
	if err != nil {
		t.Fatalf("GetMetricWith: %v", err)
	}
	if got := getGaugeValue(t, gauge); got != 1 {
		t.Errorf("expected build_info gauge value 1, got %f", got)
	}
}

func TestSetBuildInfo_NoVCSRevision(t *testing.T) {
	orig := runtimeDebugReadBuildInfo
	t.Cleanup(func() { runtimeDebugReadBuildInfo = orig })

	runtimeDebugReadBuildInfo = func() (*debug.BuildInfo, bool) {
		return nil, false
	}

	SetBuildInfo("dev")

	labels := prometheus.Labels{
		"version":   "dev",
		"revision":  "unknown",
		"goversion": runtime.Version(),
		"goos":      runtime.GOOS,
		"goarch":    runtime.GOARCH,
	}

	gauge, err := BuildInfo.GetMetricWith(labels)
	if err != nil {
		t.Fatalf("GetMetricWith: %v", err)
	}
	if got := getGaugeValue(t, gauge); got != 1 {
		t.Errorf("expected build_info gauge value 1, got %f", got)
	}
}

func TestTokenCleanupDeletedTotal(t *testing.T) {
	before := getCounterValueSimple(t, TokenCleanupDeletedTotal)
	TokenCleanupDeletedTotal.Add(5)
	after := getCounterValueSimple(t, TokenCleanupDeletedTotal)
	if after-before != 5 {
		t.Errorf("expected counter to increment by 5, got %f", after-before)
	}
}

func TestForwardProxySelectTotal(t *testing.T) {
	cases := []struct{ ruleset, layer string }{
		{"ci-egress", "token"},
		{"ci-egress", "app"},
		{"ci-egress", "net"},
		{"default", "system"},
		{"control-plane", "control"},
		{"", "ambient"},
		{"", "direct"},
		{"", "header"},
	}
	for _, c := range cases {
		t.Run(c.layer, func(t *testing.T) {
			labels := prometheus.Labels{"ruleset": c.ruleset, "layer": c.layer}
			before := getCounterValue(t, ForwardProxySelectTotal, labels)
			ForwardProxySelectTotal.WithLabelValues(c.ruleset, c.layer).Inc()
			after := getCounterValue(t, ForwardProxySelectTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestForwardProxyRulesetsActive_Gauge(t *testing.T) {
	ForwardProxyRulesetsActive.Set(3)
	if got := getGaugeValue(t, ForwardProxyRulesetsActive); got != 3 {
		t.Errorf("expected gauge value 3, got %f", got)
	}
	ForwardProxyRulesetsActive.Set(0)
	if got := getGaugeValue(t, ForwardProxyRulesetsActive); got != 0 {
		t.Errorf("expected gauge value 0, got %f", got)
	}
}

func TestForwardProxyClientSpecifiedTotal(t *testing.T) {
	cases := []struct{ scheme, tokenType string }{
		{"http", "proxy"},
		{"socks5", "agent"},
		{"https", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.scheme+"_"+c.tokenType, func(t *testing.T) {
			labels := prometheus.Labels{"scheme": c.scheme, "token_type": c.tokenType}
			before := getCounterValue(t, ForwardProxyClientSpecifiedTotal, labels)
			ForwardProxyClientSpecifiedTotal.WithLabelValues(c.scheme, c.tokenType).Inc()
			after := getCounterValue(t, ForwardProxyClientSpecifiedTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestWebhookReceivedTotal(t *testing.T) {
	labels := prometheus.Labels{"event": "pull_request", "result": "published"}
	before := getCounterValue(t, WebhookReceivedTotal, labels)
	WebhookReceivedTotal.WithLabelValues("pull_request", "published").Inc()
	after := getCounterValue(t, WebhookReceivedTotal, labels)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestWebhookPublishDuration(t *testing.T) {
	var m io_prometheus_client.Metric
	if err := WebhookPublishDuration.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	before := m.GetHistogram().GetSampleCount()
	WebhookPublishDuration.Observe(0.002)
	m.Reset()
	if err := WebhookPublishDuration.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := m.GetHistogram().GetSampleCount() - before; got != 1 {
		t.Errorf("expected sample count to increase by 1, got %d", got)
	}
}

func TestWebhookGauges(t *testing.T) {
	WebhookNgrokTunnelUp.Set(1)
	if v := getGaugeValue(t, WebhookNgrokTunnelUp); v != 1 {
		t.Errorf("WebhookNgrokTunnelUp = %f, want 1", v)
	}
	WebhookNgrokTunnelUp.Set(0)
	if v := getGaugeValue(t, WebhookNgrokTunnelUp); v != 0 {
		t.Errorf("WebhookNgrokTunnelUp = %f, want 0", v)
	}

	WebhookStreamMessages.Set(42)
	if v := getGaugeValue(t, WebhookStreamMessages); v != 42 {
		t.Errorf("WebhookStreamMessages = %f, want 42", v)
	}
	WebhookStreamBytes.Set(4096)
	if v := getGaugeValue(t, WebhookStreamBytes); v != 4096 {
		t.Errorf("WebhookStreamBytes = %f, want 4096", v)
	}

	g := WebhookSubscribersActive.WithLabelValues("sse")
	g.Set(0)
	g.Inc()
	g.Inc()
	g.Dec()
	if v := getGaugeValue(t, g); v != 1 {
		t.Errorf("WebhookSubscribersActive{sse} = %f, want 1", v)
	}
}

func TestScopeUnmappedDeniedTotal(t *testing.T) {
	tests := []struct {
		tokenType string
		method    string
		label     string
	}{
		{"proxy", "DELETE", "DELETE"},
		{"agent", "GET", "GET"},
		{"proxy", "BREW", "OTHER"},
	}
	for _, tt := range tests {
		t.Run(tt.tokenType+"/"+tt.method, func(t *testing.T) {
			labels := prometheus.Labels{"token_type": tt.tokenType, "method": tt.label}
			before := getCounterValue(t, ScopeUnmappedDeniedTotal, labels)
			ScopeUnmappedDeniedTotal.WithLabelValues(tt.tokenType, NormalizeMethod(tt.method)).Inc()
			after := getCounterValue(t, ScopeUnmappedDeniedTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestTokenScopeRejectedTotal(t *testing.T) {
	for _, reason := range []string{"unknown_permission", "invalid_level"} {
		t.Run(reason, func(t *testing.T) {
			labels := prometheus.Labels{"reason": reason}
			before := getCounterValue(t, TokenScopeRejectedTotal, labels)
			TokenScopeRejectedTotal.WithLabelValues(reason).Inc()
			if after := getCounterValue(t, TokenScopeRejectedTotal, labels); after-before != 1 {
				t.Errorf("expected increment of 1, got %f", after-before)
			}
		})
	}
}

func TestPassthroughScopeDeniedTotal(t *testing.T) {
	tests := []struct{ vhost, reason string }{
		{"github.com", "unmapped"},
		{"github.com", "repo"},
		{"codeload.github.com", "permission"},
	}
	for _, tt := range tests {
		t.Run(tt.vhost+"/"+tt.reason, func(t *testing.T) {
			labels := prometheus.Labels{"vhost": tt.vhost, "reason": tt.reason}
			before := getCounterValue(t, PassthroughScopeDeniedTotal, labels)
			PassthroughScopeDeniedTotal.With(labels).Inc()
			if got := getCounterValue(t, PassthroughScopeDeniedTotal, labels) - before; got != 1 {
				t.Fatalf("counter delta = %v, want 1", got)
			}
		})
	}
}

func TestManagementHostRejectedTotal(t *testing.T) {
	for _, reason := range []string{"anonymous", "native_token"} {
		t.Run(reason, func(t *testing.T) {
			labels := prometheus.Labels{"reason": reason}
			before := getCounterValue(t, ManagementHostRejectedTotal, labels)
			ManagementHostRejectedTotal.WithLabelValues(reason).Inc()
			after := getCounterValue(t, ManagementHostRejectedTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

// TestProxyDecisionDuration_LowBuckets checks that the decision histogram
// exposes sub-50µs buckets so cheap stages can show regressions (#322), and
// that a 20µs sample lands in the 25µs bucket but not the 10µs bucket.
func TestProxyDecisionDuration_LowBuckets(t *testing.T) {
	const tokenType = "bucket-test"
	ObserveDecision(context.Background(), StageScopeEnforcement, tokenType, 20*time.Microsecond)

	h, err := ProxyDecisionDuration.GetMetricWithLabelValues(StageScopeEnforcement, tokenType, VhostUnknown)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues: %v", err)
	}
	var m io_prometheus_client.Metric
	if err := h.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := map[float64]uint64{}
	for _, b := range m.GetHistogram().GetBucket() {
		got[b.GetUpperBound()] = b.GetCumulativeCount()
	}

	tests := []struct {
		name  string
		bound float64
		want  uint64
	}{
		{"10us", 0.00001, 0},
		{"25us", 0.000025, 1},
		{"50us", 0.00005, 1},
		{"250us", 0.00025, 1},
		{"2.5ms", 0.0025, 1},
		{"7.5ms", 0.0075, 1},
		{"10s", 10.0, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := got[tc.bound]
			if !ok {
				t.Fatalf("bucket %v missing", tc.bound)
			}
			if c != tc.want {
				t.Errorf("bucket %v cumulative count = %d, want %d", tc.bound, c, tc.want)
			}
		})
	}
}

// TestObserveDecision_Vhost checks that each vhost label value set on the
// request context lands in its own series (#330).
func TestObserveDecision_Vhost(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"api", WithVhost(context.Background(), VhostAPI), "api"},
		{"web", WithVhost(context.Background(), VhostWeb), "web"},
		{"codeload", WithVhost(context.Background(), VhostCodeload), "codeload"},
		{"management", WithVhost(context.Background(), VhostManagement), "management"},
		{"copilot", WithVhost(context.Background(), VhostCopilot), "copilot"},
		{"no vhost on context", context.Background(), "unknown"},
		{"nil context", nil, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := prometheus.Labels{
				"stage":      StageTotal,
				"token_type": "vhost-test",
				"vhost":      tt.want,
			}
			before := getHistogramCount(t, ProxyDecisionDuration, labels)
			ObserveDecision(tt.ctx, StageTotal, "vhost-test", time.Millisecond) //nolint:staticcheck // nil ctx is a tested input
			after := getHistogramCount(t, ProxyDecisionDuration, labels)
			if after-before != 1 {
				t.Errorf("vhost %q: expected sample count +1, got %d", tt.want, after-before)
			}
		})
	}
}

// TestVhostFromContext checks the context round trip and the fallback.
func TestVhostFromContext(t *testing.T) {
	if got := VhostFromContext(context.Background()); got != VhostUnknown {
		t.Errorf("bare context: got %q, want %q", got, VhostUnknown)
	}
	ctx := WithVhost(context.Background(), VhostCodeload)
	if got := VhostFromContext(ctx); got != VhostCodeload {
		t.Errorf("got %q, want %q", got, VhostCodeload)
	}
	// An inner WithVhost overrides the outer value.
	if got := VhostFromContext(WithVhost(ctx, VhostAPI)); got != VhostAPI {
		t.Errorf("override: got %q, want %q", got, VhostAPI)
	}
}
func getHistogramSum(t *testing.T, h *prometheus.HistogramVec, labels prometheus.Labels) float64 {
	t.Helper()
	var m io_prometheus_client.Metric
	obs, err := h.GetMetricWith(labels)
	if err != nil {
		t.Fatalf("GetMetricWith: %v", err)
	}
	if err := obs.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return m.GetHistogram().GetSampleSum()
}

func TestObserveDecision_NewStages(t *testing.T) {
	for _, stage := range []string{StageRequestBodyRead, StageRequestBuild, StagePipelineOther} {
		t.Run(stage, func(t *testing.T) {
			labels := prometheus.Labels{"stage": stage, "token_type": "agent", "vhost": VhostAPI}
			before := getHistogramCount(t, ProxyDecisionDuration, labels)
			ObserveDecision(WithVhost(context.Background(), VhostAPI), stage, "agent", time.Millisecond)
			if got := getHistogramCount(t, ProxyDecisionDuration, labels) - before; got != 1 {
				t.Errorf("sample count delta = %d, want 1", got)
			}
		})
	}
}

func TestDecisionTrace_PipelineOther(t *testing.T) {
	tests := []struct {
		name      string
		stages    map[string]time.Duration
		total     time.Duration
		wantOther float64 // seconds
	}{
		{"remainder", map[string]time.Duration{StageTokenResolution: 2 * time.Millisecond, StageScopeParsing: time.Millisecond}, 10 * time.Millisecond, 0.007},
		{"clamped at zero", map[string]time.Duration{StageTokenResolution: 5 * time.Millisecond}, 4 * time.Millisecond, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithDecisionTrace(WithVhost(context.Background(), VhostCopilot), "GET", "/x")
			labels := prometheus.Labels{"stage": StagePipelineOther, "token_type": "proxy", "vhost": VhostCopilot}
			beforeN := getHistogramCount(t, ProxyDecisionDuration, labels)
			beforeS := getHistogramSum(t, ProxyDecisionDuration, labels)
			for s, d := range tt.stages {
				ObserveDecision(ctx, s, "proxy", d)
			}
			ObserveDecision(ctx, StageTotal, "proxy", tt.total)
			// Stages after total are not part of the pre-forward overhead.
			ObserveDecision(ctx, StageUpstreamRoundtrip, "proxy", time.Second)
			if n := getHistogramCount(t, ProxyDecisionDuration, labels) - beforeN; n != 1 {
				t.Fatalf("pipeline_other count delta = %d, want 1", n)
			}
			if s := getHistogramSum(t, ProxyDecisionDuration, labels) - beforeS; math.Abs(s-tt.wantOther) > 1e-9 {
				t.Errorf("pipeline_other = %v, want %v", s, tt.wantOther)
			}
		})
	}
}

func TestDecisionTrace_NoTraceNoPipelineOther(t *testing.T) {
	ctx := WithVhost(context.Background(), VhostWeb)
	labels := prometheus.Labels{"stage": StagePipelineOther, "token_type": "proxy", "vhost": VhostWeb}
	before := getHistogramCount(t, ProxyDecisionDuration, labels)
	ObserveDecision(ctx, StageTotal, "proxy", 50*time.Millisecond)
	if n := getHistogramCount(t, ProxyDecisionDuration, labels) - before; n != 0 {
		t.Errorf("pipeline_other recorded without a trace: delta %d", n)
	}
}

func TestSlowDecisionLog(t *testing.T) {
	tests := []struct {
		name      string
		threshold time.Duration
		total     time.Duration
		wantLog   bool
	}{
		{"above threshold", 10 * time.Millisecond, 40 * time.Millisecond, true},
		{"at threshold", 10 * time.Millisecond, 10 * time.Millisecond, true},
		{"below threshold", 10 * time.Millisecond, 9 * time.Millisecond, false},
		{"disabled", 0, time.Second, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			ConfigureSlowDecisionLog(slog.New(slog.NewJSONHandler(&buf, nil)), tt.threshold)
			t.Cleanup(func() { ConfigureSlowDecisionLog(nil, 0) })

			ctx := WithDecisionTrace(WithVhost(context.Background(), VhostAPI), "POST", "/graphql")
			ObserveDecision(ctx, StageTokenResolution, "proxy", 3*time.Millisecond)
			ObserveDecision(ctx, StageRequestBodyRead, "proxy", 2*time.Millisecond)
			ObserveDecision(ctx, StageTotal, "proxy", tt.total)

			out := strings.TrimSpace(buf.String())
			if !tt.wantLog {
				if out != "" {
					t.Fatalf("unexpected log: %s", out)
				}
				return
			}
			lines := strings.Split(out, "\n")
			if len(lines) != 1 {
				t.Fatalf("got %d log lines, want 1: %s", len(lines), out)
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
				t.Fatalf("decode: %v", err)
			}
			want := map[string]any{
				"level":      "WARN",
				"msg":        "slow_decision",
				"token_type": "proxy",
				"vhost":      VhostAPI,
				"method":     "POST",
				"path":       "/graphql",
			}
			for k, v := range want {
				if rec[k] != v {
					t.Errorf("%s = %v, want %v", k, rec[k], v)
				}
			}
			for _, k := range []string{"total_ms", "pipeline_other_ms", "token_resolution_ms", "request_body_read_ms"} {
				if _, ok := rec[k]; !ok {
					t.Errorf("missing field %s in %s", k, lines[0])
				}
			}
			if got := rec["token_resolution_ms"]; got != 3.0 {
				t.Errorf("token_resolution_ms = %v, want 3", got)
			}
		})
	}
}

func TestSlowDecisionLog_NoTraceStillLogs(t *testing.T) {
	var buf bytes.Buffer
	ConfigureSlowDecisionLog(slog.New(slog.NewJSONHandler(&buf, nil)), time.Millisecond)
	t.Cleanup(func() { ConfigureSlowDecisionLog(nil, 0) })
	ObserveDecision(WithVhost(context.Background(), VhostWeb), StageTotal, "", 5*time.Millisecond)
	if !strings.Contains(buf.String(), `"token_type":"unknown"`) {
		t.Errorf("want slow_decision with token_type unknown, got %q", buf.String())
	}
}
