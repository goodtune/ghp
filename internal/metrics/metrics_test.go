package metrics

import (
	"runtime"
	"runtime/debug"
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
	}

	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			labels := prometheus.Labels{
				"stage":      stage,
				"token_type": "proxy",
			}
			before := getHistogramCount(t, ProxyDecisionDuration, labels)
			ObserveDecision(stage, "proxy", 1*time.Millisecond)
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
	}
	before := getHistogramCount(t, ProxyDecisionDuration, labels)
	ObserveDecision(StageTokenExtraction, "", 500*time.Microsecond)
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

func TestObserveDecision_RedirectHeadCheck(t *testing.T) {
	labels := prometheus.Labels{
		"stage":      StageRedirectHeadCheck,
		"token_type": "unknown",
	}
	before := getHistogramCount(t, ProxyDecisionDuration, labels)
	ObserveDecision(StageRedirectHeadCheck, "", 10*time.Millisecond)
	after := getHistogramCount(t, ProxyDecisionDuration, labels)
	if after-before != 1 {
		t.Errorf("expected histogram sample count to increment by 1, got %d", after-before)
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
