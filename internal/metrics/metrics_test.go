package metrics

import (
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
		StageTokenResolution,
		StageUsernameResolution,
		StageScopeParsing,
		StageScopeEnforcement,
		StageGitHubTokenResolution,
		StageUpstreamRoundtrip,
	}

	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			labels := prometheus.Labels{
				"stage":      stage,
				"token_type": "ghx",
			}
			before := getHistogramCount(t, ProxyDecisionDuration, labels)
			ObserveDecision(stage, "ghx", 1*time.Millisecond)
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
