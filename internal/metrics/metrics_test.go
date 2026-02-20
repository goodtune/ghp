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
	ObserveProxyRequest("api.github.com", pt, "GET", 200, 100*time.Millisecond, "rest")
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
	ObserveProxyRequest("api.github.com", pt, "POST", 200, 50*time.Millisecond, "graphql")
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
	ObserveProxyRequest("github.com", pt, "POST", 200, 200*time.Millisecond, "git")
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
	ObserveProxyRequest("api.github.com", pt, "GET", 200, 100*time.Millisecond, "rest")
	after := getCounterValue(t, ProxyRequestTotal, labels)

	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObserveProxyRequest_NilPt(t *testing.T) {
	// Should not panic.
	ObserveProxyRequest("api.github.com", nil, "GET", 200, 100*time.Millisecond, "rest")
}
