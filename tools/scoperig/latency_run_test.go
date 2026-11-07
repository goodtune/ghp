package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/report"
)

func TestLoadConfig_Metrics(t *testing.T) {
	tests := []struct {
		name    string
		block   string
		env     map[string]string
		want    MetricsConfig
		wantErr string
	}{
		{"omitted", "", nil, MetricsConfig{ScrapeWait: 45 * time.Second}, ""},
		{"grafana proxy url", "metrics:\n  prometheus_url: https://grafana.example.test/api/datasources/proxy/uid/prom\n  selector: job=\"ghp\"\n  scrape_wait: 1m\n", nil,
			MetricsConfig{PrometheusURL: "https://grafana.example.test/api/datasources/proxy/uid/prom", Selector: `job="ghp"`, ScrapeWait: time.Minute}, ""},
		{"bearer from env", "metrics:\n  prometheus_url: http://prom.example.test:9090\n  bearer_token_env: RIG_PROM_TOKEN\n", map[string]string{"RIG_PROM_TOKEN": "t0k"},
			MetricsConfig{PrometheusURL: "http://prom.example.test:9090", BearerTokenEnv: "RIG_PROM_TOKEN", Bearer: "t0k", ScrapeWait: 45 * time.Second}, ""},
		{"bearer env unset", "metrics:\n  prometheus_url: https://p.example.test\n  bearer_token_env: RIG_PROM_TOKEN\n", nil, MetricsConfig{}, "RIG_PROM_TOKEN is not set"},
		{"zero wait", "metrics:\n  scrape_wait: 0s\n", nil, MetricsConfig{ScrapeWait: 0}, ""},
		{"bad scheme", "metrics:\n  prometheus_url: ftp://p.example.test\n", nil, MetricsConfig{}, "metrics.prometheus_url"},
		{"credentials in url", "metrics:\n  prometheus_url: https://u:p@p.example.test\n", nil, MetricsConfig{}, "metrics.prometheus_url"},
		{"query in url", "metrics:\n  prometheus_url: https://p.example.test/?x=1\n", nil, MetricsConfig{}, "metrics.prometheus_url"},
		{"braces in selector", "metrics:\n  selector: '{job=\"ghp\"}'\n", nil, MetricsConfig{}, "metrics.selector"},
		{"bad wait", "metrics:\n  scrape_wait: soon\n", nil, MetricsConfig{}, "metrics.scrape_wait"},
		{"negative wait", "metrics:\n  scrape_wait: -1s\n", nil, MetricsConfig{}, "metrics.scrape_wait"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.yaml")
			body := "fixtures:\n  repo_a: o/a\n  repo_b: o/b\n  repo_w: o/w\n" + tt.block
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := LoadConfig(envMap(tt.env), p)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.Metrics != tt.want {
				t.Errorf("metrics = %+v, want %+v", c.Metrics, tt.want)
			}
		})
	}
}

func TestCollectLatency(t *testing.T) {
	start := time.Date(2026, 11, 7, 7, 49, 38, 0, time.UTC)
	rep := &report.Report{RunID: "20261107T0749Z-b03f", StartedAt: start.Format(time.RFC3339)}
	var gotUA string
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		q := r.URL.Query().Get("query")
		result := ""
		switch {
		case strings.Contains(q, "decision_duration_seconds_bucket"):
			result = `{"metric":{"stage":"total","token_type":"proxy","le":"0.005"},"value":[0,"150"]},` +
				`{"metric":{"stage":"total","token_type":"proxy","le":"+Inf"},"value":[0,"150"]}`
		case strings.Contains(q, "decision_duration_seconds_count"):
			result = `{"metric":{"stage":"total","token_type":"proxy"},"value":[0,"150"]}`
		case strings.Contains(q, "decision_duration_seconds_sum"):
			result = `{"metric":{"stage":"total","token_type":"proxy"},"value":[0,"0.3"]}`
		case strings.Contains(q, "ghp_build_info"):
			result = `{"metric":{"version":"0.25.0","revision":"d8f3b9de"},"value":[0,"1"]}`
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[` + result + `]}}`))
	}))
	defer prom.Close()

	t.Run("not configured", func(t *testing.T) {
		got := collectLatency(context.Background(), &Config{}, runDeps{}, rep)
		if got.Status != report.LatencyNotConfigured {
			t.Errorf("status = %q", got.Status)
		}
	})
	t.Run("waits then queries the run window", func(t *testing.T) {
		var slept time.Duration
		var out bytes.Buffer
		deps := runDeps{
			PromHTTP:   prom.Client(),
			Now:        func() time.Time { return start.Add(169 * time.Second) },
			Sleep:      func(_ context.Context, d time.Duration) error { slept = d; return nil },
			RigVersion: func() string { return "abc" },
			Out:        &out,
		}
		c := &Config{Metrics: MetricsConfig{PrometheusURL: prom.URL, ScrapeWait: 45 * time.Second}}
		got := collectLatency(context.Background(), c, deps, rep)
		if got.Status != report.LatencyOK || got.WindowSeconds != 169 || got.Version != "0.25.0" {
			t.Fatalf("latency = %+v", got)
		}
		if slept != 45*time.Second || !strings.Contains(out.String(), "waiting 45s") {
			t.Errorf("slept %s, out %q", slept, out.String())
		}
		if len(got.Stages) != 1 || got.Stages[0].Samples != 150 || got.Stages[0].P99 != 0.005*0.99 {
			t.Errorf("stages = %+v", got.Stages)
		}
		if gotUA != "ghp-scoperig/abc (run=20261107T0749Z-b03f)" {
			t.Errorf("User-Agent = %q", gotUA)
		}
	})
	t.Run("interrupted wait is unavailable", func(t *testing.T) {
		deps := runDeps{PromHTTP: prom.Client(), Sleep: func(context.Context, time.Duration) error { return context.Canceled }}
		c := &Config{Metrics: MetricsConfig{PrometheusURL: prom.URL, ScrapeWait: time.Second}}
		got := collectLatency(context.Background(), c, deps, rep)
		if got.Status != report.LatencyUnavailable || !strings.Contains(got.Error, "interrupted") {
			t.Errorf("latency = %+v", got)
		}
	})
	t.Run("query failure is unavailable", func(t *testing.T) {
		bad := httptest.NewServer(http.NotFoundHandler())
		defer bad.Close()
		deps := runDeps{PromHTTP: bad.Client(), Now: func() time.Time { return start.Add(time.Minute) }}
		c := &Config{Metrics: MetricsConfig{PrometheusURL: bad.URL}}
		got := collectLatency(context.Background(), c, deps, rep)
		if got.Status != report.LatencyUnavailable || got.Error == "" {
			t.Errorf("latency = %+v", got)
		}
	})
}
