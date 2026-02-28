package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/goodtune/ghp/internal/config"
)

// TestServeMetrics_Methods verifies that the metrics mux only accepts GET
// requests and returns 405 for all other methods.
func TestServeMetrics_Methods(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.Handler())

	tests := []struct {
		method string
		want   int
	}{
		{"GET", http.StatusOK},
		{"POST", http.StatusMethodNotAllowed},
		{"PUT", http.StatusMethodNotAllowed},
		{"DELETE", http.StatusMethodNotAllowed},
		{"PATCH", http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/metrics", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Errorf("%s /metrics: got %d, want %d", tt.method, rr.Code, tt.want)
			}
		})
	}
}

// TestServeMetrics_GET verifies that serveMetrics serves GET /metrics over TCP.
func TestServeMetrics_GET(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	srv := &Server{
		cfg:    &config.Config{Metrics: config.MetricsConfig{Listen: addr}},
		logger: slog.Default(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.serveMetrics(ctx, ln, nil)

	// Retry until the server is ready or timeout.
	var resp *http.Response
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://" + addr + "/metrics")
		if err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("metrics server not reachable: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /metrics: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestServeMetrics_Shutdown verifies that serveMetrics exits cleanly when the
// context is cancelled.
func TestServeMetrics_Shutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := &Server{
		cfg:    &config.Config{Metrics: config.MetricsConfig{Listen: ln.Addr().String()}},
		logger: slog.Default(),
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.serveMetrics(ctx, ln, nil)
	}()

	// Give the server a moment to start, then trigger shutdown.
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// shutdown completed as expected
	case <-time.After(5 * time.Second):
		t.Error("serveMetrics did not shut down within 5 seconds")
	}
}
