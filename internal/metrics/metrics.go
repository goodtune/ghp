// Package metrics exposes a Prometheus /metrics endpoint on a separate port.
package metrics

import (
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	ProxyRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ghp_proxy_request_duration_seconds",
		Help:    "Duration of proxied requests to GitHub.",
		Buckets: prometheus.DefBuckets,
	}, []string{"user", "repo", "method", "status"})

	ProxyRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_proxy_request_total",
		Help: "Total number of proxied requests.",
	}, []string{"user", "repo", "method", "status"})

	TokenActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ghp_token_active",
		Help: "Number of active tokens per user.",
	}, []string{"user"})

	TokenCreatedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_token_created_total",
		Help: "Total number of tokens created.",
	}, []string{"user"})

	TokenRevokedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_token_revoked_total",
		Help: "Total number of tokens revoked.",
	}, []string{"user"})

	GitHubRateLimitRemaining = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ghp_github_ratelimit_remaining",
		Help: "GitHub API rate limit remaining.",
	}, []string{"user"})

	GitHubRateLimitLimit = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ghp_github_ratelimit_limit",
		Help: "GitHub API rate limit total.",
	}, []string{"user"})

	GitHubTokenRefreshTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_github_token_refresh_total",
		Help: "Total number of GitHub token refresh attempts.",
	}, []string{"user", "status"})
)

// Serve starts the Prometheus metrics server on the given address.
func Serve(addr string, logger *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	logger.Info("metrics server starting", "listen", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("metrics server failed", "error", err)
	}
}
