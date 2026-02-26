// Package metrics registers Prometheus metrics for ghp.
package metrics

import (
	"strconv"
	"time"

	"github.com/goodtune/ghp/internal/database"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTP-level metrics for all requests, labeled by backend.
	HttpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ghp_http_request_duration_seconds",
		Help:    "Duration of HTTP requests by backend.",
		Buckets: prometheus.DefBuckets,
	}, []string{"backend", "method", "status"})

	HttpRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_http_request_total",
		Help: "Total number of HTTP requests by backend.",
	}, []string{"backend", "method", "status"})

	// Proxy-level metrics for ghx_/gha_ authenticated requests.
	ProxyRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ghp_proxy_request_duration_seconds",
		Help:    "Duration of proxied requests to GitHub.",
		Buckets: prometheus.DefBuckets,
	}, []string{"backend", "method", "status", "token_type", "type", "user", "app"})

	ProxyRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_proxy_request_total",
		Help: "Total number of proxied requests.",
	}, []string{"backend", "method", "status", "token_type", "type", "user", "app"})

	// Note: this gauge is driven by in-process increment/decrement calls and is
	// not seeded from the database on startup. After a process restart it begins
	// at zero rather than reflecting the real count of active tokens in the store.
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

	// RateLimitTotal counts requests rejected by the auth/API rate limiters,
	// labelled by endpoint. Use this metric to alert on sustained abuse.
	RateLimitTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_auth_rate_limit_total",
		Help: "Total number of requests rejected by the auth rate limiter, by endpoint.",
	}, []string{"endpoint"})
)

// ObserveProxyRequest records proxy-level request metrics for a completed request.
// If pt is nil the call is a no-op. apiType describes the request type (for example
// "rest", "graphql", or "git") used for the "type" metric label; callers should pass
// an appropriate value or "" if the type is unknown. The username parameter should be
// the GitHub username of the token owner (not the internal user ID).
func ObserveProxyRequest(backend string, pt *database.ProxyToken, method string, status int, dur time.Duration, apiType string, username string) {
	if pt == nil {
		return
	}
	if username == "" {
		username = "unknown"
	}
	app := ""
	if pt.InstallationID != nil {
		app = strconv.FormatInt(*pt.InstallationID, 10)
	}
	statusStr := strconv.Itoa(status)

	ProxyRequestDuration.WithLabelValues(backend, method, statusStr, pt.TokenType, apiType, username, app).Observe(dur.Seconds())
	ProxyRequestTotal.WithLabelValues(backend, method, statusStr, pt.TokenType, apiType, username, app).Inc()
}
