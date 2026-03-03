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

	// BlockAnonymousGitEnabled reflects whether the anonymous git blocking
	// feature is currently active (1) or inactive (0). Set at server startup
	// and on config reload (SIGUSR1); not updated per-request.
	BlockAnonymousGitEnabled = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ghp_block_anonymous_git_enabled",
		Help: "Set to 1 when anonymous git blocking (block.anonymous_git) is enabled, 0 otherwise.",
	})

	// BlockAnonymousGitTotal counts the number of anonymous git requests
	// that were short-circuited before egressing to GitHub.
	BlockAnonymousGitTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ghp_block_anonymous_git_total",
		Help: "Total number of anonymous git requests blocked by the anonymous git blocking feature.",
	})

	// decisionBuckets covers internal decision-making stages (typically µs–ms)
	// as well as the upstream_roundtrip stage, which includes the actual GitHub
	// API call and can easily exceed 1s under load or on slow networks.
	decisionBuckets = []float64{
		0.00005, // 50µs
		0.0001,  // 100µs
		0.0005,  // 500µs
		0.001,   // 1ms
		0.005,   // 5ms
		0.01,    // 10ms
		0.025,   // 25ms
		0.05,    // 50ms
		0.1,     // 100ms
		0.25,    // 250ms
		0.5,     // 500ms
		1.0,     // 1s
		2.5,     // 2.5s
		5.0,     // 5s
		10.0,    // 10s
	}

	// ProxyDecisionDuration records time spent in each stage of the proxy
	// decision-making pipeline. Internal stages (token_extraction through
	// github_token_resolution) measure pre-forward overhead; upstream_roundtrip
	// measures the actual GitHub API call; total measures only the pre-forward
	// decision-making overhead (i.e., arrival to just before the upstream call).
	// The "stage" label identifies the pipeline step:
	//
	//   total                  – arrival to completion of proxy decision (pre-forward only; upstream not included)
	//   token_extraction       – unpacking the Authorization header
	//   border_policy_check    – evaluating the token type border policy (block config)
	//   token_resolution       – SHA-256 hash + database lookup + expiry/revocation check
	//   username_resolution    – resolving GitHub username from user ID
	//   scope_parsing          – JSON unmarshalling of repository & permission scopes
	//   scope_enforcement      – repository allowlist + permission level checks
	//   github_token_resolution – loading & decrypting (or refreshing) the real GitHub credential
	//   upstream_roundtrip     – proxying the upstream GitHub request and streaming the response (network + GitHub processing + response body transfer)
	ProxyDecisionDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ghp_proxy_decision_duration_seconds",
		Help:    "Duration of each stage in the proxy decision pipeline.",
		Buckets: decisionBuckets,
	}, []string{"stage", "token_type"})
)

// Decision pipeline stage constants.
const (
	StageTotal                 = "total"
	StageTokenExtraction       = "token_extraction"
	StageBorderPolicyCheck     = "border_policy_check"
	StageTokenResolution       = "token_resolution"
	StageUsernameResolution    = "username_resolution"
	StageScopeParsing          = "scope_parsing"
	StageScopeEnforcement      = "scope_enforcement"
	StageGitHubTokenResolution = "github_token_resolution"
	StageUpstreamRoundtrip     = "upstream_roundtrip"
)

// ObserveDecision records the duration of a single stage in the proxy
// decision pipeline. tokenType should be "proxy", "agent", or "" for stages
// that run before the token type is known (normalised to "unknown").
func ObserveDecision(stage, tokenType string, dur time.Duration) {
	if tokenType == "" {
		tokenType = "unknown"
	}
	ProxyDecisionDuration.WithLabelValues(stage, tokenType).Observe(dur.Seconds())
}

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
