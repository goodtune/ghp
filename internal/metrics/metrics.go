// Package metrics registers all Prometheus metrics for ghp and provides helper
// functions for recording observations. Metrics are registered via promauto
// (auto-registering with the default registry) and exposed at /metrics on the
// dedicated metrics server (default port 9136).
//
// The package covers four metric categories:
//   - HTTP-level: request count and duration for all traffic by backend
//   - Proxy-level: detailed metrics for ghx_/gha_ authenticated and native GitHub token traffic (API and git smart-HTTP)
//   - Token lifecycle: creation, revocation, and active token counts
//   - Decision pipeline: per-stage latency breakdown of the proxy overhead
package metrics

import (
	"context"
	"runtime"
	"runtime/debug"
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

	ClientRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_client_request_total",
		Help: "Total number of requests by client source IP, backend, token type, and status.",
	}, []string{"client", "backend", "token_type", "status"})

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

	// TokenScopeRejectedTotal counts token scope entries rejected at creation
	// or scope update because the permission name is not canonical or the
	// level is not read/write. The permission name itself is not a label
	// (unbounded user input).
	TokenScopeRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_token_scope_rejected_total",
		Help: "Total number of token scope entries rejected by reason (unknown_permission, invalid_level).",
	}, []string{"reason"})

	// TokenCleanupDeletedTotal counts proxy tokens hard-deleted by the
	// periodic expired-token cleanup goroutine.
	TokenCleanupDeletedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ghp_token_cleanup_deleted_total",
		Help: "Total number of expired or revoked proxy tokens hard-deleted by the cleanup goroutine.",
	})

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

	// ReleasesRedirectHeadCheckTotal counts the outcomes of HEAD requests
	// made to the redirect target when releases.redirect_head_check is enabled.
	// The "result" label is one of "found" (non-404 response, redirect proceeds),
	// "not_found" (404 returned, friendly error page served), or "error" (network
	// failure, redirect proceeds).
	ReleasesRedirectHeadCheckTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_releases_redirect_head_check_total",
		Help: "Total number of HEAD checks against the release redirect target, by result.",
	}, []string{"result"})

	// CodeloadRedirectTotal counts archive download requests handled by the
	// codeload.github.com handler, labeled by owner, repo, archive format
	// ("tar.gz", "zip", "legacy.tar.gz", "legacy.zip"), and result:
	//   "redirect"    — 302 issued to the configured caching mirror
	//   "passthrough" — request forwarded transparently to upstream codeload
	//                   (allow list match or no redirect_to configured)
	//
	// The full ref (SHA, branch, or tag) is not included as a label to keep
	// cardinality bounded; it is captured in access logs as part of the URL.
	// Cardinality: bounded by (cached repos × archive formats × results).
	CodeloadRedirectTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_codeload_redirect_total",
		Help: "Total codeload.github.com archive requests handled, by owner, repo, archive format, and result.",
	}, []string{"owner", "repo", "archive", "result"})

	// PassthroughScopeDeniedTotal counts scoped client-token requests that
	// the github.com and codeload.github.com virtual hosts deny before the
	// upstream forward (goodtune/ghp#292). vhost is the backend name; reason
	// is "unmapped" (path not mapped to a repository and permission),
	// "repo" (repository not in the allowlist), or "permission" (scope does
	// not grant the mapped permission).
	PassthroughScopeDeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_passthrough_scope_denied_total",
		Help: "Total scoped client-token requests denied on the github.com and codeload.github.com virtual hosts, by vhost and reason.",
	}, []string{"vhost", "reason"})

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

	// ManagementHostRejectedTotal counts requests to the management host's
	// GHES-style API paths (/api/v3/, /api/graphql) rejected because they did
	// not carry a GHP-issued token, labeled by reason:
	//   "anonymous"    — no usable credential (401)
	//   "native_token" — a native GitHub token or other credential (403)
	ManagementHostRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_management_host_rejected_total",
		Help: "Total number of management host API requests rejected for lack of a GHP-issued token, by reason.",
	}, []string{"reason"})

	// EnterpriseExceptionTotal counts evaluations of enterprise access
	// restriction exceptions that matched a request's target, labeled by
	// outcome:
	//   "header_omitted"       — exception applied; restriction header not injected
	//   "identity_substituted" — exception applied and the caller's credential
	//                            was replaced with a managed installation token
	//   "team_denied"          — target matched but the caller is not a member
	//                            of any required team (or could not be
	//                            identified); restriction header kept
	//   "unauthenticated_denied" — target matched an identity-substituting
	//                            exception but the caller's identity could not
	//                            be resolved (anonymous or unverifiable
	//                            credential); restriction header kept
	//   "identity_error"       — target matched but the managed identity could
	//                            not be minted; restriction header kept (fail closed)
	EnterpriseExceptionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_enterprise_exception_total",
		Help: "Total number of enterprise access restriction exception matches, by outcome.",
	}, []string{"outcome"})

	// AgentRepoNarrowingFailedTotal counts installation token mints refused
	// because the repository list could not be narrowed to bare names of the
	// installation account (#294), by reason: "owner_mismatch", "malformed",
	// "lookup_failed" or "empty_login".
	AgentRepoNarrowingFailedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_agent_repo_narrowing_failed_total",
		Help: "Installation token mints refused because repositories could not be narrowed to the installation account, by reason.",
	}, []string{"reason"})

	// ScopeUnmappedDeniedTotal counts REST requests from scoped tokens that
	// were denied because no scope rule matched the method and path
	// (deny-by-default). The method label is normalised by NormalizeMethod.
	ScopeUnmappedDeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_scope_unmapped_denied_total",
		Help: "Total number of scoped-token REST requests denied because no scope rule matched.",
	}, []string{"token_type", "method"})

	// decisionBuckets covers internal decision-making stages (typically µs–ms)
	// as well as the upstream_roundtrip stage, which includes the actual GitHub
	// API call and can easily exceed 1s under load or on slow networks.
	decisionBuckets = []float64{
		0.00001,  // 10µs
		0.000025, // 25µs
		0.00005,  // 50µs
		0.0001,   // 100µs
		0.00025,  // 250µs
		0.0005,   // 500µs
		0.001,    // 1ms
		0.0025,   // 2.5ms
		0.005,    // 5ms
		0.0075,   // 7.5ms
		0.01,     // 10ms
		0.025,    // 25ms
		0.05,     // 50ms
		0.1,      // 100ms
		0.25,     // 250ms
		0.5,      // 500ms
		1.0,      // 1s
		2.5,      // 2.5s
		5.0,      // 5s
		10.0,     // 10s
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
	//   redirect_head_check   – HEAD request to the release redirect target to verify asset availability (releases handler only)
	//   graphql_analysis      – parsing a GraphQL request body and computing the static scope/repository requirements (GraphQL handler only)
	//   cache_lookup          – git cache middleware database lookup of the per-repository cache record (token_type is always "unknown")
	//   forward_proxy_selection – choosing the upstream forward proxy for the outbound request
	//   enterprise_exception  – evaluating enterprise access restriction exceptions
	//
	// The "vhost" label names the virtual host that received the request (see
	// the Vhost* constants): api, web, codeload, management, copilot, or
	// unknown when no inbound request exists (background control-plane calls).
	ProxyDecisionDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ghp_proxy_decision_duration_seconds",
		Help:    "Duration of each stage in the proxy decision pipeline.",
		Buckets: decisionBuckets,
	}, []string{"stage", "token_type", "vhost"})

	// --- Git Cache Metrics ---

	// CacheFetchTotal counts git fetch requests to cache-enabled repositories,
	// labeled by result: "hit" (served from cache), "miss" (fetched from upstream
	// first), "rejected" (access denied), "error" (cache or upstream failure).
	// Per-repo breakdown is available via access logs to avoid unbounded label
	// cardinality.
	CacheFetchTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_cache_fetch_total",
		Help: "Total git fetch requests to cache-enabled repositories, by result.",
	}, []string{"result"})

	// CacheLsRefsTotal counts ls-refs commands forwarded to upstream for
	// cache-enabled repositories.
	CacheLsRefsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ghp_cache_lsrefs_total",
		Help: "Total ls-refs commands forwarded to upstream for cached repos.",
	})

	// CacheWarmTotal counts async cache warming operations triggered when
	// refs change, labeled by result ("success" or "error").
	CacheWarmTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_cache_warm_total",
		Help: "Total cache warming operations triggered by ref changes, by result.",
	}, []string{"result"})

	// CacheReposActive is a gauge reflecting how many repositories currently
	// have caching enabled in the database.
	CacheReposActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ghp_cache_repos_active",
		Help: "Number of repositories with caching currently enabled.",
	})

	// CacheRequestTotal counts git smart HTTP requests per repository with
	// cache outcome. Labels: owner, repo, result. Result values:
	//   "hit"     — served from local cache
	//   "miss"    — cache miss, fetched upstream then served
	//   "nocache" — repository not configured for caching
	//   "bypass"  — repository configured but caching disabled
	//   "error"   — cache operation failed
	//   "rejected"    — upstream rejected access
	//   "passthrough" — delegated to upstream proxy
	//
	// Cardinality note: bounded by the number of distinct repositories
	// accessed through the proxy (typically hundreds). Intended for
	// identifying cache candidate repositories via PromQL.
	CacheRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_cache_request_total",
		Help: "Git smart HTTP requests per repository with cache outcome.",
	}, []string{"owner", "repo", "result"})

	// CachePackfileTotal counts packfile response cache operations, labeled
	// by result: "hit" (served from disk), "miss" (proxied upstream and cached).
	// This is distinct from CacheFetchTotal which tracks the broader fetch flow
	// including rejections and errors. Use this metric to measure the disk cache
	// effectiveness and inform TTL eviction tuning.
	//
	// Labels: owner, repo, user (GitHub username), result.
	// Cardinality: bounded by (cached repos × active users × 2 results).
	CachePackfileTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_cache_packfile_total",
		Help: "Packfile response cache operations by result (hit = served from disk, miss = proxied upstream).",
	}, []string{"owner", "repo", "user", "result"})

	// CachePackfileBytesTotal counts the total bytes served from the packfile
	// response cache, labeled by result. Comparing hit vs miss bytes shows the
	// upstream bandwidth saved by caching.
	//
	// Labels: owner, repo, user (GitHub username), result.
	CachePackfileBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_cache_packfile_bytes_total",
		Help: "Total bytes served from packfile response cache by result.",
	}, []string{"owner", "repo", "user", "result"})

	// CacheEvictionTotal counts the number of cached protocol response files
	// evicted by the size-limit cleanup goroutine, labeled by owner and repo.
	CacheEvictionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_cache_eviction_total",
		Help: "Total cached protocol response files evicted by size-limit cleanup.",
	}, []string{"owner", "repo"})

	// CacheResponseSizeBytes reports the current total size (in bytes) of
	// cached protocol response files per repository, updated each cleanup cycle.
	CacheResponseSizeBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ghp_cache_response_size_bytes",
		Help: "Current total size of cached protocol response files per repository.",
	}, []string{"owner", "repo"})

	// CLIDeviceStartedTotal counts CLI device-authorization requests
	// initiated via POST /cli/auth/device. Each "ghp auth login" invocation
	// increments this counter exactly once.
	CLIDeviceStartedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ghp_cli_auth_device_started_total",
		Help: "Total number of CLI device-authorization requests initiated.",
	})

	// CLIDeviceCompletedTotal counts CLI device-authorization requests that
	// reached a terminal state, labeled by result: "approved" (user
	// authorized and CLI received a session token), "denied" (user clicked
	// deny), or "expired" (record TTL'd before the user acted).
	CLIDeviceCompletedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_cli_auth_device_completed_total",
		Help: "Total number of CLI device-authorization requests that reached a terminal state.",
	}, []string{"result"})

	// ForwardProxySelectTotal counts forward proxy routing decisions on
	// outbound GitHub requests, labeled by the matched ruleset name and the
	// layer that matched ("token", "app", "net", "system", "control";
	// "header" when the client selected the proxy via request headers;
	// "ambient" when no ruleset applied and the environment default was
	// used; "direct" for non-GitHub control calls sent with no proxy;
	// ruleset is empty for header, ambient, and direct decisions).
	ForwardProxySelectTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_forward_proxy_select_total",
		Help: "Total forward proxy routing decisions by matched ruleset and layer.",
	}, []string{"ruleset", "layer"})

	// ForwardProxyClientSpecifiedTotal counts requests whose forward proxy
	// was selected by the client via the X-GitHub-Proxy-Forward-* request
	// headers (feature-gated by forward_proxy.allow_request_header),
	// labeled by the proxy URL scheme and the client token type. The proxy
	// URL itself is never used as a label — it is client-controlled and
	// unbounded.
	ForwardProxyClientSpecifiedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_forward_proxy_client_specified_total",
		Help: "Total requests routed through a client-specified forward proxy via request headers.",
	}, []string{"scheme", "token_type"})

	// ForwardProxyRulesetsActive is a gauge reflecting how many enabled
	// forward proxy rulesets are currently compiled into the route table.
	ForwardProxyRulesetsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ghp_forward_proxy_rulesets_active",
		Help: "Number of enabled forward proxy rulesets currently active in the route table.",
	})

	// --- Upstream transport metrics ---
	//
	// Recorded by the forward proxy routing transport for every outbound
	// request (proxied traffic and ghp's own control-plane calls). Labels are
	// bounded: protocol is one of the UpstreamProtocol* constants and vhost
	// one of the Vhost* constants; no hosts, paths or proxy URLs.

	// UpstreamSentBytesTotal counts request body bytes sent upstream
	// (payload only: no headers, framing or TLS overhead).
	UpstreamSentBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_upstream_sent_bytes_total",
		Help: "Request body bytes sent to upstream GitHub, by negotiated protocol and vhost.",
	}, []string{"protocol", "vhost"})

	// UpstreamReceivedBytesTotal counts response body bytes received from
	// upstream (payload only), added as the client reads the body.
	UpstreamReceivedBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_upstream_received_bytes_total",
		Help: "Response body bytes received from upstream GitHub, by negotiated protocol and vhost.",
	}, []string{"protocol", "vhost"})

	// UpstreamConnectionsTotal counts the connection each upstream request
	// used, by result: "opened" (newly dialled) or "reused" (taken from the
	// pool, or another stream on a live HTTP/2 connection).
	UpstreamConnectionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_upstream_connections_total",
		Help: "Upstream connections used by outbound requests, by negotiated protocol, vhost and result (opened, reused).",
	}, []string{"protocol", "vhost", "result"})

	// UpstreamFirstByteDuration measures from the start of the upstream
	// round trip, after proxy selection (pool wait or dial, TLS, request write, GitHub
	// processing) to the first response byte. upstream_roundtrip minus this
	// is the response transfer time.
	UpstreamFirstByteDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ghp_upstream_first_byte_seconds",
		Help:    "Time from the start of an upstream request to the first response byte, by negotiated protocol and vhost.",
		Buckets: decisionBuckets,
	}, []string{"protocol", "vhost"})

	// WebhookReceivedTotal counts GitHub webhook deliveries presented to the
	// ingress handler, labeled by the X-GitHub-Event name and the outcome:
	//   "published"         — verified and stored in the JetStream stream
	//   "duplicate"         — verified, but the delivery GUID was already
	//                         stored within the dedupe window
	//   "invalid_signature" — no candidate secret produced a matching
	//                         X-Hub-Signature-256 (or the header was absent)
	//   "unknown_app"       — no secret could be resolved for the delivery
	//                         target at all
	//   "bad_request"       — malformed delivery (missing headers, bad
	//                         form encoding, oversized body)
	//   "publish_error"     — JetStream publish failed; 503 returned so the
	//                         operator can redeliver from GitHub
	//   "internal_error"    — the secret lookup itself failed (store error)
	// The event label is bounded by GitHub's event catalogue; unknown or
	// empty event names are normalised to "unknown".
	WebhookReceivedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_webhook_received_total",
		Help: "Total GitHub webhook deliveries received by the ingress handler, by event and outcome.",
	}, []string{"event", "result"})

	// WebhookPublishDuration measures the time from handing a verified
	// delivery to JetStream until the publish acknowledgement returns.
	WebhookPublishDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "ghp_webhook_publish_duration_seconds",
		Help:    "Duration of JetStream publish + acknowledgement for webhook deliveries.",
		Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
	})

	// WebhookNgrokTunnelUp is 1 while the embedded ngrok agent session is
	// connected to the ngrok service and 0 otherwise (disabled, connecting,
	// or disconnected).
	WebhookNgrokTunnelUp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ghp_webhook_ngrok_tunnel_up",
		Help: "1 when the embedded ngrok tunnel session is connected, 0 otherwise.",
	})

	// WebhookStreamMessages and WebhookStreamBytes reflect the current size
	// of the webhook JetStream stream. They are refreshed periodically from
	// stream info rather than incremented per publish, so they also account
	// for retention-driven discards.
	WebhookStreamMessages = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ghp_webhook_stream_messages",
		Help: "Number of webhook deliveries currently retained in the JetStream stream.",
	})
	WebhookStreamBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ghp_webhook_stream_bytes",
		Help: "Total bytes currently retained in the webhook JetStream stream.",
	})

	// WebhookSubscribersActive counts open subscriber connections by kind:
	// "sse" for admin API server-sent-events streams and "nats" for native
	// NATS clients connected to the embedded server's listener.
	WebhookSubscribersActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ghp_webhook_subscribers_active",
		Help: "Number of active webhook subscribers by kind (sse, nats).",
	}, []string{"kind"})

	// BuildInfo is a gauge with a constant value of 1 labeled by build
	// metadata. It follows the node_exporter_build_info convention.
	BuildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ghp_build_info",
		Help: "A metric with a constant '1' value labeled by version, revision, goversion, goos, and goarch from which ghp was built.",
	}, []string{"version", "revision", "goversion", "goos", "goarch"})
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
	StageRedirectHeadCheck     = "redirect_head_check"
	StageCacheLookup           = "cache_lookup"
	StageGraphQLAnalysis       = "graphql_analysis"
	StageEnterpriseException   = "enterprise_exception"
	StageForwardProxySelection = "forward_proxy_selection"
	StageRequestBodyRead       = "request_body_read"
	StageRequestBuild          = "request_build"
	// StagePipelineOther is derived, not timed: total minus the stages
	// observed for the same request before total (see WithDecisionTrace).
	StagePipelineOther = "pipeline_other"
)

// Vhost label values for ghp_proxy_decision_duration_seconds. The set is
// closed: pass only these constants to WithVhost.
const (
	VhostAPI        = "api"
	VhostWeb        = "web"
	VhostCodeload   = "codeload"
	VhostManagement = "management"
	VhostCopilot    = "copilot"
	VhostUnknown    = "unknown"
)

// Upstream protocol label values. The set is closed.
const (
	UpstreamProtocolH2      = "h2"
	UpstreamProtocolHTTP1   = "http/1.1"
	UpstreamProtocolUnknown = "unknown"
)

// Upstream connection result label values.
const (
	UpstreamConnOpened = "opened"
	UpstreamConnReused = "reused"
)

// UpstreamProtocol maps a TLS ALPN value to a protocol label. An empty
// value (no ALPN, or a plain TCP connection) means HTTP/1.1.
func UpstreamProtocol(alpn string) string {
	switch alpn {
	case "h2":
		return UpstreamProtocolH2
	case "", "http/1.1":
		return UpstreamProtocolHTTP1
	default:
		return UpstreamProtocolUnknown
	}
}

type vhostKey struct{}

// WithVhost returns a copy of ctx that carries the vhost label value. The host
// dispatcher calls it once per request; outbound requests built from the
// inbound context inherit it.
func WithVhost(ctx context.Context, vhost string) context.Context {
	return context.WithValue(ctx, vhostKey{}, vhost)
}

// VhostFromContext returns the vhost label value stored by WithVhost, or
// VhostUnknown when ctx is nil or carries none.
func VhostFromContext(ctx context.Context) string {
	if ctx == nil {
		return VhostUnknown
	}
	if v, ok := ctx.Value(vhostKey{}).(string); ok && v != "" {
		return v
	}
	return VhostUnknown
}

// ObserveDecision records the duration of a single stage in the proxy
// decision pipeline. The vhost label is read from ctx (see WithVhost).
// tokenType should be "proxy", "agent", or "" for stages that run before the
// token type is known (normalised to "unknown").
func ObserveDecision(ctx context.Context, stage, tokenType string, dur time.Duration) {
	if tokenType == "" {
		tokenType = "unknown"
	}
	vhost := VhostFromContext(ctx)
	ProxyDecisionDuration.WithLabelValues(stage, tokenType, vhost).Observe(dur.Seconds())
	if stage == StageTotal {
		finishDecision(ctx, tokenType, vhost, dur)
		return
	}
	if tr := decisionTraceFrom(ctx); tr != nil {
		tr.add(stage, dur)
	}
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

// ObservePassthroughRequest records proxy-level request metrics for passthrough
// traffic forwarded without ghx_/gha_ token resolution. It uses the same
// ProxyRequestDuration and ProxyRequestTotal vectors as managed tokens, with an
// empty "app" label. Token type and username are best-effort: when no native
// token is present they are recorded as "unknown".
func ObservePassthroughRequest(backendName, method string, status int, dur time.Duration, apiType, tokenType, username string) {
	if username == "" {
		username = "unknown"
	}
	if tokenType == "" {
		tokenType = "unknown"
	}
	statusStr := strconv.Itoa(status)
	ProxyRequestDuration.WithLabelValues(backendName, method, statusStr, tokenType, apiType, username, "").Observe(dur.Seconds())
	ProxyRequestTotal.WithLabelValues(backendName, method, statusStr, tokenType, apiType, username, "").Inc()
}

func ObserveClientRequest(client, backendName, tokenType string, status int) {
	if client == "" {
		client = "unknown"
	}
	if tokenType == "" {
		tokenType = "unknown"
	}
	ClientRequestTotal.WithLabelValues(client, backendName, tokenType, strconv.Itoa(status)).Inc()
}

// SetBuildInfo records build metadata as a gauge with a constant value of 1.
// It should be called once at server startup. The revision is extracted from
// Go's debug.ReadBuildInfo VCS metadata; if unavailable it defaults to "unknown".
func SetBuildInfo(version string) {
	revision := "unknown"
	if info, ok := runtimeDebugReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				revision = s.Value
				break
			}
		}
	}
	BuildInfo.WithLabelValues(version, revision, runtime.Version(), runtime.GOOS, runtime.GOARCH).Set(1)
}

// runtimeDebugReadBuildInfo is an indirection over debug.ReadBuildInfo so that
// tests can inject a fake. It is package-level so tests can swap it.
var runtimeDebugReadBuildInfo = defaultReadBuildInfo

func defaultReadBuildInfo() (*debug.BuildInfo, bool) {
	return debug.ReadBuildInfo()
}

// NormalizeMethod maps an HTTP method to a bounded label value. Standard
// methods are returned unchanged; anything else becomes "OTHER".
func NormalizeMethod(method string) string {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return method
	}
	return "OTHER"
}
