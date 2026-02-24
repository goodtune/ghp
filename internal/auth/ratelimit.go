package auth

import (
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/ghp/internal/metrics"
)

// visitor holds in-window request timestamps and the last-seen time for an IP.
type visitor struct {
	reqs     []time.Time
	lastSeen time.Time
}

// IPRateLimiter is a sliding-window rate limiter keyed by IP address.
// It allows at most limit requests per window duration from each IP.
// A background goroutine periodically evicts entries for IPs that have been
// inactive for longer than the window, bounding memory growth.
type IPRateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	limit    int
	window   time.Duration

	// endpoint names the protected route; used in log and metric labels.
	endpoint string
	logger   *slog.Logger
}

// NewIPRateLimiter creates a new IPRateLimiter that allows up to limit requests
// per window duration per IP address.
//
// endpoint is included in slog and Prometheus label values so operators can
// distinguish traffic sources in dashboards and alerts.
// logger receives a Warn-level entry for every rejected request.
//
// A background goroutine is started to evict stale entries; it runs for the
// lifetime of the process (no explicit stop is required for server-lifetime
// limiters).
func NewIPRateLimiter(limit int, window time.Duration, endpoint string, logger *slog.Logger) *IPRateLimiter {
	l := &IPRateLimiter{
		visitors: make(map[string]*visitor),
		limit:    limit,
		window:   window,
		endpoint: endpoint,
		logger:   logger,
	}
	go l.cleanupLoop()
	return l
}

// allow checks whether a request from ip is within the rate limit.
// It returns (true, 0) when the request is allowed, or (false, retryAfter)
// when it is rejected, where retryAfter is the time until the oldest
// in-window request expires and a slot becomes free.
func (l *IPRateLimiter) allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	v, ok := l.visitors[ip]
	if !ok {
		v = &visitor{}
		l.visitors[ip] = v
	}
	v.lastSeen = now

	// Prune timestamps outside the current window (in-place, no allocation).
	j := 0
	for _, t := range v.reqs {
		if t.After(cutoff) {
			v.reqs[j] = t
			j++
		}
	}
	v.reqs = v.reqs[:j]

	if len(v.reqs) >= l.limit {
		// Exact time until the oldest slot in the window expires.
		retryAfter := v.reqs[0].Add(l.window).Sub(now)
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return false, retryAfter
	}

	v.reqs = append(v.reqs, now)
	return true, 0
}

// Allow reports whether a request from ip is within the rate limit.
// It is safe for concurrent use.
func (l *IPRateLimiter) Allow(ip string) bool {
	ok, _ := l.allow(ip)
	return ok
}

// cleanupLoop runs in a background goroutine and evicts visitor entries that
// have not been seen within the past window, preventing unbounded memory growth
// from IPs that stop making requests.
func (l *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(l.window)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		cutoff := time.Now().Add(-l.window)
		for ip, v := range l.visitors {
			if v.lastSeen.Before(cutoff) {
				delete(l.visitors, ip)
			}
		}
		l.mu.Unlock()
	}
}

// Middleware returns an http.Handler that enforces the rate limit before
// delegating to next.
//
// Rejected requests receive:
//   - HTTP 429 Too Many Requests
//   - Content-Type: application/json
//   - Retry-After: seconds until the next request slot is available
//   - a JSON error body
//
// Each rejection is also:
//   - logged via slog at Warn level with endpoint, IP, and retry_after_seconds
//   - counted in the ghp_auth_rate_limit_total{endpoint} Prometheus counter
//
// These two observability signals allow operators to build dashboards and
// alerts that reveal sustained brute-force or resource-exhaustion attempts.
func (l *IPRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		if ok, retryAfter := l.allow(ip); !ok {
			retryAfterSec := int(math.Ceil(retryAfter.Seconds()))
			if retryAfterSec < 1 {
				retryAfterSec = 1
			}
			l.logger.Warn("rate_limit_exceeded",
				"endpoint", l.endpoint,
				"ip", ip,
				"retry_after_seconds", retryAfterSec,
			)
			metrics.RateLimitTotal.WithLabelValues(l.endpoint).Inc()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSec))
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"message":"Rate limit exceeded. Please try again later."}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClientIP extracts the client IP address from the request.
// When the server runs behind a trusted reverse proxy it uses X-Real-IP or
// the first entry of X-Forwarded-For; otherwise it falls back to RemoteAddr.
// Note: X-Real-IP and X-Forwarded-For headers can be spoofed by clients when
// the server is not behind a proxy. Deploy behind a reverse proxy that strips
// or overwrites these headers to prevent rate-limit bypass.
func ClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// X-Forwarded-For may be a comma-separated list; take the first entry.
		if idx := strings.IndexByte(forwarded, ','); idx != -1 {
			return strings.TrimSpace(forwarded[:idx])
		}
		return strings.TrimSpace(forwarded)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
