package auth

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/goodtune/ghp/internal/metrics"
)

// visitorTTL is how long an idle visitor entry is kept before being evicted.
const visitorTTL = 3 * time.Minute

// visitor holds the per-IP rate limiter and the last time it was seen.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// IPRateLimiter is a per-IP token-bucket rate limiter backed by
// golang.org/x/time/rate. Stale visitor entries are evicted on each
// Allow call so memory usage is bounded.
type IPRateLimiter struct {
	mu          sync.Mutex
	visitors    map[string]*visitor
	ratePerSec  rate.Limit
	burst       int
}

// NewIPRateLimiter creates a new IPRateLimiter that allows up to limit requests
// per window duration per IP address. The underlying token bucket refills at
// limit/window tokens per second with a burst equal to limit.
func NewIPRateLimiter(limit int, window time.Duration) *IPRateLimiter {
	ratePerSec := rate.Limit(float64(limit) / window.Seconds())
	return &IPRateLimiter{
		visitors:   make(map[string]*visitor),
		ratePerSec: ratePerSec,
		burst:      limit,
	}
}

// Allow returns true if a request from ip is within the rate limit.
func (l *IPRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.evictStale()

	v, ok := l.visitors[ip]
	if !ok {
		v = &visitor{limiter: rate.NewLimiter(l.ratePerSec, l.burst)}
		l.visitors[ip] = v
	}
	v.lastSeen = time.Now()
	return v.limiter.Allow()
}

// evictStale removes visitor entries that have not been seen within visitorTTL.
// Must be called with l.mu held.
func (l *IPRateLimiter) evictStale() {
	cutoff := time.Now().Add(-visitorTTL)
	for ip, v := range l.visitors {
		if v.lastSeen.Before(cutoff) {
			delete(l.visitors, ip)
		}
	}
}

// Middleware returns an http.Handler that enforces rate limiting before
// delegating to next. Requests that exceed the limit receive 429.
// endpoint is used as a label on the ghp_ratelimit_rejected_total metric.
func (l *IPRateLimiter) Middleware(endpoint string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(ClientIP(r)) {
			metrics.RateLimitRejectedTotal.WithLabelValues(endpoint).Inc()
			http.Error(w, `{"message":"Rate limit exceeded. Please try again later."}`, http.StatusTooManyRequests)
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
