package auth

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IPRateLimiter is a sliding-window rate limiter keyed by IP address.
// It allows at most limit requests per window duration from each IP.
type IPRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

// NewIPRateLimiter creates a new IPRateLimiter that allows up to limit requests
// per window duration per IP address.
func NewIPRateLimiter(limit int, window time.Duration) *IPRateLimiter {
	return &IPRateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Allow returns true if a request from ip is within the rate limit.
func (l *IPRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	// Retain only timestamps within the current window.
	reqs := l.requests[ip]
	j := 0
	for _, t := range reqs {
		if t.After(cutoff) {
			reqs[j] = t
			j++
		}
	}
	reqs = reqs[:j]

	if len(reqs) >= l.limit {
		l.requests[ip] = reqs
		return false
	}

	if len(reqs) == 0 {
		// Remove the map entry when there are no in-window requests so that
		// stale IPs do not accumulate and cause unbounded memory growth.
		delete(l.requests, ip)
	}

	l.requests[ip] = append(reqs, now)
	return true
}

// Middleware returns an http.Handler that enforces rate limiting before
// delegating to next. Requests that exceed the limit receive 429.
func (l *IPRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(ClientIP(r)) {
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
