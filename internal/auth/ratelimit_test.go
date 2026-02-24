package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPRateLimiter_Allow(t *testing.T) {
	limiter := NewIPRateLimiter(3, time.Minute)

	ip := "1.2.3.4"

	// First three requests should be allowed.
	for i := 0; i < 3; i++ {
		if !limiter.Allow(ip) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// Fourth request should be denied.
	if limiter.Allow(ip) {
		t.Error("fourth request should be rate limited")
	}

	// A different IP is not affected.
	if !limiter.Allow("5.6.7.8") {
		t.Error("different IP should be allowed")
	}
}

func TestIPRateLimiter_WindowExpiry(t *testing.T) {
	// Use a very short window so we can test expiry without sleeping too long.
	limiter := NewIPRateLimiter(2, 50*time.Millisecond)
	ip := "10.0.0.1"

	if !limiter.Allow(ip) {
		t.Fatal("first request should be allowed")
	}
	if !limiter.Allow(ip) {
		t.Fatal("second request should be allowed")
	}
	// Third request should be denied (limit=2).
	if limiter.Allow(ip) {
		t.Error("third request should be rate limited")
	}

	// After the window expires the counter resets.
	time.Sleep(60 * time.Millisecond)
	if !limiter.Allow(ip) {
		t.Error("request after window expiry should be allowed")
	}
}

func TestIPRateLimiter_Middleware(t *testing.T) {
	limiter := NewIPRateLimiter(2, time.Minute)

	called := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	})
	handler := limiter.Middleware(inner)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}
	if called != 2 {
		t.Errorf("inner handler called %d times, want 2", called)
	}

	// Third request should be rejected with 429.
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
	if called != 2 {
		t.Error("inner handler should not be called after rate limit")
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xRealIP    string
		xForwarded string
		want       string
	}{
		{
			name:       "plain remote addr",
			remoteAddr: "1.2.3.4:5678",
			want:       "1.2.3.4",
		},
		{
			name:       "X-Real-IP takes precedence",
			remoteAddr: "1.2.3.4:5678",
			xRealIP:    "9.9.9.9",
			want:       "9.9.9.9",
		},
		{
			name:       "X-Forwarded-For single IP",
			remoteAddr: "1.2.3.4:5678",
			xForwarded: "203.0.113.1",
			want:       "203.0.113.1",
		},
		{
			name:       "X-Forwarded-For first IP used",
			remoteAddr: "1.2.3.4:5678",
			xForwarded: "203.0.113.1, 10.0.0.1, 172.16.0.1",
			want:       "203.0.113.1",
		},
		{
			name:       "X-Real-IP beats X-Forwarded-For",
			remoteAddr: "1.2.3.4:5678",
			xRealIP:    "9.9.9.9",
			xForwarded: "203.0.113.1",
			want:       "9.9.9.9",
		},
		{
			name:       "remote addr without port",
			remoteAddr: "1.2.3.4",
			want:       "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if tt.xForwarded != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwarded)
			}
			got := ClientIP(req)
			if got != tt.want {
				t.Errorf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
