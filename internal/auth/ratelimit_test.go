package auth

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// newTestLimiter creates a limiter with a no-op logger suitable for unit tests.
func newTestLimiter(limit int, window time.Duration) *IPRateLimiter {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewIPRateLimiter(limit, window, "/test", logger)
}

func TestIPRateLimiter_Allow(t *testing.T) {
	limiter := newTestLimiter(3, time.Minute)
	ip := "1.2.3.4"

	for i := 0; i < 3; i++ {
		if !limiter.Allow(ip) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	if limiter.Allow(ip) {
		t.Error("fourth request should be rate limited")
	}

	if !limiter.Allow("5.6.7.8") {
		t.Error("different IP should be allowed")
	}
}

func TestIPRateLimiter_Middleware(t *testing.T) {
	limiter := newTestLimiter(2, time.Minute)

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

func TestIPRateLimiter_Middleware_ResponseHeaders(t *testing.T) {
	limiter := newTestLimiter(1, time.Minute)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := limiter.Middleware(inner)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Error("Retry-After header missing on 429 response")
	}
}

func TestIPRateLimiter_ConcurrentAccess(t *testing.T) {
	limiter := newTestLimiter(1000, time.Minute)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := limiter.Middleware(inner)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
			for j := 0; j < 10; j++ {
				req := httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = ip + ":1234"
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
			}
		}(i)
	}
	wg.Wait()
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
