package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/proxy"
)

// responseRecorder wraps http.ResponseWriter to capture status and size.
type responseRecorder struct {
	http.ResponseWriter
	status      int
	size        int
	wroteHeader bool
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.status = code
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.size += n
	return n, err
}

// Flush implements http.Flusher by delegating to the underlying writer.
func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter so callers can access
// optional interfaces (e.g. http.Hijacker) via httputil helpers.
func (r *responseRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// Caddy-compatible JSON access log types.

type accessLogEntry struct {
	Level       string              `json:"level"`
	TS          float64             `json:"ts"`
	Logger      string              `json:"logger"`
	Msg         string              `json:"msg"`
	Request     requestEntry        `json:"request"`
	BytesRead   int                 `json:"bytes_read"`
	UserID      string              `json:"user_id"`
	Duration    float64             `json:"duration"`
	Size        int                 `json:"size"`
	Status      int                 `json:"status"`
	RespHeaders map[string][]string `json:"resp_headers"`
	CacheState  string              `json:"cache_state,omitempty"`
	CacheRepo   string              `json:"cache_repo,omitempty"`
}

type requestEntry struct {
	RemoteIP   string              `json:"remote_ip"`
	RemotePort string              `json:"remote_port"`
	ClientIP   string              `json:"client_ip"`
	Proto      string              `json:"proto"`
	Method     string              `json:"method"`
	Host       string              `json:"host"`
	URI        string              `json:"uri"`
	Headers    map[string][]string `json:"headers"`
}

// accessLogWriter provides thread-safe Caddy-format JSON log writing.
type accessLogWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func newAccessLogWriter(w io.Writer) *accessLogWriter {
	if w == nil {
		w = io.Discard
	}
	return &accessLogWriter{w: w}
}

func (c *accessLogWriter) writeEntry(entry *accessLogEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')
	c.mu.Lock()
	defer c.mu.Unlock()
	c.w.Write(data) // best-effort; access log write errors are non-critical
}

// accessLogHandler wraps an http.Handler with Caddy-compatible JSON access
// logging and per-backend Prometheus metrics.
func accessLogHandler(backend string, next http.Handler, aw *accessLogWriter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}

		// Prepare mutable slots in the request context so downstream
		// handlers can inject the resolved GitHub username and user ID.
		r, slots := proxy.PrepareAccessLogSlots(r)

		next.ServeHTTP(rec, r)

		dur := time.Since(start)
		statusStr := strconv.Itoa(rec.status)

		remoteIP, remotePort := splitRemoteAddr(r.RemoteAddr)

		// Copy request headers, redacting sensitive values.
		headers := make(map[string][]string, len(r.Header))
		for k, v := range r.Header {
			switch strings.ToLower(k) {
			case "authorization", "proxy-authorization", "cookie",
				"x-auth-token", "x-api-key", "x-access-token":
				headers[k] = []string{"REDACTED"}
			default:
				headers[k] = v
			}
		}

		// Capture response headers, redacting sensitive values.
		respHeaders := make(map[string][]string, len(rec.Header()))
		for k, v := range rec.Header() {
			switch strings.ToLower(k) {
			case "set-cookie":
				respHeaders[k] = []string{"REDACTED"}
			default:
				respHeaders[k] = v
			}
		}

		level := "info"
		if rec.status >= 500 {
			level = "error"
		}

		// Prefer the GitHub username for the user_id field so that
		// operators see a recognisable login rather than an opaque
		// internal UUID. Fall back to the internal user ID slot when
		// the username slot is empty (e.g. unauthenticated requests).
		userID := *slots.Username
		if userID == "" {
			userID = *slots.UserID
		}

		entry := &accessLogEntry{
			Level:  level,
			TS:     float64(start.UnixNano()) / 1e9,
			Logger: "http.log.access",
			Msg:    "handled request",
			Request: requestEntry{
				RemoteIP:   remoteIP,
				RemotePort: remotePort,
				ClientIP:   remoteIP,
				Proto:      r.Proto,
				Method:     r.Method,
				Host:       r.Host,
				URI:        r.URL.RequestURI(),
				Headers:    headers,
			},
			BytesRead:   0,
			UserID:      userID,
			Duration:    dur.Seconds(),
			Size:        rec.size,
			Status:      rec.status,
			RespHeaders: respHeaders,
			CacheState:  *slots.CacheState,
			CacheRepo:   *slots.CacheRepo,
		}

		aw.writeEntry(entry)

		metrics.HttpRequestDuration.WithLabelValues(backend, r.Method, statusStr).Observe(dur.Seconds())
		metrics.HttpRequestTotal.WithLabelValues(backend, r.Method, statusStr).Inc()
	})
}

func splitRemoteAddr(addr string) (ip, port string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, ""
	}
	return host, port
}
