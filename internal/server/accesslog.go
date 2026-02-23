package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/ghp/internal/metrics"
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

// accessLogHandler wraps an http.Handler with standard HTTP access logging
// and per-backend Prometheus metrics.
func accessLogHandler(backend string, next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		dur := time.Since(start)
		statusStr := strconv.Itoa(rec.status)

		logger.Info("http_request",
			"method", r.Method,
			"host", r.Host,
			"path", r.URL.Path,
			"status", rec.status,
			"size", rec.size,
			"duration_ms", dur.Milliseconds(),
			"remote_addr", r.RemoteAddr,
			"user_agent", r.Header.Get("User-Agent"),
		)

		metrics.HttpRequestDuration.WithLabelValues(backend, r.Method, statusStr).Observe(dur.Seconds())
		metrics.HttpRequestTotal.WithLabelValues(backend, r.Method, statusStr).Inc()
	})
}

// Caddy-compatible JSON access log types.

type caddyAccessLogEntry struct {
	Level       string              `json:"level"`
	TS          float64             `json:"ts"`
	Logger      string              `json:"logger"`
	Msg         string              `json:"msg"`
	Request     caddyRequestEntry   `json:"request"`
	BytesRead   int                 `json:"bytes_read"`
	UserID      string              `json:"user_id"`
	Duration    float64             `json:"duration"`
	Size        int                 `json:"size"`
	Status      int                 `json:"status"`
	RespHeaders map[string][]string `json:"resp_headers"`
}

type caddyRequestEntry struct {
	RemoteIP   string              `json:"remote_ip"`
	RemotePort string              `json:"remote_port"`
	ClientIP   string              `json:"client_ip"`
	Proto      string              `json:"proto"`
	Method     string              `json:"method"`
	Host       string              `json:"host"`
	URI        string              `json:"uri"`
	Headers    map[string][]string `json:"headers"`
}

// caddyLogWriter provides thread-safe Caddy-format JSON log writing.
type caddyLogWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func newCaddyLogWriter(w io.Writer) *caddyLogWriter {
	return &caddyLogWriter{w: w}
}

func (c *caddyLogWriter) writeEntry(entry *caddyAccessLogEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')
	c.mu.Lock()
	c.w.Write(data)
	c.mu.Unlock()
}

// caddyAccessLogHandler wraps an http.Handler with Caddy-compatible JSON
// access logging and per-backend Prometheus metrics.
func caddyAccessLogHandler(backend string, next http.Handler, cw *caddyLogWriter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		dur := time.Since(start)
		statusStr := strconv.Itoa(rec.status)

		remoteIP, remotePort := splitRemoteAddr(r.RemoteAddr)

		// Copy request headers, redacting sensitive values.
		headers := make(map[string][]string, len(r.Header))
		for k, v := range r.Header {
			switch strings.ToLower(k) {
			case "authorization", "proxy-authorization", "cookie":
				headers[k] = []string{"REDACTED"}
			default:
				headers[k] = v
			}
		}

		// Capture response headers.
		respHeaders := make(map[string][]string, len(rec.Header()))
		for k, v := range rec.Header() {
			respHeaders[k] = v
		}

		level := "info"
		if rec.status >= 500 {
			level = "error"
		}

		entry := &caddyAccessLogEntry{
			Level:  level,
			TS:     float64(start.UnixNano()) / 1e9,
			Logger: "http.log.access",
			Msg:    "handled request",
			Request: caddyRequestEntry{
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
			UserID:      "",
			Duration:    dur.Seconds(),
			Size:        rec.size,
			Status:      rec.status,
			RespHeaders: respHeaders,
		}

		cw.writeEntry(entry)

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
