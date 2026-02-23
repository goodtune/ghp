package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/backend"
)

func TestAccessLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})

	handler := accessLogHandler(backend.GitHub, inner, logger)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.Header.Set("User-Agent", "git/2.40")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	log := buf.String()
	for _, want := range []string{"http_request", "GET", "/org/repo", "200", "git/2.40", "github.com"} {
		if !strings.Contains(log, want) {
			t.Errorf("log missing %q: %s", want, log)
		}
	}
}

func TestCaddyAccessLog(t *testing.T) {
	var buf bytes.Buffer
	cw := newCaddyLogWriter(&buf)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})

	handler := caddyAccessLogHandler(backend.GitHub, inner, cw)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.Header.Set("User-Agent", "git/2.40")
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var entry caddyAccessLogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to unmarshal caddy log entry: %v\nraw: %s", err, buf.String())
	}

	// Verify top-level Caddy fields.
	if entry.Level != "info" {
		t.Errorf("level: got %q, want %q", entry.Level, "info")
	}
	if entry.TS == 0 {
		t.Error("ts should be non-zero")
	}
	if entry.Logger != "http.log.access" {
		t.Errorf("logger: got %q, want %q", entry.Logger, "http.log.access")
	}
	if entry.Msg != "handled request" {
		t.Errorf("msg: got %q, want %q", entry.Msg, "handled request")
	}
	if entry.Status != 200 {
		t.Errorf("status: got %d, want %d", entry.Status, 200)
	}
	if entry.Size != 5 {
		t.Errorf("size: got %d, want %d", entry.Size, 5)
	}
	if entry.Duration <= 0 {
		t.Error("duration should be positive")
	}

	// Verify nested request fields.
	if entry.Request.Method != "GET" {
		t.Errorf("request.method: got %q, want %q", entry.Request.Method, "GET")
	}
	if entry.Request.Host != "github.com" {
		t.Errorf("request.host: got %q, want %q", entry.Request.Host, "github.com")
	}
	if entry.Request.URI != "/org/repo" {
		t.Errorf("request.uri: got %q, want %q", entry.Request.URI, "/org/repo")
	}
	if entry.Request.RemoteIP != "192.168.1.1" {
		t.Errorf("request.remote_ip: got %q, want %q", entry.Request.RemoteIP, "192.168.1.1")
	}
	if entry.Request.RemotePort != "12345" {
		t.Errorf("request.remote_port: got %q, want %q", entry.Request.RemotePort, "12345")
	}
	if entry.Request.Proto != "HTTP/1.1" {
		t.Errorf("request.proto: got %q, want %q", entry.Request.Proto, "HTTP/1.1")
	}

	// Verify headers are present.
	ua := entry.Request.Headers["User-Agent"]
	if len(ua) == 0 || ua[0] != "git/2.40" {
		t.Errorf("request.headers.User-Agent: got %v, want [\"git/2.40\"]", ua)
	}
}

func TestCaddyAccessLog_SensitiveHeadersRedacted(t *testing.T) {
	var buf bytes.Buffer
	cw := newCaddyLogWriter(&buf)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := caddyAccessLogHandler(backend.GitHub, inner, cw)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "session=abc123")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var entry caddyAccessLogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if auth := entry.Request.Headers["Authorization"]; len(auth) == 0 || auth[0] != "REDACTED" {
		t.Errorf("Authorization header should be REDACTED, got %v", auth)
	}
	if cookie := entry.Request.Headers["Cookie"]; len(cookie) == 0 || cookie[0] != "REDACTED" {
		t.Errorf("Cookie header should be REDACTED, got %v", cookie)
	}
}

func TestCaddyAccessLog_ErrorLevel(t *testing.T) {
	var buf bytes.Buffer
	cw := newCaddyLogWriter(&buf)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	handler := caddyAccessLogHandler(backend.GitHub, inner, cw)

	req := httptest.NewRequest("GET", "http://github.com/error", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var entry caddyAccessLogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if entry.Level != "error" {
		t.Errorf("level: got %q, want %q for 500 status", entry.Level, "error")
	}
	if entry.Status != 500 {
		t.Errorf("status: got %d, want %d", entry.Status, 500)
	}
}
