package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/ghp/internal/backend"
	"github.com/goodtune/ghp/internal/proxy"
)

func TestAccessLog(t *testing.T) {
	var buf bytes.Buffer
	aw := newAccessLogWriter(&buf)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})

	handler := accessLogHandler(backend.GitHub, inner, aw)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.Header.Set("User-Agent", "git/2.40")
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var entry accessLogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to unmarshal access log entry: %v\nraw: %s", err, buf.String())
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

func TestAccessLog_SensitiveHeadersRedacted(t *testing.T) {
	var buf bytes.Buffer
	aw := newAccessLogWriter(&buf)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.GitHub, inner, aw)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "session=abc123")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var entry accessLogEntry
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

func TestAccessLog_ExtendedSensitiveRequestHeadersRedacted(t *testing.T) {
	var buf bytes.Buffer
	aw := newAccessLogWriter(&buf)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.GitHub, inner, aw)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.Header.Set("X-Auth-Token", "secret-auth")
	req.Header.Set("X-Api-Key", "secret-api-key")
	req.Header.Set("X-Access-Token", "secret-access-token")
	req.Header.Set("User-Agent", "git/2.40")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var entry accessLogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	for _, h := range []string{"X-Auth-Token", "X-Api-Key", "X-Access-Token"} {
		if v := entry.Request.Headers[h]; len(v) == 0 || v[0] != "REDACTED" {
			t.Errorf("%s header should be REDACTED, got %v", h, v)
		}
	}
	// Non-sensitive headers should pass through.
	if ua := entry.Request.Headers["User-Agent"]; len(ua) == 0 || ua[0] != "git/2.40" {
		t.Errorf("User-Agent should not be redacted, got %v", ua)
	}
}

func TestAccessLog_SetCookieResponseHeaderRedacted(t *testing.T) {
	var buf bytes.Buffer
	aw := newAccessLogWriter(&buf)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=secret; HttpOnly; Secure")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.GitHub, inner, aw)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var entry accessLogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if v := entry.RespHeaders["Set-Cookie"]; len(v) == 0 || v[0] != "REDACTED" {
		t.Errorf("Set-Cookie response header should be REDACTED, got %v", v)
	}
	// Non-sensitive response headers should pass through.
	if ct := entry.RespHeaders["Content-Type"]; len(ct) == 0 || ct[0] != "text/plain" {
		t.Errorf("Content-Type should not be redacted, got %v", ct)
	}
}

func TestAccessLog_UserIDFromSlot(t *testing.T) {
	var buf bytes.Buffer
	aw := newAccessLogWriter(&buf)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.SetUserID(r, "user-uuid-123")
		proxy.SetUsername(r, "alice")
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.Mgmt, inner, aw)

	req := httptest.NewRequest("GET", "http://ghp.example.com/admin", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var entry accessLogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to unmarshal: %v\nraw: %s", err, buf.String())
	}

	// user_id should prefer the GitHub username over the internal UUID.
	if entry.UserID != "alice" {
		t.Errorf("user_id: got %q, want %q", entry.UserID, "alice")
	}
}

func TestAccessLog_UserIDFallsBackToUserID(t *testing.T) {
	var buf bytes.Buffer
	aw := newAccessLogWriter(&buf)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only set user ID (no username) — simulates requests where
		// only the internal UUID is known.
		proxy.SetUserID(r, "user-uuid-456")
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.Mgmt, inner, aw)

	req := httptest.NewRequest("GET", "http://ghp.example.com/admin", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var entry accessLogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to unmarshal: %v\nraw: %s", err, buf.String())
	}

	// user_id should fall back to the internal UUID when no username is set.
	if entry.UserID != "user-uuid-456" {
		t.Errorf("user_id: got %q, want %q", entry.UserID, "user-uuid-456")
	}
}

func TestAccessLog_UserIDFallsBackToUsername(t *testing.T) {
	var buf bytes.Buffer
	aw := newAccessLogWriter(&buf)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only set username (no user ID) — simulates proxy requests
		// where only the GitHub username is resolved.
		proxy.SetUsername(r, "alice")
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.API, inner, aw)

	req := httptest.NewRequest("GET", "http://api.github.com/repos/org/repo", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var entry accessLogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to unmarshal: %v\nraw: %s", err, buf.String())
	}

	// user_id should fall back to the username when no user ID is set.
	if entry.UserID != "alice" {
		t.Errorf("user_id: got %q, want %q", entry.UserID, "alice")
	}
}

func TestAccessLog_ErrorLevel(t *testing.T) {
	var buf bytes.Buffer
	aw := newAccessLogWriter(&buf)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	handler := accessLogHandler(backend.GitHub, inner, aw)

	req := httptest.NewRequest("GET", "http://github.com/error", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var entry accessLogEntry
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
