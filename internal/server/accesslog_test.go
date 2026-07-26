package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	otellog "go.opentelemetry.io/otel/log"

	"github.com/goodtune/ghp/internal/backend"
	"github.com/goodtune/ghp/internal/proxy"
)

func TestAccessLog(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

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

	rec := exp.only(t)

	// Record-level fields.
	if rec.severity != otellog.SeverityInfo {
		t.Errorf("severity: got %v, want Info", rec.severity)
	}
	if rec.body != "handled request" {
		t.Errorf("body: got %q, want %q", rec.body, "handled request")
	}
	if rec.scope != "test" {
		t.Errorf("scope: got %q", rec.scope)
	}

	// HTTP semantic-convention attributes.
	if got := rec.int(t, attrHTTPResponseStatusCode); got != 200 {
		t.Errorf("%s: got %d, want 200", attrHTTPResponseStatusCode, got)
	}
	if got := rec.int(t, attrHTTPResponseBodySize); got != 5 {
		t.Errorf("%s: got %d, want 5", attrHTTPResponseBodySize, got)
	}
	if got := rec.float(t, attrHTTPServerRequestDuration); got <= 0 {
		t.Errorf("%s should be positive, got %v", attrHTTPServerRequestDuration, got)
	}
	if got := rec.str(t, attrHTTPRequestMethod); got != "GET" {
		t.Errorf("%s: got %q, want GET", attrHTTPRequestMethod, got)
	}
	if got := rec.str(t, attrServerAddress); got != "github.com" {
		t.Errorf("%s: got %q, want github.com", attrServerAddress, got)
	}
	if got := rec.str(t, attrURLPath); got != "/org/repo" {
		t.Errorf("%s: got %q, want /org/repo", attrURLPath, got)
	}
	if got := rec.str(t, attrClientAddress); got != "192.168.1.1" {
		t.Errorf("%s: got %q, want 192.168.1.1", attrClientAddress, got)
	}
	if got := rec.int(t, attrClientPort); got != 12345 {
		t.Errorf("%s: got %d, want 12345", attrClientPort, got)
	}
	if got := rec.str(t, attrNetworkProtocolVersion); got != "1.1" {
		t.Errorf("%s: got %q, want 1.1", attrNetworkProtocolVersion, got)
	}
	if got := rec.str(t, attrUserAgentOriginal); got != "git/2.40" {
		t.Errorf("%s: got %q, want git/2.40", attrUserAgentOriginal, got)
	}
	if got := rec.str(t, attrGHPBackend); got != backend.GitHub {
		t.Errorf("%s: got %q, want %q", attrGHPBackend, got, backend.GitHub)
	}

	// Request headers captured under http.request.header.*
	if ua := rec.slice(t, attrHTTPRequestHeaderPrefix+"user-agent"); len(ua) == 0 || ua[0] != "git/2.40" {
		t.Errorf("request user-agent header: got %v, want [git/2.40]", ua)
	}
}

func TestAccessLog_SensitiveHeadersRedacted(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.GitHub, inner, aw)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "session=abc123")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	rec := exp.only(t)

	if auth := rec.slice(t, attrHTTPRequestHeaderPrefix+"authorization"); len(auth) == 0 || auth[0] != "REDACTED" {
		t.Errorf("authorization header should be REDACTED, got %v", auth)
	}
	if cookie := rec.slice(t, attrHTTPRequestHeaderPrefix+"cookie"); len(cookie) == 0 || cookie[0] != "REDACTED" {
		t.Errorf("cookie header should be REDACTED, got %v", cookie)
	}
}

func TestAccessLog_ExtendedSensitiveRequestHeadersRedacted(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

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

	rec := exp.only(t)

	for _, h := range []string{"x-auth-token", "x-api-key", "x-access-token"} {
		if v := rec.slice(t, attrHTTPRequestHeaderPrefix+h); len(v) == 0 || v[0] != "REDACTED" {
			t.Errorf("%s header should be REDACTED, got %v", h, v)
		}
	}
	// Non-sensitive headers should pass through.
	if ua := rec.slice(t, attrHTTPRequestHeaderPrefix+"user-agent"); len(ua) == 0 || ua[0] != "git/2.40" {
		t.Errorf("user-agent should not be redacted, got %v", ua)
	}
}

func TestAccessLog_SetCookieResponseHeaderRedacted(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=secret; HttpOnly; Secure")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.GitHub, inner, aw)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	rec := exp.only(t)

	if v := rec.slice(t, attrHTTPResponseHeaderPrefix+"set-cookie"); len(v) == 0 || v[0] != "REDACTED" {
		t.Errorf("set-cookie response header should be REDACTED, got %v", v)
	}
	// Non-sensitive response headers should pass through.
	if ct := rec.slice(t, attrHTTPResponseHeaderPrefix+"content-type"); len(ct) == 0 || ct[0] != "text/plain" {
		t.Errorf("content-type should not be redacted, got %v", ct)
	}
}

func TestAccessLog_UserIDFromSlot(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.SetUserID(r, "user-uuid-123")
		proxy.SetUsername(r, "alice")
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.Mgmt, inner, aw)

	req := httptest.NewRequest("GET", "http://ghp.example.com/admin", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	rec := exp.only(t)

	// enduser.id should prefer the GitHub username over the internal UUID.
	if got := rec.str(t, attrEndUserID); got != "alice" {
		t.Errorf("%s: got %q, want alice", attrEndUserID, got)
	}
}

func TestAccessLog_UserIDFallsBackToUUIDWhenUsernameEmpty(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

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

	rec := exp.only(t)

	// enduser.id should fall back to the internal UUID when no username is set.
	if got := rec.str(t, attrEndUserID); got != "user-uuid-456" {
		t.Errorf("%s: got %q, want user-uuid-456", attrEndUserID, got)
	}
}

func TestAccessLog_UserIDFallsBackToUsername(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

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

	rec := exp.only(t)

	// enduser.id should fall back to the username when no user ID is set.
	if got := rec.str(t, attrEndUserID); got != "alice" {
		t.Errorf("%s: got %q, want alice", attrEndUserID, got)
	}
}

func TestAccessLog_RawAuthSlot(t *testing.T) {
	t.Run("emits ghp.raw.auth when the slot is set", func(t *testing.T) {
		logger, exp := newCaptureLogger(t)
		aw := newAccessLogWriter(logger)

		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxy.SetRawAuth(r, "query_token")
			w.WriteHeader(http.StatusOK)
		})

		handler := accessLogHandler(backend.API, inner, aw)

		req := httptest.NewRequest("GET", "http://ghp.example.com/o/r/main/f.txt", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		rec := exp.only(t)

		if got := rec.str(t, attrGHPRawAuth); got != "query_token" {
			t.Errorf("%s: got %q, want query_token", attrGHPRawAuth, got)
		}
	})

	t.Run("omits ghp.raw.auth when the slot is untouched", func(t *testing.T) {
		logger, exp := newCaptureLogger(t)
		aw := newAccessLogWriter(logger)

		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := accessLogHandler(backend.Mgmt, inner, aw)

		req := httptest.NewRequest("GET", "http://ghp.example.com/admin", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		rec := exp.only(t)

		if rec.has(attrGHPRawAuth) {
			t.Errorf("%s: present, want absent for non-raw backend", attrGHPRawAuth)
		}
	})
}

func TestAccessLog_ErrorLevel(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	handler := accessLogHandler(backend.GitHub, inner, aw)

	req := httptest.NewRequest("GET", "http://github.com/error", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	rec := exp.only(t)

	if rec.severity != otellog.SeverityError {
		t.Errorf("severity: got %v, want Error for 500 status", rec.severity)
	}
	if got := rec.int(t, attrHTTPResponseStatusCode); got != 500 {
		t.Errorf("%s: got %d, want 500", attrHTTPResponseStatusCode, got)
	}
}

func TestRedactedQuery(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no sensitive params", "ref=main&path=README.md", "ref=main&path=README.md"},
		{"github blob token", "token=AACGATXPAI3FK7WLHZDREQLKMR6GLAA", "token=REDACTED"},
		{"access_token", "access_token=abc123", "access_token=REDACTED"},
		{"client_secret", "client_secret=shhh", "client_secret=REDACTED"},
		{"mixed", "ref=main&token=abc&page=2", "ref=main&token=REDACTED&page=2"},
		{"case insensitive name", "TOKEN=abc", "TOKEN=REDACTED"},
		{"repeated param", "token=a&token=b", "token=REDACTED&token=REDACTED"},
		{"valueless param", "token", "token=REDACTED"},
		{"unparseable is redacted wholesale", "%zz&token=abc", "REDACTED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redactedQuery(tt.in); got != tt.want {
				t.Errorf("redactedQuery(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestAccessLogHandler_RedactsQueryToken(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	h := accessLogHandler(backend.Codeload, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), aw)

	req := httptest.NewRequest(http.MethodGet, "/o/r/main/README.md?token=SECRETVALUE123", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	rec := exp.only(t)

	got := rec.str(t, attrURLQuery)
	if strings.Contains(got, "SECRETVALUE123") {
		t.Errorf("%s = %q, must not contain the token value", attrURLQuery, got)
	}
	if got != "token=REDACTED" {
		t.Errorf("%s = %q, want %q", attrURLQuery, got, "token=REDACTED")
	}
}
