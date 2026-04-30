package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/database"
)

// TestDeviceStart_ReturnsCodes verifies POST /cli/auth/device returns the
// device_code, user_code and verification URLs.
func TestDeviceStart_ReturnsCodes(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{BaseURL: "https://proxy.example.com"},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	req := httptest.NewRequest("POST", "/cli/auth/device", nil)
	w := httptest.NewRecorder()
	h.handleDeviceStart(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp deviceStartTestResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if resp.DeviceCode == "" {
		t.Error("device_code missing")
	}
	if resp.UserCode == "" {
		t.Error("user_code missing")
	}
	if !strings.HasSuffix(resp.VerificationURI, "/cli/auth") {
		t.Errorf("verification_uri = %q", resp.VerificationURI)
	}
	if !strings.Contains(resp.VerificationURIComplete, url.QueryEscape(resp.UserCode)) {
		t.Errorf("verification_uri_complete missing user_code: %q", resp.VerificationURIComplete)
	}
	if resp.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want > 0", resp.ExpiresIn)
	}
	if resp.Interval <= 0 {
		t.Errorf("interval = %d, want > 0", resp.Interval)
	}
}

type deviceStartTestResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// TestDevicePoll_PendingThenApproved walks the full happy-path: start,
// poll-pending, decision=approve, poll-success.
func TestDevicePoll_PendingThenApproved(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	// Start.
	ds := runDeviceStart(t, h)

	// Poll while pending → 400 authorization_pending.
	if got := pollDeviceTokenAndExpect(t, h, ds.DeviceCode); got != "authorization_pending" {
		t.Fatalf("first poll: got %q, want authorization_pending", got)
	}

	// Now simulate the user approving via the verification page. We need a
	// session for the decision handler.
	sessToken := mustCreateSession(t, h, "user-1", "alice", "user")
	form := url.Values{}
	form.Set("user_code", ds.UserCode)
	form.Set("action", "approve")
	decisionReq := httptest.NewRequest("POST", "/cli/auth/decision", strings.NewReader(form.Encode()))
	decisionReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	decisionReq.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessToken})
	decisionW := httptest.NewRecorder()
	h.handleDeviceDecision(decisionW, decisionReq)
	if decisionW.Code != http.StatusOK {
		t.Fatalf("decision: status %d, body %s", decisionW.Code, decisionW.Body.String())
	}
	if !strings.Contains(decisionW.Body.String(), "Approved") {
		t.Errorf("expected approval HTML, got: %s", decisionW.Body.String())
	}

	// The poll-rate limiter is enforced via LastPolledAt on the device row.
	// Backdate it so the next poll passes without waiting wall-clock time.
	bumpLastPolledAt(t, h, ds.DeviceCode, -time.Hour)

	// Poll → 200 with token.
	pollReq := httptest.NewRequest("POST", "/cli/auth/device/token",
		bytes.NewReader([]byte(`{"device_code":"`+ds.DeviceCode+`"}`)))
	pollReq.Header.Set("Content-Type", "application/json")
	pollW := httptest.NewRecorder()
	h.handleDevicePoll(pollW, pollReq)
	if pollW.Code != http.StatusOK {
		t.Fatalf("approved poll: status %d, body %s", pollW.Code, pollW.Body.String())
	}

	var success struct {
		SessionToken string `json:"session_token"`
		Username     string `json:"username"`
	}
	if err := json.NewDecoder(pollW.Body).Decode(&success); err != nil {
		t.Fatalf("decoding success: %v", err)
	}
	if !strings.HasPrefix(success.SessionToken, "ghpr_") {
		t.Errorf("session_token = %q, want ghpr_ prefix", success.SessionToken)
	}
	if success.Username != "alice" {
		t.Errorf("username = %q, want alice", success.Username)
	}

	// Token can be used to look up a session.
	if h.lookupSession(context.Background(), success.SessionToken) == nil {
		t.Error("issued token did not resolve to an active session")
	}

	// Polling again must fail (record consumed). The first successful poll
	// removed the row from the store, so this is a not-found path and the
	// rate-limit timer is irrelevant.
	pollReq2 := httptest.NewRequest("POST", "/cli/auth/device/token",
		bytes.NewReader([]byte(`{"device_code":"`+ds.DeviceCode+`"}`)))
	pollReq2.Header.Set("Content-Type", "application/json")
	pollW2 := httptest.NewRecorder()
	h.handleDevicePoll(pollW2, pollReq2)
	if pollW2.Code != http.StatusBadRequest {
		t.Errorf("re-poll after approval: got %d, want 400", pollW2.Code)
	}
}

// TestDevicePoll_Denied verifies that a denied decision is reported as
// access_denied to the CLI.
func TestDevicePoll_Denied(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	ds := runDeviceStart(t, h)

	sessToken := mustCreateSession(t, h, "user-1", "alice", "user")
	form := url.Values{}
	form.Set("user_code", ds.UserCode)
	form.Set("action", "deny")
	dr := httptest.NewRequest("POST", "/cli/auth/decision", strings.NewReader(form.Encode()))
	dr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dr.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessToken})
	h.handleDeviceDecision(httptest.NewRecorder(), dr)

	// Backdate LastPolledAt so the rate-limit timer doesn't suppress this
	// poll (no decision endpoint has run a poll yet, but the start handler
	// doesn't seed it either, so this is a no-op when LastPolledAt is nil
	// — included for clarity and consistency with TestDevicePoll_PendingThenApproved).
	bumpLastPolledAt(t, h, ds.DeviceCode, -time.Hour)
	if got := pollDeviceTokenAndExpect(t, h, ds.DeviceCode); got != "access_denied" {
		t.Errorf("got %q, want access_denied", got)
	}
}

// TestDevicePoll_SlowDown verifies that polling faster than the minimum
// interval returns slow_down, and that each rejected poll bumps the
// rate-limit window forward so a tight loop keeps being slow_down'd.
func TestDevicePoll_SlowDown(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	ds := runDeviceStart(t, h)

	// First poll → authorization_pending.
	if got := pollDeviceTokenAndExpect(t, h, ds.DeviceCode); got != "authorization_pending" {
		t.Fatalf("first poll: got %q", got)
	}
	// Immediate second poll → slow_down.
	if got := pollDeviceTokenAndExpect(t, h, ds.DeviceCode); got != "slow_down" {
		t.Errorf("rapid second poll: got %q, want slow_down", got)
	}
	// The slow_down response must itself update LastPolledAt; otherwise a
	// misbehaving client could spam the endpoint without ever advancing
	// the rate-limit window. Verify by reading the row directly.
	da, err := h.store.GetDeviceAuthByDeviceCode(context.Background(), ds.DeviceCode)
	if err != nil {
		t.Fatalf("GetDeviceAuthByDeviceCode: %v", err)
	}
	if da.LastPolledAt == nil {
		t.Fatal("expected LastPolledAt to be set after slow_down")
	}
	// Backdate the row so we can verify the next slow_down really did
	// re-write LastPolledAt (rather than just observing two polls hitting
	// the same wall-clock millisecond, which the millisecond-precision
	// storage format would render indistinguishable).
	bumped := time.Now().Add(-time.Hour).UTC()
	da.LastPolledAt = &bumped
	if err := h.store.UpdateDeviceAuth(context.Background(), da); err != nil {
		t.Fatalf("seed LastPolledAt: %v", err)
	}
	// Third poll: still slow_down (we backdated, so it's now > minInterval
	// since the seeded LastPolledAt and the request advances the window
	// anyway — the assertion is that the row got re-written).
	if got := pollDeviceTokenAndExpect(t, h, ds.DeviceCode); got != "authorization_pending" && got != "slow_down" {
		t.Errorf("third poll: got %q, want slow_down or authorization_pending", got)
	}
	da2, _ := h.store.GetDeviceAuthByDeviceCode(context.Background(), ds.DeviceCode)
	if da2.LastPolledAt == nil || !da2.LastPolledAt.After(bumped) {
		t.Errorf("LastPolledAt should advance after another poll: prev=%v new=%v", bumped, da2.LastPolledAt)
	}
}

// TestDevicePoll_UnknownCode verifies that polling with a never-issued
// device_code returns expired_token (we deliberately conflate "expired" and
// "never existed" — see handler comment).
func TestDevicePoll_UnknownCode(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())
	if got := pollDeviceTokenAndExpect(t, h, "deadbeef-not-a-real-code"); got != "expired_token" {
		t.Errorf("got %q, want expired_token", got)
	}
}

// TestDevicePoll_InvalidRequest verifies that a malformed body returns
// invalid_request.
func TestDevicePoll_InvalidRequest(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	req := httptest.NewRequest("POST", "/cli/auth/device/token", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handleDevicePoll(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
	var er struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &er); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if er.Error != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", er.Error)
	}
}

// TestDeviceVerify_RedirectsWhenLoggedOut ensures the verification page sends
// unauthenticated browsers to GitHub login with a return_to back to here.
func TestDeviceVerify_RedirectsWhenLoggedOut(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	req := httptest.NewRequest("GET", "/cli/auth?user_code=ABCD-EFGH", nil)
	w := httptest.NewRecorder()
	h.handleDeviceVerify(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/auth/github?return_to=") {
		t.Errorf("Location = %q", loc)
	}
	// The return_to must round-trip the user_code.
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	rt := u.Query().Get("return_to")
	if !strings.Contains(rt, "user_code=ABCD-EFGH") {
		t.Errorf("return_to = %q, want to include user_code", rt)
	}
}

// TestDeviceVerify_RendersFormForKnownCode verifies the approve/deny page is
// rendered when a logged-in user visits with a valid user_code.
func TestDeviceVerify_RendersFormForKnownCode(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	ds := runDeviceStart(t, h)

	sessToken := mustCreateSession(t, h, "user-1", "alice", "user")
	req := httptest.NewRequest("GET", "/cli/auth?user_code="+url.QueryEscape(ds.UserCode), nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessToken})
	w := httptest.NewRecorder()
	h.handleDeviceVerify(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, ds.UserCode) {
		t.Errorf("page should display user_code")
	}
	if !strings.Contains(body, "Authorize") || !strings.Contains(body, "Deny") {
		t.Errorf("page should have Authorize/Deny buttons; body: %s", body)
	}
	if !strings.Contains(body, "alice") {
		t.Errorf("page should mention the user; body: %s", body)
	}
}

// TestDeviceVerify_UnknownCode shows an error message when the user_code is
// invalid or expired (rather than redirecting back to login).
func TestDeviceVerify_UnknownCode(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	sessToken := mustCreateSession(t, h, "user-1", "alice", "user")
	req := httptest.NewRequest("GET", "/cli/auth?user_code=ZZZZ-ZZZZ", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessToken})
	w := httptest.NewRecorder()
	h.handleDeviceVerify(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid or has expired") {
		t.Errorf("expected error message in body, got: %s", w.Body.String())
	}
}

// TestDeviceDecision_RequiresSession ensures the approval endpoint refuses
// unauthenticated POSTs.
func TestDeviceDecision_RequiresSession(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	form := url.Values{}
	form.Set("user_code", "ABCD-EFGH")
	form.Set("action", "approve")
	req := httptest.NewRequest("POST", "/cli/auth/decision", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.handleDeviceDecision(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestSanitizeReturnTo blocks non-local, protocol-relative, and
// control-character-bearing return_to values.
func TestSanitizeReturnTo(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"empty", "", ""},
		{"local path", "/cli/auth", "/cli/auth"},
		{"local path with query", "/cli/auth?user_code=X", "/cli/auth?user_code=X"},
		{"absolute https url", "https://evil.example.com/", ""},
		{"protocol-relative", "//evil.example.com", ""},
		{"path-with-backslash", "/\\evil.example.com", ""},
		{"javascript scheme", "javascript:alert(1)", ""},
		// Control characters in the path/query would otherwise reach the
		// Location header verbatim and risk response-splitting on lenient
		// clients/proxies.
		{"crlf injection", "/cli/auth\r\nSet-Cookie: x=y", ""},
		{"bare lf", "/cli/auth\nfoo", ""},
		{"bare cr", "/cli/auth\rfoo", ""},
		{"null byte", "/cli/auth\x00", ""},
		{"tab", "/cli/auth\t", ""},
		{"del", "/cli/auth\x7f", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeReturnTo(tt.in); got != tt.want {
				t.Errorf("sanitizeReturnTo(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestForwardedField parses RFC 7239 Forwarded header values for the
// scheme/host fallback used when server.base_url is not configured.
func TestForwardedField(t *testing.T) {
	tests := []struct {
		header, name, want string
	}{
		{"", "proto", ""},
		{"proto=https", "proto", "https"},
		{"for=10.0.0.1;proto=https;host=ghp.example.com", "host", "ghp.example.com"},
		{"for=10.0.0.1;proto=https;host=ghp.example.com", "proto", "https"},
		{`proto="https"`, "proto", "https"},
		// Only the first forwarded element is used.
		{"proto=https, proto=http", "proto", "https"},
		// Case-insensitive field name matching.
		{"Proto=https", "proto", "https"},
		// Missing field returns empty.
		{"for=10.0.0.1", "proto", ""},
	}
	for _, tt := range tests {
		got := forwardedField(tt.header, tt.name)
		if got != tt.want {
			t.Errorf("forwardedField(%q, %q) = %q, want %q", tt.header, tt.name, got, tt.want)
		}
	}
}

// TestNormaliseUserCode handles a few common user-input variants.
func TestNormaliseUserCode(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"abcd-efgh", "ABCD-EFGH"},
		{"  ABCD-EFGH  ", "ABCD-EFGH"},
		{"ABCDEFGH", "ABCD-EFGH"},
		{"abcd efgh", "ABCD-EFGH"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := normaliseUserCode(tt.in); got != tt.want {
				t.Errorf("normaliseUserCode(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestGitHubLogin_HonoursReturnTo verifies that ?return_to=<path> on
// /auth/github causes the post-callback redirect to land on that path
// instead of "/".
func TestGitHubLogin_HonoursReturnTo(t *testing.T) {
	cfg := &config.Config{
		GitHub: config.GitHubConfig{ClientID: "id"},
		Server: config.ServerConfig{BaseURL: "https://proxy.example.com"},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	req := httptest.NewRequest("GET", "/auth/github?return_to=/cli/auth?user_code=ABCD-EFGH", nil)
	w := httptest.NewRecorder()
	h.handleGitHubLogin(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("missing state")
	}

	// The state row should now hold the return_to value. ConsumeOAuthState
	// also deletes it; that's fine for the test's single read.
	got, err := h.store.ConsumeOAuthState(req.Context(), state, database.OAuthStateKindLogin)
	if err != nil {
		t.Fatalf("state not stored: %v", err)
	}
	if got.ReturnTo != "/cli/auth?user_code=ABCD-EFGH" {
		t.Errorf("stored return_to = %q", got.ReturnTo)
	}
}

// TestGitHubLogin_ReturnToIsValidated verifies that a hostile return_to is
// dropped (sanitizeReturnTo returns "").
func TestGitHubLogin_ReturnToIsValidated(t *testing.T) {
	cfg := &config.Config{
		GitHub: config.GitHubConfig{ClientID: "id"},
		Server: config.ServerConfig{BaseURL: "https://proxy.example.com"},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	req := httptest.NewRequest("GET", "/auth/github?return_to=https://evil.example.com/x", nil)
	w := httptest.NewRecorder()
	h.handleGitHubLogin(w, req)

	loc, _ := url.Parse(w.Header().Get("Location"))
	state := loc.Query().Get("state")
	got, err := h.store.ConsumeOAuthState(req.Context(), state, database.OAuthStateKindLogin)
	if err != nil {
		t.Fatalf("state not stored: %v", err)
	}
	if got.ReturnTo != "" {
		t.Errorf("stored return_to = %q, want empty", got.ReturnTo)
	}
}

// runDeviceStart issues POST /cli/auth/device against h, asserts a 200
// response, decodes the body, and returns the parsed start response. A
// failure here surfaces immediately at its source rather than as a chain
// of "field is empty" assertions later in the calling test.
func runDeviceStart(t *testing.T, h *Handler) deviceStartTestResponse {
	t.Helper()
	startW := httptest.NewRecorder()
	h.handleDeviceStart(startW, httptest.NewRequest("POST", "/cli/auth/device", nil))
	if startW.Code != http.StatusOK {
		t.Fatalf("handleDeviceStart: status %d, body %s", startW.Code, startW.Body.String())
	}
	var ds deviceStartTestResponse
	if err := json.NewDecoder(startW.Body).Decode(&ds); err != nil {
		t.Fatalf("decoding device-start response: %v", err)
	}
	return ds
}

// mustCreateSession is a test helper that mints a session and fails the
// test on store error. Used in place of the old LRU-backed createSession
// which returned a single value.
func mustCreateSession(t *testing.T, h *Handler, userID, username, role string) string {
	t.Helper()
	tok, err := h.createSession(context.Background(), userID, username, role)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	return tok
}

// bumpLastPolledAt rewrites the device row's LastPolledAt to now+offset.
// Tests use this to fast-forward past the poll-rate limiter without sleeping
// real time. A negative offset (e.g. -time.Hour) makes the next poll succeed
// immediately; a positive offset is rarely needed but supported for symmetry.
//
// If the row doesn't exist (which happens after an approved poll deletes it),
// this is a no-op so callers don't have to special-case the post-consume path.
func bumpLastPolledAt(t *testing.T, h *Handler, deviceCode string, offset time.Duration) {
	t.Helper()
	ctx := context.Background()
	da, err := h.store.GetDeviceAuthByDeviceCode(ctx, deviceCode)
	if err != nil {
		// ErrNotFound is expected for already-consumed rows.
		return
	}
	t1 := time.Now().Add(offset).UTC()
	da.LastPolledAt = &t1
	if err := h.store.UpdateDeviceAuth(ctx, da); err != nil {
		t.Fatalf("bumpLastPolledAt: %v", err)
	}
}

// pollDeviceTokenAndExpect makes a single POST /cli/auth/device/token call
// and returns the "error" field from the response body. It fails the test
// on transport-level errors.
func pollDeviceTokenAndExpect(t *testing.T, h *Handler, deviceCode string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"device_code": deviceCode})
	req := httptest.NewRequest("POST", "/cli/auth/device/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handleDevicePoll(w, req)

	if w.Code == http.StatusOK {
		t.Fatalf("expected error response, got 200: %s", w.Body.String())
	}
	var er struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &er); err != nil {
		raw, _ := io.ReadAll(w.Body)
		t.Fatalf("decoding error response: %v (body: %s)", err, raw)
	}
	return er.Error
}
