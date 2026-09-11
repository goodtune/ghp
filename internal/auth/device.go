package auth

// CLI device-authorization flow.
//
// The CLI authenticates against ghp itself, not GitHub. The flow mirrors RFC
// 8628 (OAuth 2.0 Device Authorization Grant) but the authorizing party is
// the ghp server, not GitHub:
//
//	  CLI                                 ghp server                       user (browser)
//	   |---- POST /cli/auth/device ------->|                                    |
//	   |<---- {device_code, user_code,     |                                    |
//	          verification_uri,            |                                    |
//	          verification_uri_complete} --|                                    |
//	   |                                   |                                    |
//	   |     (user opens verification_uri_complete in browser)                  |
//	   |                                   |<--- GET /cli/auth?user_code=X ---- |
//	   |                                   |                                    |
//	   |                                   |   (if not signed in to ghp,        |
//	   |                                   |    user goes through               |
//	   |                                   |    /auth/github first, then        |
//	   |                                   |    returns here)                   |
//	   |                                   |                                    |
//	   |                                   |<-- POST /cli/auth/decision ------- |
//	   |                                   |    (Approve or Deny)               |
//	   |                                   |---- HTML "approved" page --------->|
//	   |                                   |                                    |
//	   |- POST /cli/auth/device/token ---->|                                    |
//	   |  (polling every interval seconds) |                                    |
//	   |<--- {session_token, username} ----|                                    |
//
// State is held in the database (cli_device_authorizations table) rather
// than an in-process LRU so that the four round-trips above remain correct
// when load-balanced across multiple ghp instances. GitHub OAuth is still
// the identity provider for the ghp web UI, but it is no longer involved in
// the CLI bootstrap — the CLI never sees a github.com URL.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/metrics"
)

const (
	// deviceRequestTTL is how long a device-authorization request remains
	// valid. After this window the user_code becomes invalid and the CLI
	// poll receives "expired_token".
	deviceRequestTTL = 10 * time.Minute
	// devicePollMinInterval is the minimum permitted interval between
	// polls for a single device_code. Polling faster receives "slow_down".
	devicePollMinInterval = 2 * time.Second
	// deviceUserCodeAlphabet is the set of characters used in user_codes.
	// Restricted to a 31-character set that avoids visually-confusable
	// glyphs (no 0/O, 1/I/L) so users can read and re-type codes reliably
	// from a small printout.
	deviceUserCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	// deviceUserCodeBlockSize is the length of each block in the user code.
	deviceUserCodeBlockSize = 4
	// deviceUserCodeBlocks is the number of dash-separated blocks. Total
	// entropy is blocks * blockSize * log2(alphabet) ≈ 8 * log2(31) ≈ 39.6
	// bits, sufficient for the 10-minute window.
	deviceUserCodeBlocks = 2
)

// registerDeviceRoutes adds the CLI device-authorization endpoints to the mux.
// Called from RegisterRoutes. The two anonymous endpoints (/cli/auth/device
// for flow initiation and /cli/auth/device/token for polling) are wrapped in
// per-IP rate limiters so a hostile client cannot churn the database with
// device-auth rows or hammer the polling endpoint with non-existent codes.
func (h *Handler) registerDeviceRoutes(mux *http.ServeMux) {
	mux.Handle("POST /cli/auth/device", h.deviceStartLimiter.Middleware(http.HandlerFunc(h.handleDeviceStart)))
	mux.Handle("POST /cli/auth/device/token", h.devicePollLimiter.Middleware(http.HandlerFunc(h.handleDevicePoll)))
	mux.HandleFunc("GET /cli/auth", h.handleDeviceVerify)
	mux.HandleFunc("POST /cli/auth/decision", h.handleDeviceDecision)
}

// handleDeviceStart creates a new device-authorization request. The CLI hits
// this endpoint anonymously; no user identity is associated with the record
// until the verification page is approved.
//
// Response is RFC-8628-shaped JSON.
func (h *Handler) handleDeviceStart(w http.ResponseWriter, r *http.Request) {
	// user_code collisions are extremely unlikely (≈40 bits of entropy with
	// at most ~1k records active in a 10-minute window) but possible. We
	// regenerate both codes on each attempt: a duplicate user_code is the
	// expected retriable failure, but if some other transient DB issue
	// happens to be tied to a particular row (e.g. a primary-key collision
	// on device_code, however vanishingly improbable), keeping the same
	// device_code across attempts would just spin uselessly. Fresh codes
	// each iteration also remove any need to introspect driver-specific
	// constraint error messages.
	var deviceCode, userCode string
	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		dc, err := generateDeviceCode()
		if err != nil {
			h.logger.Error("failed to generate device_code", "error", err)
			writeDeviceError(w, "server_error", http.StatusInternalServerError)
			return
		}
		uc, err := generateUserCode()
		if err != nil {
			h.logger.Error("failed to generate user_code", "error", err)
			writeDeviceError(w, "server_error", http.StatusInternalServerError)
			return
		}
		if err := h.store.CreateDeviceAuth(r.Context(), &database.DeviceAuth{
			DeviceCode: dc,
			UserCode:   uc,
			Status:     database.DeviceAuthStatusPending,
			ExpiresAt:  time.Now().Add(deviceRequestTTL).UTC(),
		}); err != nil {
			if attempt == maxAttempts-1 {
				h.logger.Error("failed to persist device_auth", "error", err, "attempts", maxAttempts)
				writeDeviceError(w, "server_error", http.StatusInternalServerError)
				return
			}
			continue
		}
		deviceCode = dc
		userCode = uc
		break
	}

	verifyURI := h.absoluteURL(r, "/cli/auth")
	verifyComplete := verifyURI + "?user_code=" + url.QueryEscape(userCode)

	metrics.CLIDeviceStartedTotal.Inc()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          verifyURI,
		"verification_uri_complete": verifyComplete,
		"expires_in":                int(deviceRequestTTL.Seconds()),
		"interval":                  int(devicePollMinInterval.Seconds()),
	})
}

// handleDevicePoll returns the issued session token once the device request
// has been approved by an authenticated browser session. Until then it
// returns RFC-8628-style error codes.
func (h *Handler) handleDevicePoll(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var body struct {
		DeviceCode string `json:"device_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeDeviceError(w, "invalid_request", http.StatusRequestEntityTooLarge)
			return
		}
		writeDeviceError(w, "invalid_request", http.StatusBadRequest)
		return
	}
	if body.DeviceCode == "" {
		writeDeviceError(w, "invalid_request", http.StatusBadRequest)
		return
	}

	da, err := h.store.GetDeviceAuthByDeviceCode(r.Context(), body.DeviceCode)
	if err != nil {
		// Either the device_code was never issued, or the record has expired
		// and been pruned. RFC 8628 distinguishes these but we conflate
		// them — both outcomes mean the CLI must restart from the beginning.
		if errors.Is(err, database.ErrNotFound) {
			writeDeviceError(w, "expired_token", http.StatusBadRequest)
			return
		}
		h.logger.Error("device_auth lookup failed", "error", err)
		writeDeviceError(w, "server_error", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	if da.LastPolledAt != nil && now.Sub(*da.LastPolledAt) < devicePollMinInterval {
		// Bump LastPolledAt forward even on rejection so a misbehaving
		// client polling in a tight loop keeps pushing its own rate-limit
		// window out instead of repeatedly hitting only the in-memory
		// timestamp comparison. Without this the next poll from any
		// instance sees the same stale LastPolledAt and the offender pays
		// only the cost of the DB lookup, never advancing past slow_down.
		da.LastPolledAt = &now
		if err := h.store.UpdateDeviceAuth(r.Context(), da); err != nil {
			// Non-fatal: the rate-limit window just won't tighten further
			// for this client across this poll. The IP-level limiter still
			// applies as a backstop.
			h.logger.Warn("device_auth slow-down update failed", "error", err)
		}
		writeDeviceError(w, "slow_down", http.StatusBadRequest)
		return
	}

	switch da.Status {
	case database.DeviceAuthStatusPending:
		// Persist the new last_polled_at so subsequent pollers from any
		// instance see the same rate-limit window.
		da.LastPolledAt = &now
		if err := h.store.UpdateDeviceAuth(r.Context(), da); err != nil {
			h.logger.Warn("device_auth poll-time update failed", "error", err)
			// Continue — failing to record the poll time is non-fatal
			// (the rate limit just won't trip on this poll).
		}
		writeDeviceError(w, "authorization_pending", http.StatusBadRequest)
		return
	case database.DeviceAuthStatusDenied:
		// Remove the record so a denied code cannot be re-polled.
		if err := h.store.DeleteDeviceAuth(r.Context(), da.DeviceCode); err != nil {
			h.logger.Warn("device_auth delete failed", "error", err)
		}
		metrics.CLIDeviceCompletedTotal.WithLabelValues("denied").Inc()
		writeDeviceError(w, "access_denied", http.StatusBadRequest)
		return
	case database.DeviceAuthStatusApproved:
		// Hand the token to the CLI exactly once and discard the record.
		token := da.SessionToken
		username := da.Username
		if err := h.store.DeleteDeviceAuth(r.Context(), da.DeviceCode); err != nil {
			h.logger.Warn("device_auth delete failed", "error", err)
		}
		metrics.CLIDeviceCompletedTotal.WithLabelValues("approved").Inc()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"session_token": token,
			"username":      username,
		})
		return
	}

	writeDeviceError(w, "server_error", http.StatusInternalServerError)
}

// handleDeviceVerify renders the "approve this CLI sign-in" page. The user
// must be signed in to ghp; if not, they are redirected through the existing
// GitHub OAuth flow with a return_to back to this page.
func (h *Handler) handleDeviceVerify(w http.ResponseWriter, r *http.Request) {
	userCode := normaliseUserCode(r.URL.Query().Get("user_code"))

	session := h.GetSession(r)
	if session == nil {
		ret := "/cli/auth"
		if userCode != "" {
			ret += "?user_code=" + url.QueryEscape(userCode)
		}
		http.Redirect(w, r, "/auth/github?return_to="+url.QueryEscape(ret), http.StatusSeeOther)
		return
	}

	data := deviceVerifyData{
		Username: session.Username,
		UserCode: userCode,
	}

	if userCode == "" {
		data.NeedsCode = true
		renderDeviceVerify(w, h.logger, data)
		return
	}

	da, err := h.store.GetDeviceAuthByUserCode(r.Context(), userCode)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			data.Error = "That code is invalid or has expired. Run `ghp auth login` again to get a new one."
		} else {
			h.logger.Error("device_auth lookup failed", "error", err)
			data.Error = "Internal error looking up that code."
		}
		renderDeviceVerify(w, h.logger, data)
		return
	}

	switch da.Status {
	case database.DeviceAuthStatusApproved:
		data.AlreadyApproved = true
	case database.DeviceAuthStatusDenied:
		data.AlreadyDenied = true
	}
	renderDeviceVerify(w, h.logger, data)
}

// handleDeviceDecision processes the approve/deny form submission. Same-
// origin protection is provided by the SameSite=Lax session cookie (the
// cookie is not sent on cross-site POSTs), and the user_code itself is a
// short-lived secret known only to the CLI and the user.
func (h *Handler) handleDeviceDecision(w http.ResponseWriter, r *http.Request) {
	session := h.GetSession(r)
	if session == nil {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	// Bound the body size before ParseForm reads it. The form has two
	// short fields (user_code, action); 1 MB is the same ceiling we apply
	// elsewhere and is far more than the legitimate flow needs.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	userCode := normaliseUserCode(r.FormValue("user_code"))
	action := r.FormValue("action")

	if userCode == "" || (action != "approve" && action != "deny") {
		http.Error(w, "Missing or invalid form fields", http.StatusBadRequest)
		return
	}

	da, err := h.store.GetDeviceAuthByUserCode(r.Context(), userCode)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			h.logger.Error("device_auth lookup failed", "error", err)
		}
		renderDeviceVerify(w, h.logger, deviceVerifyData{
			Username: session.Username,
			UserCode: userCode,
			Error:    "That code is invalid or has expired. Run `ghp auth login` again to get a new one.",
		})
		return
	}

	if da.Status != database.DeviceAuthStatusPending {
		// Already decided. Render an idempotent response.
		data := deviceVerifyData{
			Username: session.Username,
			UserCode: userCode,
		}
		switch da.Status {
		case database.DeviceAuthStatusApproved:
			data.AlreadyApproved = true
		case database.DeviceAuthStatusDenied:
			data.AlreadyDenied = true
		}
		renderDeviceVerify(w, h.logger, data)
		return
	}

	if action == "deny" {
		da.Status = database.DeviceAuthStatusDenied
		if err := h.store.UpdateDeviceAuth(r.Context(), da); err != nil {
			h.logger.Error("device_auth deny update failed", "error", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		h.logger.Info("cli_auth_denied", "user", session.Username)
		renderDeviceVerify(w, h.logger, deviceVerifyData{
			Username:   session.Username,
			UserCode:   userCode,
			JustDenied: true,
		})
		return
	}

	// Approve: mint a fresh session for the CLI tied to this user. The CLI
	// session is independent of the browser session — revoking the browser
	// session via /auth/logout does not revoke CLI sessions.
	cliToken, err := h.createSession(r.Context(), session.UserID, session.Username, session.Role)
	if err != nil {
		h.logger.Error("CLI session creation failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	da.Status = database.DeviceAuthStatusApproved
	da.SessionToken = cliToken
	da.Username = session.Username
	if err := h.store.UpdateDeviceAuth(r.Context(), da); err != nil {
		// Best-effort: clean up the session we just created so it isn't
		// orphaned in the sessions table.
		h.deleteSession(r.Context(), cliToken)
		h.logger.Error("device_auth approve update failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("cli_auth_approved", "user", session.Username)

	renderDeviceVerify(w, h.logger, deviceVerifyData{
		Username:     session.Username,
		UserCode:     userCode,
		JustApproved: true,
	})
}

// writeDeviceError emits an RFC-8628-style {"error":"..."} JSON body.
func writeDeviceError(w http.ResponseWriter, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// generateDeviceCode returns a 32-byte hex-encoded random token. This is the
// long-lived secret the CLI polls with; it must be high-entropy.
func generateDeviceCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// generateUserCode returns a short, human-typeable code such as "ABCD-EFGH".
// Each character is uniformly drawn from deviceUserCodeAlphabet using
// crypto/rand.
func generateUserCode() (string, error) {
	alphabetLen := big.NewInt(int64(len(deviceUserCodeAlphabet)))
	blocks := make([]string, deviceUserCodeBlocks)
	for b := 0; b < deviceUserCodeBlocks; b++ {
		var sb strings.Builder
		sb.Grow(deviceUserCodeBlockSize)
		for i := 0; i < deviceUserCodeBlockSize; i++ {
			n, err := rand.Int(rand.Reader, alphabetLen)
			if err != nil {
				return "", err
			}
			sb.WriteByte(deviceUserCodeAlphabet[n.Int64()])
		}
		blocks[b] = sb.String()
	}
	return strings.Join(blocks, "-"), nil
}

// normaliseUserCode upper-cases and strips whitespace from a user-supplied
// code so we accept "abcd-efgh" and "ABCD EFGH" the same way.
func normaliseUserCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	if !strings.Contains(s, "-") && len(s) == deviceUserCodeBlocks*deviceUserCodeBlockSize {
		var b strings.Builder
		for i := 0; i < deviceUserCodeBlocks; i++ {
			if i > 0 {
				b.WriteByte('-')
			}
			b.WriteString(s[i*deviceUserCodeBlockSize : (i+1)*deviceUserCodeBlockSize])
		}
		s = b.String()
	}
	return s
}

// absoluteURL constructs an absolute URL for path on this server, preferring
// the configured server.base_url. When base_url is unset it falls back to a
// scheme/host derived from the incoming request, optionally honouring
// reverse-proxy headers when server.trust_proxy_headers is true.
func (h *Handler) absoluteURL(r *http.Request, path string) string {
	if h.cfg.Server.BaseURL != "" {
		return strings.TrimRight(h.cfg.Server.BaseURL, "/") + path
	}
	return fmt.Sprintf("%s://%s%s", requestScheme(r, h.cfg.Server.TrustProxyHeaders), requestHost(r, h.cfg.Server.TrustProxyHeaders), path)
}

// requestScheme reports the externally-visible scheme for r. When trustProxy
// is true it consults the standardised Forwarded header first, then
// X-Forwarded-Proto, before falling back to whether the connection itself is
// TLS — this matters when TLS terminates at a reverse proxy and ghp
// receives plain HTTP. When trustProxy is false the headers are ignored, so
// an internet-reachable instance cannot be tricked into emitting attacker-
// controlled scheme values via header spoofing.
func requestScheme(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if v := forwardedField(r.Header.Get("Forwarded"), "proto"); v != "" {
			return v
		}
		if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
			// Multiple proxies may chain values ("https, http"); take the
			// first, which represents the originating client edge.
			if i := strings.Index(v, ","); i >= 0 {
				v = v[:i]
			}
			return strings.TrimSpace(v)
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// requestHost reports the externally-visible host for r. Behaves the same as
// requestScheme: forwarded host headers are only honoured when trustProxy is
// true. Otherwise we use r.Host, which Go has already validated for HTTP
// host-header injection.
func requestHost(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if v := forwardedField(r.Header.Get("Forwarded"), "host"); v != "" {
			return v
		}
		if v := r.Header.Get("X-Forwarded-Host"); v != "" {
			if i := strings.Index(v, ","); i >= 0 {
				v = v[:i]
			}
			return strings.TrimSpace(v)
		}
	}
	return r.Host
}

// forwardedField extracts a single field (e.g. "proto" or "host") from an
// RFC 7239 Forwarded header value. Returns "" when the header is empty or
// the field is absent. Only the first forwarded element is consulted (the
// originating client's view of the request); chained proxies after that
// are ignored, matching the X-Forwarded-* convention above.
func forwardedField(header, name string) string {
	if header == "" {
		return ""
	}
	// Forwarded: by=...;for=...;host=...;proto=...
	first := header
	if i := strings.Index(first, ","); i >= 0 {
		first = first[:i]
	}
	for _, part := range strings.Split(first, ";") {
		part = strings.TrimSpace(part)
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		if !strings.EqualFold(part[:eq], name) {
			continue
		}
		v := strings.TrimSpace(part[eq+1:])
		// Values may be quoted per the spec.
		v = strings.Trim(v, `"`)
		return v
	}
	return ""
}

// deviceVerifyData drives the verification template. Exactly one of NeedsCode,
// Error, AlreadyApproved, AlreadyDenied, JustApproved, or JustDenied is set;
// otherwise the page renders the approve/deny form for UserCode.
type deviceVerifyData struct {
	Username        string
	UserCode        string
	NeedsCode       bool
	Error           string
	AlreadyApproved bool
	AlreadyDenied   bool
	JustApproved    bool
	JustDenied      bool
}

var deviceVerifyTmpl = template.Must(template.New("device_verify").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ghp — Authorize CLI sign-in</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 1rem; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 2rem; max-width: 480px; width: 100%; }
h1 { font-size: 1.4rem; margin-bottom: 0.75rem; color: #f0f6fc; }
p { color: #8b949e; margin-bottom: 1rem; font-size: 0.95rem; line-height: 1.5; }
.user-code { display: block; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 1.6rem; letter-spacing: 0.15em; text-align: center; padding: 0.9rem 1rem; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #f0f6fc; margin: 1rem 0 1.5rem; }
.actions { display: flex; gap: 0.75rem; margin-top: 1.5rem; }
.btn { flex: 1; display: inline-block; padding: 0.75rem 1rem; border-radius: 6px; border: 0; font-weight: 600; font-size: 0.95rem; cursor: pointer; text-align: center; text-decoration: none; }
.btn-approve { background: #238636; color: #fff; }
.btn-approve:hover { background: #2ea043; }
.btn-deny { background: #21262d; color: #f0f6fc; border: 1px solid #30363d; }
.btn-deny:hover { background: #30363d; }
.notice { padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1rem; }
.notice-error { background: #4c1d1d; color: #ffa198; border: 1px solid #6e2222; }
.notice-success { background: #1a3a1f; color: #7ee787; border: 1px solid #2ea04340; }
.notice-info { background: #1f2a44; color: #79c0ff; border: 1px solid #1f6feb40; }
input[type=text] { width: 100%; padding: 0.6rem 0.75rem; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #f0f6fc; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 1rem; letter-spacing: 0.1em; margin-bottom: 1rem; }
.muted { color: #6e7681; font-size: 0.8rem; }
form { margin: 0; }
</style>
</head>
<body>
<div class="card">
<h1>Authorize CLI sign-in</h1>
{{if .JustApproved}}
<div class="notice notice-success">Approved. You can return to your terminal — the CLI will pick up the new credentials within a few seconds. You can close this tab.</div>
{{else if .JustDenied}}
<div class="notice notice-info">Denied. The CLI session has not been authorized.</div>
{{else if .AlreadyApproved}}
<div class="notice notice-info">This code has already been approved.</div>
{{else if .AlreadyDenied}}
<div class="notice notice-info">This code was denied.</div>
{{else if .Error}}
<div class="notice notice-error">{{.Error}}</div>
{{else if .NeedsCode}}
<p>Enter the user code shown by your <code>ghp</code> CLI to authorize a new sign-in:</p>
<form method="POST" action="/cli/auth/decision">
<input type="text" name="user_code" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="ABCD-EFGH" required>
<input type="hidden" name="action" value="approve">
<div class="actions">
<button class="btn btn-approve" type="submit">Authorize</button>
</div>
</form>
{{else}}
<p>A <code>ghp</code> CLI is requesting permission to sign in as <strong>{{.Username}}</strong>.</p>
<p>Confirm the code below matches what your CLI displayed:</p>
<span class="user-code">{{.UserCode}}</span>
<p class="muted">If you did not start a sign-in just now, click Deny.</p>
<form method="POST" action="/cli/auth/decision">
<input type="hidden" name="user_code" value="{{.UserCode}}">
<div class="actions">
<button class="btn btn-deny" type="submit" name="action" value="deny">Deny</button>
<button class="btn btn-approve" type="submit" name="action" value="approve">Authorize</button>
</div>
</form>
{{end}}
</div>
</body>
</html>
`))

func renderDeviceVerify(w http.ResponseWriter, logger interface{ Error(msg string, args ...any) }, data deviceVerifyData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := deviceVerifyTmpl.Execute(w, data); err != nil {
		logger.Error("device verify template execution failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}
