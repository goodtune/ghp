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
// Design notes:
//   - Device records are kept in-memory (expirable.LRU), since they are
//     short-lived and small in number; persisting them in the database would
//     require migrations across all three backends (Postgres, SQLite, Vault)
//     for no real benefit.
//   - GitHub OAuth is still the identity provider for the ghp web UI, but it
//     is no longer involved in the CLI bootstrap. The CLI never sees a
//     github.com URL.

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
	"sync"
	"time"

	"github.com/goodtune/ghp/internal/metrics"
)

const (
	// deviceRequestTTL is how long a device-authorization request remains
	// valid. After this window the user_code becomes invalid and the CLI
	// poll receives "expired_token".
	deviceRequestTTL = 10 * time.Minute
	// maxDeviceRequests caps the number of in-flight device requests held
	// in memory. The LRU evicts oldest entries past this size.
	maxDeviceRequests = 1_000
	// devicePollMinInterval is the minimum permitted interval between
	// polls for a single device_code. Polling faster receives "slow_down".
	devicePollMinInterval = 2 * time.Second
	// deviceUserCodeAlphabet is the set of characters used in user_codes.
	// Restricted to a 32-character set that avoids visually-confusable
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

// DeviceAuthStatus is the lifecycle state of a device-authorization request.
type DeviceAuthStatus string

const (
	deviceStatusPending  DeviceAuthStatus = "pending"
	deviceStatusApproved DeviceAuthStatus = "approved"
	deviceStatusDenied   DeviceAuthStatus = "denied"
)

// deviceAuthRequest is the in-memory record for a CLI device-authorization
// request. The device_code is the long-lived secret the CLI polls with;
// the user_code is the short, human-readable code displayed in both the
// CLI output and the browser approval page.
type deviceAuthRequest struct {
	mu sync.Mutex

	DeviceCode string
	UserCode   string

	Status DeviceAuthStatus

	// SessionToken and Username are populated when Status transitions to
	// approved. They are returned to the CLI on its next poll (after which
	// the device record is removed from the LRU to prevent token re-use).
	SessionToken string
	Username     string

	// LastPolledAt is updated by the polling endpoint to enforce the
	// minimum poll interval.
	LastPolledAt time.Time

	CreatedAt time.Time
}

// RegisterDeviceRoutes adds the CLI device-authorization endpoints to the mux.
// Called from RegisterRoutes.
func (h *Handler) registerDeviceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /cli/auth/device", h.handleDeviceStart)
	mux.HandleFunc("POST /cli/auth/device/token", h.handleDevicePoll)
	mux.HandleFunc("GET /cli/auth", h.handleDeviceVerify)
	mux.HandleFunc("POST /cli/auth/decision", h.handleDeviceDecision)
}

// handleDeviceStart creates a new device-authorization request. The CLI
// hits this endpoint anonymously; no user identity is associated with the
// record until the verification page is approved.
//
// Response is RFC-8628-shaped JSON:
//
//	{
//	  "device_code": "...",
//	  "user_code": "ABCD-EFGH",
//	  "verification_uri": "https://server/cli/auth",
//	  "verification_uri_complete": "https://server/cli/auth?user_code=ABCD-EFGH",
//	  "expires_in": 600,
//	  "interval": 5
//	}
func (h *Handler) handleDeviceStart(w http.ResponseWriter, r *http.Request) {
	deviceCode, err := generateDeviceCode()
	if err != nil {
		h.logger.Error("failed to generate device_code", "error", err)
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	userCode, err := generateUserCode()
	if err != nil {
		h.logger.Error("failed to generate user_code", "error", err)
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	req := &deviceAuthRequest{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		Status:     deviceStatusPending,
		CreatedAt:  time.Now(),
	}
	h.deviceRequests.Add(deviceCode, req)
	h.deviceUserCodes.Add(userCode, deviceCode)

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
//
// Request body: {"device_code": "..."}
//
// Responses:
//   - 200 {"session_token": "ghpr_...", "username": "..."}                approved
//   - 400 {"error": "authorization_pending"}                              still waiting
//   - 400 {"error": "slow_down"}                                          polled too fast
//   - 400 {"error": "expired_token"}                                      record TTL'd
//   - 400 {"error": "access_denied"}                                      user denied
//   - 400 {"error": "invalid_grant"}                                      device_code unknown
func (h *Handler) handleDevicePoll(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var body struct {
		DeviceCode string `json:"device_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusRequestEntityTooLarge)
			return
		}
		writeDeviceError(w, "invalid_request", http.StatusBadRequest)
		return
	}
	if body.DeviceCode == "" {
		writeDeviceError(w, "invalid_request", http.StatusBadRequest)
		return
	}

	req, ok := h.deviceRequests.Get(body.DeviceCode)
	if !ok {
		// Either the device_code was never issued, or it has expired and
		// been evicted. RFC 8628 distinguishes these but we do not — both
		// outcomes mean the CLI must restart from the beginning.
		writeDeviceError(w, "expired_token", http.StatusBadRequest)
		return
	}

	req.mu.Lock()
	defer req.mu.Unlock()

	now := time.Now()
	if !req.LastPolledAt.IsZero() && now.Sub(req.LastPolledAt) < devicePollMinInterval {
		writeDeviceError(w, "slow_down", http.StatusBadRequest)
		return
	}
	req.LastPolledAt = now

	switch req.Status {
	case deviceStatusPending:
		writeDeviceError(w, "authorization_pending", http.StatusBadRequest)
		return
	case deviceStatusDenied:
		// Remove the record so a denied code can't be re-polled.
		h.deviceRequests.Remove(req.DeviceCode)
		h.deviceUserCodes.Remove(req.UserCode)
		metrics.CLIDeviceCompletedTotal.WithLabelValues("denied").Inc()
		writeDeviceError(w, "access_denied", http.StatusBadRequest)
		return
	case deviceStatusApproved:
		// Hand the token to the CLI exactly once and discard the record.
		token := req.SessionToken
		username := req.Username
		h.deviceRequests.Remove(req.DeviceCode)
		h.deviceUserCodes.Remove(req.UserCode)
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
		// Send the user through GitHub login, then back to this page with
		// the user_code preserved.
		ret := "/cli/auth"
		if userCode != "" {
			ret += "?user_code=" + url.QueryEscape(userCode)
		}
		loginURL := "/auth/github?return_to=" + url.QueryEscape(ret)
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
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

	deviceCode, ok := h.deviceUserCodes.Get(userCode)
	if !ok {
		data.Error = "That code is invalid or has expired. Run `ghp auth login` again to get a new one."
		renderDeviceVerify(w, h.logger, data)
		return
	}
	req, ok := h.deviceRequests.Get(deviceCode)
	if !ok {
		data.Error = "That code is invalid or has expired. Run `ghp auth login` again to get a new one."
		renderDeviceVerify(w, h.logger, data)
		return
	}
	req.mu.Lock()
	status := req.Status
	req.mu.Unlock()

	switch status {
	case deviceStatusApproved:
		data.AlreadyApproved = true
	case deviceStatusDenied:
		data.AlreadyDenied = true
	}

	renderDeviceVerify(w, h.logger, data)
}

// handleDeviceDecision processes the approve/deny form submission. Same-Origin
// is enforced by the SameSite=Lax session cookie (the cookie is not sent on
// cross-site POSTs), and the user_code itself is a short-lived secret known
// only to the CLI and the user.
func (h *Handler) handleDeviceDecision(w http.ResponseWriter, r *http.Request) {
	session := h.GetSession(r)
	if session == nil {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	userCode := normaliseUserCode(r.FormValue("user_code"))
	action := r.FormValue("action")

	if userCode == "" || (action != "approve" && action != "deny") {
		http.Error(w, "Missing or invalid form fields", http.StatusBadRequest)
		return
	}

	deviceCode, ok := h.deviceUserCodes.Get(userCode)
	if !ok {
		renderDeviceVerify(w, h.logger, deviceVerifyData{
			Username: session.Username,
			UserCode: userCode,
			Error:    "That code is invalid or has expired. Run `ghp auth login` again to get a new one.",
		})
		return
	}
	req, ok := h.deviceRequests.Get(deviceCode)
	if !ok {
		renderDeviceVerify(w, h.logger, deviceVerifyData{
			Username: session.Username,
			UserCode: userCode,
			Error:    "That code is invalid or has expired. Run `ghp auth login` again to get a new one.",
		})
		return
	}

	req.mu.Lock()
	defer req.mu.Unlock()

	if req.Status != deviceStatusPending {
		// Already decided. Render an idempotent response.
		data := deviceVerifyData{
			Username: session.Username,
			UserCode: userCode,
		}
		switch req.Status {
		case deviceStatusApproved:
			data.AlreadyApproved = true
		case deviceStatusDenied:
			data.AlreadyDenied = true
		}
		renderDeviceVerify(w, h.logger, data)
		return
	}

	if action == "deny" {
		req.Status = deviceStatusDenied
		h.logger.Info("cli_auth_denied", "user", session.Username)
		renderDeviceVerify(w, h.logger, deviceVerifyData{
			Username:      session.Username,
			UserCode:      userCode,
			JustDenied:    true,
		})
		return
	}

	// Approve: mint a fresh session for the CLI tied to this user. The CLI
	// session is independent of the browser session — revoking the browser
	// session via /auth/logout does not revoke CLI sessions.
	cliToken := h.createSession(session.UserID, session.Username, session.Role)
	req.Status = deviceStatusApproved
	req.SessionToken = cliToken
	req.Username = session.Username

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
	// Ensure the code contains the dash separator. If the user typed it
	// without dashes ("ABCDEFGH"), reinsert them every blockSize chars.
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
// the configured server.base_url and falling back to the request's host.
func (h *Handler) absoluteURL(r *http.Request, path string) string {
	if h.cfg.Server.BaseURL != "" {
		return strings.TrimRight(h.cfg.Server.BaseURL, "/") + path
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s%s", scheme, r.Host, path)
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
