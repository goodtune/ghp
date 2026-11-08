package gitcred

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// maxResponseBytes caps every ghp API response body the client reads.
	maxResponseBytes = 1 << 20
	defaultTimeout   = 30 * time.Second
	// maxServerTextBytes caps the server's error message before "..." is
	// appended, so a hostile server cannot flood git's stderr.
	maxServerTextBytes = 200
)

// Sentinel errors matched by *APIError.Is for the statuses the helper
// reports specially.
var (
	ErrUnauthorized = errors.New("ghp session token was rejected")
	ErrForbidden    = errors.New("ghp server refused the request")
	ErrRateLimited  = errors.New("ghp server rate limit reached")
)

// Client calls the ghp management API with a ghpr_ session token.
type Client struct {
	BaseURL string       // trailing "/" trimmed before use
	Token   string       // ghpr_ session token, sent as "Authorization: Bearer <Token>"
	HTTP    *http.Client // nil → &http.Client{Timeout: 30 * time.Second}
}

// App is one entry of GET /api/apps.
type App struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	AppID     int64  `json:"app_id"`
	IsDefault bool   `json:"is_default"`
}

// Installation is one entry of GET /api/apps/{id}/installations.
type Installation struct {
	ID      int64 `json:"id"`
	Account struct {
		Login string `json:"login"`
	} `json:"account"`
	Permissions map[string]string `json:"permissions"`
}

// MintRequest is the body of POST /api/tokens.
type MintRequest struct {
	Type           string   `json:"type"`
	Repositories   []string `json:"repositories"`
	Scopes         string   `json:"scopes"`
	Duration       string   `json:"duration"`
	SessionID      string   `json:"session_id"`
	AppRecordID    string   `json:"app_record_id,omitempty"`
	InstallationID int64    `json:"installation_id,omitempty"`
}

// MintedToken is the 201 response of POST /api/tokens.
type MintedToken struct {
	Token        string            `json:"token"`
	ID           string            `json:"id"`
	Type         string            `json:"type"`
	Repositories []string          `json:"repositories"`
	Scopes       map[string]string `json:"scopes"`
	ExpiresAt    *time.Time        `json:"expires_at"`
}

// APIError is a ghp API response with an unexpected status. Message is the
// server's "message" field; it never holds a token.
type APIError struct {
	Op         string
	Status     int
	Message    string
	RetryAfter string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("%s: server returned %d: %s", e.Op, e.Status, msg)
}

// capServerText cuts s to at most 200 bytes on a rune boundary and appends
// "..." when it cut anything.
func capServerText(s string) string {
	if len(s) <= maxServerTextBytes {
		return s
	}
	cut := maxServerTextBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// Is maps 401, 403 and 429 to ErrUnauthorized, ErrForbidden and
// ErrRateLimited.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrUnauthorized:
		return e.Status == http.StatusUnauthorized
	case ErrForbidden:
		return e.Status == http.StatusForbidden
	case ErrRateLimited:
		return e.Status == http.StatusTooManyRequests
	}
	return false
}

// ListApps returns the GitHub Apps configured on the server (admin only).
func (c *Client) ListApps(ctx context.Context) ([]App, error) {
	var apps []App
	if err := c.do(ctx, "listing GitHub Apps", http.MethodGet, "/api/apps", nil, http.StatusOK, &apps); err != nil {
		return nil, err
	}
	return apps, nil
}

// ListInstallations returns the installations of one app (admin only).
func (c *Client) ListInstallations(ctx context.Context, appRecordID string) ([]Installation, error) {
	var insts []Installation
	path := "/api/apps/" + url.PathEscape(appRecordID) + "/installations"
	if err := c.do(ctx, "listing app installations", http.MethodGet, path, nil, http.StatusOK, &insts); err != nil {
		return nil, err
	}
	return insts, nil
}

// CreateToken mints a ghx_ or gha_ token.
func (c *Client) CreateToken(ctx context.Context, req MintRequest) (*MintedToken, error) {
	var tok MintedToken
	if err := c.do(ctx, "creating token", http.MethodPost, "/api/tokens", req, http.StatusCreated, &tok); err != nil {
		return nil, err
	}
	return &tok, nil
}

// RevokeToken revokes a token by its record ID.
func (c *Client) RevokeToken(ctx context.Context, id string) error {
	return c.do(ctx, "revoking token", http.MethodDelete, "/api/tokens/"+url.PathEscape(id), nil, http.StatusOK, nil)
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: defaultTimeout}
}

// do sends one request and decodes a want-status response into out (when
// non-nil). Any other status becomes an *APIError.
func (c *Client) do(ctx context.Context, op, method, path string, body any, want int, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("%s: encoding request: %w", op, err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, reqBody)
	if err != nil {
		return fmt.Errorf("%s: building request: %w", op, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("%s: connecting to ghp server: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("%s: reading response: %w", op, err)
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("%s: response larger than %d bytes", op, maxResponseBytes)
	}

	if resp.StatusCode != want {
		apiErr := &APIError{Op: op, Status: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After")}
		var msg struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &msg) == nil {
			apiErr.Message = capServerText(msg.Message)
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: decoding response: %w", op, err)
	}
	return nil
}
