package tokens

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/redact"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

// SessionPrefix marks every token the rig creates.
const SessionPrefix = "scoperig-"

// retryAfter429 is how long Create waits before its single 429 retry.
const retryAfter429 = 60 * time.Second

// revokeTimeout bounds cleanup that runs after the caller's context ended.
const revokeTimeout = 60 * time.Second

// Pace returns the delay between creates for a server limit of ratePerMin
// requests per minute, using 75% of that limit.
func Pace(ratePerMin int) time.Duration {
	if ratePerMin <= 0 {
		ratePerMin = 20
	}
	return time.Duration(float64(time.Minute) / (float64(ratePerMin) * 0.75))
}

// Manager creates tokens through the GHP management API and guarantees
// they can be revoked. It is safe for concurrent use; creates are serialised.
type Manager struct {
	base    string
	session string
	runID   string
	client  *http.Client
	pace    time.Duration
	// sleep waits for d or until ctx ends. Tests replace it.
	sleep func(ctx context.Context, d time.Duration) error

	createMu    sync.Mutex // serialises creates and the pacer
	createdOnce bool

	mu      sync.Mutex
	created []string
	revoked map[string]bool
}

// NewManager returns a Manager for the management API at mgmtURL,
// authenticating with sessionToken (sent as a Bearer token).
func NewManager(mgmtURL, sessionToken, runID string, client *http.Client, pace time.Duration) *Manager {
	if client == nil {
		client = http.DefaultClient
	}
	return &Manager{
		base:    strings.TrimRight(mgmtURL, "/"),
		session: sessionToken,
		runID:   runID,
		client:  client,
		pace:    pace,
		sleep:   ctxSleep,
		revoked: map[string]bool{},
	}
}

func ctxSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// SessionID is the session_id attached to every token of this run.
func (m *Manager) SessionID() string { return SessionPrefix + m.runID }

// Created returns how many tokens this manager created.
func (m *Manager) Created() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.created)
}

// Create mints a token for profile p, expanding repository templates with v.
func (m *Manager) Create(ctx context.Context, p scenario.Profile, v *scenario.Vars) (Handle, error) {
	repos := make([]string, 0, len(p.Repositories))
	for _, r := range p.Repositories {
		e, err := scenario.Expand(r, v)
		if err != nil {
			return Handle{}, fmt.Errorf("profile %s: %w", p.Name, err)
		}
		repos = append(repos, e)
	}
	body := map[string]any{
		"type":         p.Type,
		"repositories": repos,
		"scopes":       p.Scopes,
		"session_id":   m.SessionID(),
	}
	if p.Duration != "" {
		body["duration"] = p.Duration
	}
	status, resp, err := m.create(ctx, body)
	if err != nil {
		return Handle{}, fmt.Errorf("profile %s: %w", p.Name, err)
	}
	if status != http.StatusCreated {
		return Handle{}, fmt.Errorf("profile %s: create token: status %d: %s", p.Name, status, message(resp))
	}
	id, _ := resp["id"].(string)
	val, _ := resp["token"].(string)
	if id == "" || val == "" {
		return Handle{}, fmt.Errorf("profile %s: create token: response missing id or token", p.Name)
	}
	return Handle{id: id, value: val}, nil
}

// CreateRaw posts body to /api/tokens as-is (for token_api scenarios),
// adding session_id when absent. It shares the pacer and 429 retry with
// Create, records any returned id for revocation, and strips "token" from
// the returned response.
func (m *Manager) CreateRaw(ctx context.Context, body map[string]any) (int, map[string]any, error) {
	cp := make(map[string]any, len(body)+1)
	for k, v := range body {
		cp[k] = v
	}
	if _, ok := cp["session_id"]; !ok {
		cp["session_id"] = m.SessionID()
	}
	status, resp, err := m.create(ctx, cp)
	delete(resp, "token")
	return status, resp, err
}

// create paces, posts, retries one 429, and records the created id.
func (m *Manager) create(ctx context.Context, body map[string]any) (int, map[string]any, error) {
	m.createMu.Lock()
	defer m.createMu.Unlock()
	if m.createdOnce && m.pace > 0 {
		if err := m.sleep(ctx, m.pace); err != nil {
			return 0, nil, err
		}
	}
	m.createdOnce = true
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, nil, fmt.Errorf("encode request: %w", err)
	}
	var status int
	var resp map[string]any
	for attempt := 0; attempt < 2; attempt++ {
		status, resp, err = m.do(ctx, http.MethodPost, "/api/tokens", payload)
		if err != nil {
			return 0, nil, err
		}
		if status != http.StatusTooManyRequests || attempt == 1 {
			break
		}
		if err := m.sleep(ctx, retryAfter429); err != nil {
			return 0, nil, err
		}
	}
	if status == http.StatusCreated {
		if id, _ := resp["id"].(string); id != "" {
			m.mu.Lock()
			m.created = append(m.created, id)
			m.mu.Unlock()
		}
	}
	return status, resp, nil
}

// Revoke revokes id. It is idempotent: an id already revoked by this manager
// is skipped, and a 400 for a token the server shows as revoked is success.
func (m *Manager) Revoke(ctx context.Context, id string) error {
	m.mu.Lock()
	done := m.revoked[id]
	m.mu.Unlock()
	if done {
		return nil
	}
	status, resp, err := m.do(ctx, http.MethodDelete, "/api/tokens/"+url.PathEscape(id), nil)
	if err != nil {
		return fmt.Errorf("revoke %s: %w", id, err)
	}
	switch {
	case status == http.StatusOK:
	case status == http.StatusBadRequest:
		revoked, gerr := m.isRevoked(ctx, id)
		if gerr != nil || !revoked {
			return fmt.Errorf("revoke %s: status %d: %s", id, status, message(resp))
		}
	default:
		return fmt.Errorf("revoke %s: status %d: %s", id, status, message(resp))
	}
	m.mu.Lock()
	m.revoked[id] = true
	m.mu.Unlock()
	return nil
}

func (m *Manager) isRevoked(ctx context.Context, id string) (bool, error) {
	status, resp, err := m.do(ctx, http.MethodGet, "/api/tokens/"+url.PathEscape(id), nil)
	if err != nil {
		return false, err
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("status %d", status)
	}
	return resp["revoked_at"] != nil, nil
}

// RevokeAll revokes every token this manager created and returns the ids it
// could not revoke. It is safe to call repeatedly and from defer. If ctx has
// already ended, cleanup continues on a fresh bounded context.
func (m *Manager) RevokeAll(ctx context.Context) []string {
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), revokeTimeout)
		defer cancel()
	}
	m.mu.Lock()
	ids := append([]string(nil), m.created...)
	m.mu.Unlock()
	var leftover []string
	for _, id := range ids {
		if err := m.Revoke(ctx, id); err != nil {
			leftover = append(leftover, id)
		}
	}
	return leftover
}

// RevokeOnSignal runs RevokeAll when one of sigs (default SIGINT, SIGTERM;
// pass the syscall values from the caller) arrives, then calls after with the
// leftover ids. The returned stop function removes the handler.
func (m *Manager) RevokeOnSignal(after func(leftover []string), sigs ...os.Signal) (stop func()) {
	if len(sigs) == 0 {
		sigs = []os.Signal{os.Interrupt}
	}
	ch := make(chan os.Signal, 1)
	quit := make(chan struct{})
	signal.Notify(ch, sigs...)
	go func() {
		select {
		case <-ch:
			left := m.RevokeAll(context.Background())
			if after != nil {
				after(left)
			}
		case <-quit:
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			signal.Stop(ch)
			close(quit)
		})
	}
}

type listedToken struct {
	ID        string  `json:"id"`
	SessionID string  `json:"session_id"`
	RevokedAt *string `json:"revoked_at"`
}

// list returns tokens visible to the session. If all is set it tries
// ?all=true first and falls back to the caller's own tokens on 403 or an
// empty list.
func (m *Manager) list(ctx context.Context, all bool) ([]listedToken, error) {
	if all {
		toks, status, err := m.listPath(ctx, "/api/tokens?all=true")
		if err != nil {
			return nil, err
		}
		if status == http.StatusOK && len(toks) > 0 {
			return toks, nil
		}
		if status != http.StatusOK && status != http.StatusForbidden {
			return nil, fmt.Errorf("list tokens: status %d", status)
		}
	}
	toks, status, err := m.listPath(ctx, "/api/tokens")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list tokens: status %d", status)
	}
	return toks, nil
}

func (m *Manager) listPath(ctx context.Context, path string) ([]listedToken, int, error) {
	raw, status, err := m.raw(ctx, http.MethodGet, path, nil)
	if err != nil || status != http.StatusOK {
		return nil, status, err
	}
	var toks []listedToken
	if err := json.Unmarshal(raw, &toks); err != nil {
		return nil, status, fmt.Errorf("decode token list: %w", err)
	}
	return toks, status, nil
}

// Sweep revokes leftover unrevoked tokens from earlier rig runs (any
// session_id starting with "scoperig-") and returns the ids it revoked.
func (m *Manager) Sweep(ctx context.Context) ([]string, error) {
	toks, err := m.list(ctx, true)
	if err != nil {
		return nil, err
	}
	var revoked []string
	var errs []error
	for _, t := range toks {
		if t.RevokedAt != nil || !strings.HasPrefix(t.SessionID, SessionPrefix) {
			continue
		}
		if err := m.Revoke(ctx, t.ID); err != nil {
			errs = append(errs, err)
			continue
		}
		revoked = append(revoked, t.ID)
	}
	return revoked, errors.Join(errs...)
}

// VerifyNoneLeft lists tokens and returns ids created by this manager that
// the server does not show as revoked.
func (m *Manager) VerifyNoneLeft(ctx context.Context) ([]string, error) {
	toks, err := m.list(ctx, true)
	if err != nil {
		return nil, err
	}
	state := make(map[string]bool, len(toks)) // id -> revoked
	for _, t := range toks {
		state[t.ID] = t.RevokedAt != nil
	}
	m.mu.Lock()
	ids := append([]string(nil), m.created...)
	m.mu.Unlock()
	var leftover []string
	for _, id := range ids {
		if revoked, seen := state[id]; seen && !revoked {
			leftover = append(leftover, id)
		}
	}
	sort.Strings(leftover)
	return leftover, nil
}

// do sends a request and decodes a JSON object response (nil if not an object).
func (m *Manager) do(ctx context.Context, method, path string, body []byte) (int, map[string]any, error) {
	raw, status, err := m.raw(ctx, method, path, body)
	if err != nil {
		return 0, nil, err
	}
	var resp map[string]any
	_ = json.Unmarshal(raw, &resp)
	return status, resp, nil
}

func (m *Manager) raw(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, m.base+path, rd)
	if err != nil {
		return nil, 0, fmt.Errorf("%s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+m.session)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.client.Do(req)
	if err != nil {
		// url.Error contains only method and URL; no credentials.
		return nil, 0, fmt.Errorf("%s %s: %s", method, path, redact.String(err.Error()))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("%s %s: read body: %w", method, path, err)
	}
	return raw, resp.StatusCode, nil
}

// message returns the redacted "message" field of an API error response.
func message(resp map[string]any) string {
	s, _ := resp["message"].(string)
	if s == "" {
		return "(no message)"
	}
	return redact.String(s)
}
