// Package auth handles GitHub OAuth user-to-server authentication and session management.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
)

const (
	// SessionCookieName is the name of the browser session cookie.
	SessionCookieName = "ghp_session"
	// SessionDuration is how long a browser session lasts.
	SessionDuration = 30 * 24 * time.Hour
)

// Session represents an authenticated user session.
type Session struct {
	UserID    string
	Username  string
	Role      string
	ExpiresAt time.Time
}

// Handler manages OAuth flows and sessions.
type Handler struct {
	cfg       *config.Config
	store     database.Store
	encryptor *crypto.Encryptor
	logger    *slog.Logger

	mu       sync.RWMutex
	sessions map[string]*Session // session token -> Session

	// OAuth state tokens (short-lived, in-memory).
	stateMu sync.Mutex
	states  map[string]time.Time
}

// NewHandler creates a new auth handler.
func NewHandler(cfg *config.Config, store database.Store, enc *crypto.Encryptor, logger *slog.Logger) *Handler {
	return &Handler{
		cfg:       cfg,
		store:     store,
		encryptor: enc,
		logger:    logger,
		sessions:  make(map[string]*Session),
		states:    make(map[string]time.Time),
	}
}

// RegisterRoutes adds auth routes to the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/github", h.handleGitHubLogin)
	mux.HandleFunc("GET /auth/github/callback", h.handleGitHubCallback)
	mux.HandleFunc("POST /auth/logout", h.handleLogout)
	mux.HandleFunc("GET /auth/status", h.handleStatus)

	// Dev-mode only: test login endpoint that bypasses GitHub OAuth.
	if h.cfg.DevMode {
		h.logger.Warn("dev mode enabled: /auth/test-login endpoint is active")
		mux.HandleFunc("POST /auth/test-login", h.handleTestLogin)
	}
}

// GetSession returns the session for the given request, or nil.
func (h *Handler) GetSession(r *http.Request) *Session {
	// Check cookie first.
	if cookie, err := r.Cookie(SessionCookieName); err == nil {
		return h.lookupSession(cookie.Value)
	}

	// Check Authorization header for service tokens (CLI usage).
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ghpr_") {
		return h.lookupSession(strings.TrimPrefix(auth, "Bearer "))
	}

	return nil
}

// RequireAuth is middleware that enforces authentication.
func (h *Handler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := h.GetSession(r)
		if session == nil {
			http.Error(w, `{"message":"Authentication required"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey{}, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin is middleware that enforces admin role.
func (h *Handler) RequireAdmin(next http.Handler) http.Handler {
	return h.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := SessionFromContext(r.Context())
		if session == nil || session.Role != "admin" {
			http.Error(w, `{"message":"Admin access required"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

type sessionKey struct{}

// SessionFromContext retrieves the session from context.
func SessionFromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionKey{}).(*Session)
	return s
}

func (h *Handler) lookupSession(token string) *Session {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s, ok := h.sessions[token]
	if !ok {
		return nil
	}
	if time.Now().After(s.ExpiresAt) {
		return nil
	}
	return s
}

func (h *Handler) createSession(userID, username, role string) string {
	token := generateSessionToken()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessions[token] = &Session{
		UserID:    userID,
		Username:  username,
		Role:      role,
		ExpiresAt: time.Now().Add(SessionDuration),
	}
	return token
}

// CreateTestSession creates a session for E2E testing without OAuth.
// Returns the session token that should be set as the ghp_session cookie.
func (h *Handler) CreateTestSession(userID, username, role string) string {
	return h.createSession(userID, username, role)
}

func (h *Handler) deleteSession(token string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.sessions, token)
}

func (h *Handler) handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	h.stateMu.Lock()
	h.states[state] = time.Now().Add(10 * time.Minute)
	h.stateMu.Unlock()

	url := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&state=%s",
		h.cfg.GitHub.ClientID, state)

	// If the request accepts JSON (CLI), return the URL; otherwise redirect.
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"url": url})
		return
	}
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *Handler) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	// Handle GitHub App installation callback.
	// When a user installs the app, GitHub redirects here with installation_id
	// and setup_action params instead of the OAuth code/state.
	if r.URL.Query().Get("installation_id") != "" {
		h.logger.Info("github_app_installed", "installation_id", r.URL.Query().Get("installation_id"), "action", r.URL.Query().Get("setup_action"))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}

	// Validate state.
	h.stateMu.Lock()
	expiry, ok := h.states[state]
	if ok {
		delete(h.states, state)
	}
	h.stateMu.Unlock()

	if !ok || time.Now().After(expiry) {
		http.Error(w, "Invalid or expired state", http.StatusBadRequest)
		return
	}

	// Exchange code for access token.
	accessToken, refreshToken, expiresIn, err := h.exchangeCode(code)
	if err != nil {
		h.logger.Error("OAuth code exchange failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Get user info from GitHub.
	ghUser, err := h.getGitHubUser(accessToken)
	if err != nil {
		h.logger.Error("Failed to get GitHub user", "error", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Encrypt tokens before storage.
	encAccess, err := h.encryptor.Encrypt(accessToken)
	if err != nil {
		h.logger.Error("Failed to encrypt access token", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	encRefresh, err := h.encryptor.Encrypt(refreshToken)
	if err != nil {
		h.logger.Error("Failed to encrypt refresh token", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Determine role.
	role := "user"
	if h.cfg.IsAdmin(ghUser.Login) {
		role = "admin"
	}

	// Upsert user.
	user := &database.User{
		GitHubID:      ghUser.ID,
		GitHubUsername: ghUser.Login,
		GitHubEmail:   ghUser.Email,
		Role:          role,
	}
	if err := h.store.UpsertUser(r.Context(), user); err != nil {
		h.logger.Error("Failed to upsert user", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Store GitHub token.
	gt := &database.GitHubToken{
		UserID:                user.ID,
		AccessToken:           encAccess,
		RefreshToken:          encRefresh,
		AccessTokenExpiresAt:  time.Now().Add(time.Duration(expiresIn) * time.Second),
		RefreshTokenExpiresAt: time.Now().Add(6 * 30 * 24 * time.Hour), // ~6 months
		Scopes:                "",
	}
	if err := h.store.UpsertGitHubToken(r.Context(), gt); err != nil {
		h.logger.Error("Failed to store GitHub token", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("auth_login", "user", ghUser.Login, "github_id", ghUser.ID)

	// Create session.
	sessionToken := h.createSession(user.ID, user.GitHubUsername, user.Role)

	// If the request wants JSON (CLI client), return the token.
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"session_token": sessionToken,
			"username":      ghUser.Login,
		})
		return
	}

	// Set cookie for web UI.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionDuration.Seconds()),
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil {
		h.deleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out"})
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	session := h.GetSession(r)
	if session == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      session.Username,
		"role":          session.Role,
		"user_id":       session.UserID,
	})
}

// handleTestLogin creates a test user and session without GitHub OAuth.
// Only available when DevMode is enabled. This must never be used in production.
func (h *Handler) handleTestLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		req.Username = "testuser"
	}
	if req.Role == "" {
		req.Role = "user"
	}

	// Create or find the test user. Derive a unique GitHub ID from the username
	// so different test usernames create distinct users with separate tokens.
	var ghID int64
	for _, c := range req.Username {
		ghID = ghID*31 + int64(c)
	}
	if ghID < 0 {
		ghID = -ghID
	}
	ghID += 900000 // offset to avoid collisions with real GitHub IDs

	user := &database.User{
		GitHubID:       ghID,
		GitHubUsername:  req.Username,
		GitHubEmail:    req.Username + "@test.local",
		Role:           req.Role,
	}
	if err := h.store.UpsertUser(r.Context(), user); err != nil {
		h.logger.Error("failed to create test user", "error", err)
		http.Error(w, "Failed to create test user", http.StatusInternalServerError)
		return
	}

	// Create a dummy GitHub token so token creation works.
	encDummy, _ := h.encryptor.Encrypt("gho_test_dummy_token")
	gt := &database.GitHubToken{
		UserID:                user.ID,
		AccessToken:           encDummy,
		RefreshToken:          encDummy,
		AccessTokenExpiresAt:  time.Now().Add(8 * time.Hour),
		RefreshTokenExpiresAt: time.Now().Add(180 * 24 * time.Hour),
		Scopes:                "",
	}
	if err := h.store.UpsertGitHubToken(r.Context(), gt); err != nil {
		h.logger.Error("failed to create test github token", "error", err)
		http.Error(w, "Failed to create test GitHub token", http.StatusInternalServerError)
		return
	}

	// Create session.
	sessionToken := h.createSession(user.ID, user.GitHubUsername, user.Role)

	// Set cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionDuration.Seconds()),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_token": sessionToken,
		"username":      user.GitHubUsername,
		"user_id":       user.ID,
		"role":          user.Role,
	})
}

type githubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Email string `json:"email"`
}

func (h *Handler) exchangeCode(code string) (accessToken, refreshToken string, expiresIn int, err error) {
	body := fmt.Sprintf("client_id=%s&client_secret=%s&code=%s",
		h.cfg.GitHub.ClientID, h.cfg.GitHub.ClientSecret, code)

	req, err := http.NewRequest("POST", "https://github.com/login/oauth/access_token",
		strings.NewReader(body))
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", 0, err
	}
	if result.Error != "" {
		return "", "", 0, fmt.Errorf("OAuth error: %s", result.Error)
	}

	if result.ExpiresIn == 0 {
		result.ExpiresIn = 28800 // 8 hours default
	}

	return result.AccessToken, result.RefreshToken, result.ExpiresIn, nil
}

func (h *Handler) getGitHubUser(accessToken string) (*githubUser, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, body)
	}

	var user githubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return "ghpr_" + hex.EncodeToString(b)
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
