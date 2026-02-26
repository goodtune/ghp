// Package auth handles GitHub OAuth user-to-server authentication and session management.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
)

const (
	// SessionCookieName is the name of the browser session cookie.
	SessionCookieName = "ghp_session"
	// SessionDuration is how long a browser session lasts.
	SessionDuration = 30 * 24 * time.Hour

	// maxRequestBodySize is the maximum allowed request body size for API endpoints.
	maxRequestBodySize = 1 << 20 // 1 MB
	// maxTokenResponseSize is the maximum number of bytes read from GitHub's
	// OAuth token and user-info endpoints. This guards against unbounded reads.
	maxTokenResponseSize = 64 * 1024 // 64 KB
	// maxSessions is the maximum number of concurrent user sessions held in memory.
	maxSessions = 10_000
	// maxStates is the maximum number of in-flight OAuth state tokens.
	maxStates = 1_000
	// stateTTL is how long an OAuth state token remains valid.
	stateTTL = 10 * time.Minute
	// maxBrokerStates is the maximum number of in-flight broker OAuth states.
	maxBrokerStates = 1_000
	// brokerStateTTL is how long a broker OAuth state token remains valid.
	brokerStateTTL = 10 * time.Minute
	// authHTTPTimeout is the timeout for outbound HTTP requests made by the
	// auth handler (OAuth token exchange and GitHub user-info calls).
	authHTTPTimeout = 30 * time.Second
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

	// rsaPrivKey is the RSA private key used to sign broker JWTs with RS256.
	// When nil, broker endpoints are disabled entirely.
	// Note: this key is set once at NewHandler time; config hot-reload (SIGUSR1)
	// does not update it — a server restart is required to change the signing key.
	rsaPrivKey *rsa.PrivateKey

	// sessions maps session tokens to active user sessions.
	// Bounded and TTL-expired via expirable.LRU (thread-safe).
	sessions *expirable.LRU[string, *Session]

	// states holds in-flight OAuth state tokens (short-lived).
	states *expirable.LRU[string, struct{}]

	// brokerStates holds in-flight broker OAuth flow states (short-lived).
	brokerStates *expirable.LRU[string, *brokerState]

	// Rate limiters for sensitive endpoints (keyed by IP address).
	loginLimiter     *IPRateLimiter // POST /auth/test-login
	githubLimiter    *IPRateLimiter // GET  /auth/github
	authorizeLimiter *IPRateLimiter // GET  /auth/authorize

	// httpClient is used for all outbound OAuth and GitHub API requests.
	// It has a finite timeout to prevent goroutine/connection leaks.
	httpClient *http.Client

	// Overridable base URLs for GitHub endpoints (used in tests).
	githubBaseURL    string // defaults to "https://github.com"
	githubAPIBaseURL string // defaults to "https://api.github.com"
}

// NewHandler creates a new auth handler.
func NewHandler(cfg *config.Config, store database.Store, enc *crypto.Encryptor, logger *slog.Logger) *Handler {
	h := &Handler{
		cfg:              cfg,
		store:            store,
		encryptor:        enc,
		logger:           logger,
		sessions:         expirable.NewLRU[string, *Session](maxSessions, nil, SessionDuration),
		states:           expirable.NewLRU[string, struct{}](maxStates, nil, stateTTL),
		brokerStates:     expirable.NewLRU[string, *brokerState](maxBrokerStates, nil, brokerStateTTL),
		loginLimiter:     NewIPRateLimiter(30, time.Minute, "/auth/test-login", logger),
		githubLimiter:    NewIPRateLimiter(10, time.Minute, "/auth/github", logger),
		authorizeLimiter: NewIPRateLimiter(10, time.Minute, "/auth/authorize", logger),
		httpClient:       &http.Client{Timeout: authHTTPTimeout},
	}
	if cfg.Auth.JWTPrivateKey != "" || cfg.Auth.JWTPrivateKeyFile != "" {
		var pemData string
		if cfg.Auth.JWTPrivateKey != "" {
			pemData = cfg.Auth.JWTPrivateKey
		} else {
			data, err := os.ReadFile(cfg.Auth.JWTPrivateKeyFile)
			if err != nil {
				logger.Error("failed to read JWT private key file", "error", err)
			} else {
				pemData = string(data)
			}
		}
		if pemData != "" {
			key, err := crypto.ParseRSAPrivateKey(pemData)
			if err != nil {
				logger.Error("failed to load JWT RSA private key", "error", err)
			} else {
				h.rsaPrivKey = key
			}
		}
	}
	return h
}

// secureCookies returns true when cookies should be sent with the Secure flag.
// This is the case when TLS certificates are configured or when the BaseURL
// uses an https:// scheme.
func (h *Handler) secureCookies() bool {
	if len(h.cfg.TLS.Certificates) > 0 {
		return true
	}
	return strings.HasPrefix(h.cfg.Server.BaseURL, "https://")
}

// RegisterRoutes adds auth routes to the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("GET /auth/github", h.githubLimiter.Middleware(http.HandlerFunc(h.handleGitHubLogin)))
	mux.HandleFunc("GET /auth/github/callback", h.handleGitHubCallback)
	mux.HandleFunc("POST /auth/logout", h.handleLogout)
	mux.HandleFunc("GET /auth/status", h.handleStatus)

	// OAuth broker endpoints: delegate authentication to this proxy.
	if h.cfg.Auth.JWTPrivateKey != "" || h.cfg.Auth.JWTPrivateKeyFile != "" {
		if h.rsaPrivKey == nil {
			h.logger.Error("jwt_private_key configuration is invalid; oauth broker endpoints disabled")
		} else {
			mux.Handle("GET /auth/authorize", h.authorizeLimiter.Middleware(http.HandlerFunc(h.handleBrokerAuthorize)))
			mux.HandleFunc("GET /auth/callback", h.handleBrokerCallback)
			mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)
			h.logger.Info("oauth broker endpoints enabled")
			if len(h.cfg.Auth.AllowedRedirects) == 0 {
				h.logger.Warn("oauth broker enabled but no allowed redirects configured; all broker authorization requests will fail with \"redirect_uri not allowed\"")
			}
		}
	}

	// Dev-mode only: test login endpoint that bypasses GitHub OAuth.
	if h.cfg.DevMode {
		h.logger.Warn("dev mode enabled: /auth/test-login endpoint is active")
		mux.Handle("POST /auth/test-login", h.loginLimiter.Middleware(http.HandlerFunc(h.handleTestLogin)))
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
	s, ok := h.sessions.Get(token)
	if !ok {
		return nil
	}
	// ExpiresAt is a belt-and-suspenders check; the LRU TTL already evicts
	// expired entries, but we keep it for defense in depth.
	if time.Now().After(s.ExpiresAt) {
		h.sessions.Remove(token)
		return nil
	}
	return s
}

func (h *Handler) createSession(userID, username, role string) string {
	token := generateSessionToken()
	h.sessions.Add(token, &Session{
		UserID:    userID,
		Username:  username,
		Role:      role,
		ExpiresAt: time.Now().Add(SessionDuration),
	})
	return token
}

// CreateTestSession creates a session for E2E testing without OAuth.
// Returns the session token that should be set as the ghp_session cookie.
func (h *Handler) CreateTestSession(userID, username, role string) string {
	return h.createSession(userID, username, role)
}

func (h *Handler) deleteSession(token string) {
	h.sessions.Remove(token)
}

func (h *Handler) handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	h.states.Add(state, struct{}{})

	params := url.Values{}
	params.Set("client_id", h.cfg.GitHub.ClientID)
	params.Set("redirect_uri", h.mainCallbackURL(r))
	params.Set("state", state)
	authURL := h.getGitHubBaseURL() + "/login/oauth/authorize?" + params.Encode()

	// If the request accepts JSON (CLI), return the URL; otherwise redirect.
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"url": authURL})
		return
	}
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
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
	setupAction := r.URL.Query().Get("setup_action")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "Missing code parameter", http.StatusBadRequest)
		return
	}

	// When GitHub redirects after app installation/authorization it sends
	// code + setup_action but no state parameter. Skip state validation in
	// that case — the code exchange itself authenticates the request.
	if setupAction == "" {
		if state == "" {
			http.Error(w, "Missing state parameter", http.StatusBadRequest)
			return
		}

		// Validate state. Get returns false for missing or TTL-expired entries.
		_, ok := h.states.Get(state)
		if ok {
			h.states.Remove(state)
		}
		if !ok {
			http.Error(w, "Invalid or expired state", http.StatusBadRequest)
			return
		}
	}

	// Exchange code for access token.
	// For the normal OAuth flow, pass the same redirect_uri that was sent in
	// the authorization request so GitHub can verify the two values match.
	// For the app installation flow (setup_action is set), the redirect_uri
	// was not sent in the authorization request so we omit it here.
	redirectURI := ""
	if setupAction == "" {
		redirectURI = h.mainCallbackURL(r)
	}
	accessToken, refreshToken, expiresIn, err := h.exchangeCode(code, redirectURI)
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
		Secure:   h.secureCookies(),
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
		Secure:   h.secureCookies(),
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
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
		}
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
		Secure:   h.secureCookies(),
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
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func (h *Handler) exchangeCode(code string, redirectURI string) (accessToken, refreshToken string, expiresIn int, err error) {
	params := url.Values{
		"client_id":     {h.cfg.GitHub.ClientID},
		"client_secret": {h.cfg.GitHub.ClientSecret},
		"code":          {code},
	}
	if redirectURI != "" {
		params.Set("redirect_uri", redirectURI)
	}

	req, err := http.NewRequest("POST", h.getGitHubBaseURL()+"/login/oauth/access_token",
		strings.NewReader(params.Encode()))
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseSize))
		return "", "", 0, fmt.Errorf("GitHub token endpoint returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseSize)).Decode(&result); err != nil {
		return "", "", 0, err
	}
	if result.Error != "" {
		if result.ErrorDescription != "" {
			return "", "", 0, fmt.Errorf("OAuth error: %s: %s", result.Error, result.ErrorDescription)
		}
		return "", "", 0, fmt.Errorf("OAuth error: %s", result.Error)
	}
	if result.AccessToken == "" {
		return "", "", 0, errors.New("OAuth response contained no access token")
	}

	if result.ExpiresIn == 0 {
		result.ExpiresIn = 28800 // 8 hours default
	}

	return result.AccessToken, result.RefreshToken, result.ExpiresIn, nil
}

func (h *Handler) getGitHubUser(accessToken string) (*githubUser, error) {
	req, err := http.NewRequest("GET", h.getGitHubAPIBaseURL()+"/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseSize))
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, body)
	}

	var user githubUser
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseSize)).Decode(&user); err != nil {
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

func (h *Handler) getGitHubBaseURL() string {
	if h.githubBaseURL != "" {
		return h.githubBaseURL
	}
	return "https://github.com"
}

func (h *Handler) getGitHubAPIBaseURL() string {
	if h.githubAPIBaseURL != "" {
		return h.githubAPIBaseURL
	}
	return "https://api.github.com"
}

// mainCallbackURL returns the absolute URL of the GitHub OAuth callback endpoint
// for the main login flow. It uses the configured BaseURL if available, otherwise
// derives the URL from the incoming request.
func (h *Handler) mainCallbackURL(r *http.Request) string {
	if h.cfg.Server.BaseURL != "" {
		return strings.TrimRight(h.cfg.Server.BaseURL, "/") + "/auth/github/callback"
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/auth/github/callback", scheme, r.Host)
}
