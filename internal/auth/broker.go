package auth

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// brokerState holds the pending state for an in-progress OAuth broker flow.
type brokerState struct {
	RedirectURI     string
	DownstreamState string
	ExpiresAt       time.Time
}

// BrokerClaims are the JWT claims minted by the OAuth broker.
type BrokerClaims struct {
	AvatarURL string `json:"avatar_url"`
	jwt.RegisteredClaims
}

// handleBrokerAuthorize is the entry point for downstream services to initiate
// authentication. It validates the redirect_uri, stores the broker state, and
// redirects the user to GitHub OAuth.
func (h *Handler) handleBrokerAuthorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "Missing redirect_uri parameter", http.StatusBadRequest)
		return
	}

	if !h.validateRedirectURI(redirectURI) {
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	downstreamState := r.URL.Query().Get("state")

	state := generateState()
	h.brokerStates.Add(state, &brokerState{
		RedirectURI:     redirectURI,
		DownstreamState: downstreamState,
		ExpiresAt:       time.Now().Add(brokerStateTTL),
	})

	callbackURL := h.brokerCallbackURL(r)
	params := url.Values{}
	params.Set("client_id", h.cfg.GitHub.ClientID)
	params.Set("redirect_uri", callbackURL)
	params.Set("state", state)

	authURL := h.getGitHubBaseURL() + "/login/oauth/authorize?" + params.Encode()
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// handleBrokerCallback handles the GitHub OAuth callback for broker flows.
// It exchanges the code for an access token, fetches the user's identity,
// mints a short-lived signed JWT, and redirects to the downstream service.
func (h *Handler) handleBrokerCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "Missing code parameter", http.StatusBadRequest)
		return
	}
	if state == "" {
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	bs, ok := h.brokerStates.Get(state)
	if ok {
		h.brokerStates.Remove(state)
	}
	if !ok || time.Now().After(bs.ExpiresAt) {
		http.Error(w, "Invalid or expired state", http.StatusBadRequest)
		return
	}

	// Exchange code for access token, including the redirect_uri that was
	// sent in the authorize request (GitHub requires it to match).
	callbackURL := h.brokerCallbackURL(r)
	accessToken, _, _, err := h.exchangeCode(code, callbackURL)
	if err != nil {
		h.logger.Error("broker: OAuth code exchange failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Fetch user identity from GitHub. The access token is not stored;
	// it is only used to retrieve the user's login and avatar.
	user, err := h.getGitHubUser(accessToken)
	if err != nil {
		h.logger.Error("broker: failed to get GitHub user", "error", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Mint a short-lived JWT containing the user's identity.
	now := time.Now()
	claims := BrokerClaims{
		AvatarURL: user.AvatarURL,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.Login,
			Audience:  jwt.ClaimStrings{bs.RedirectURI},
			ExpiresAt: jwt.NewNumericDate(now.Add(60 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(h.cfg.Auth.JWTSecret))
	if err != nil {
		h.logger.Error("broker: failed to sign JWT", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Redirect to the downstream service with the signed token.
	redirectURL, err := url.Parse(bs.RedirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect_uri", http.StatusInternalServerError)
		return
	}
	q := redirectURL.Query()
	q.Set("token", signed)
	if bs.DownstreamState != "" {
		q.Set("state", bs.DownstreamState)
	}
	redirectURL.RawQuery = q.Encode()

	h.logger.Info("broker_auth_complete", "user", user.Login, "redirect_uri", bs.RedirectURI)
	http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
}

// validateRedirectURI checks whether uri is permitted by the configured allowlist.
func (h *Handler) validateRedirectURI(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}

	// Require HTTPS. Allow HTTP only for localhost when dev mode is on.
	if parsed.Scheme != "https" {
		if !h.cfg.DevMode || !isLocalhost(parsed.Host) {
			return false
		}
	}

	for _, pattern := range h.cfg.Auth.AllowedRedirects {
		if matchesRedirectPattern(uri, parsed, pattern) {
			return true
		}
	}
	return false
}

// matchesRedirectPattern checks whether a parsed URI matches a single allowlist
// entry. Patterns can be exact URLs or wildcard domains like "*.example.com".
func matchesRedirectPattern(rawURI string, parsed *url.URL, pattern string) bool {
	// Wildcard domain pattern: *.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		host := parsed.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}

	// Exact URL match (normalize trailing slashes).
	return strings.TrimRight(rawURI, "/") == strings.TrimRight(pattern, "/")
}

func isLocalhost(host string) bool {
	h := host
	if hp, _, err := net.SplitHostPort(h); err == nil {
		h = hp
	}
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// brokerCallbackURL returns the URL that GitHub should redirect to after
// the user authorizes. It uses the configured BaseURL if available, otherwise
// it derives the URL from the incoming request.
func (h *Handler) brokerCallbackURL(r *http.Request) string {
	if h.cfg.Server.BaseURL != "" {
		return strings.TrimRight(h.cfg.Server.BaseURL, "/") + "/auth/callback"
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/auth/callback", scheme, r.Host)
}
