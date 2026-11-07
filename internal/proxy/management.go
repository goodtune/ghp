package proxy

import (
	"net/http"
	"time"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/token"
)

const (
	msgManagementAnonymous = "Authentication with a GHP-issued token (ghx_ or gha_) is required"
	msgManagementNative    = "Native GitHub tokens are not accepted on the GHP management host; use a GHP-issued token (ghx_ or gha_)"
	msgBorderPolicy        = "Token type is not permitted by the border policy"

	reasonAnonymous   = "anonymous"
	reasonNativeToken = "native_token"
)

// RequireGHPToken wraps the API proxy handler for the management host's
// GHES-style paths (/api/v3/ and /api/graphql). Only requests that carry a
// GHP-issued client token (ghx_ or gha_) reach next. Anonymous requests get
// 401 and any other credential gets 403, independent of the border policy
// settings, so the management host can never act as an open pass-through
// to api.github.com. The api.github.com virtual host does not use this
// wrapper; the border policy still governs it.
func RequireGHPToken(next http.Handler, cfg *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		clientToken, rawCredential, _ := extractClientToken(r)
		if clientToken != "" {
			// Time the pass decision too; the downstream handler records
			// its own total, so only this stage is observed here.
			tokenType := ""
			if tt, ok := token.TokenTypeFromPrefix(clientToken); ok {
				tokenType = string(tt)
			}
			metrics.ObserveDecision(r.Context(), metrics.StageBorderPolicyCheck, tokenType, time.Since(start))
			next.ServeHTTP(w, r)
			return
		}
		reject := func(reason string, status int, msg string) {
			metrics.ManagementHostRejectedTotal.WithLabelValues(reason).Inc()
			metrics.ObserveDecision(r.Context(), metrics.StageBorderPolicyCheck, "", time.Since(start))
			metrics.ObserveDecision(r.Context(), metrics.StageTotal, "unknown", time.Since(start))
			writeError(w, status, msg)
		}
		if rawCredential == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ghp"`)
			reject(reasonAnonymous, http.StatusUnauthorized, msgManagementAnonymous)
			return
		}
		// Keep the border policy message for token types it blocks, so
		// clients see the same body as before; the status is 403 either way.
		msg := msgManagementNative
		if cfg.IsTokenBlocked(rawCredential) {
			msg = msgBorderPolicy
		}
		reject(reasonNativeToken, http.StatusForbidden, msg)
	})
}
