package proxy

import (
	"context"
	"net/http"
)

// contextKey is an unexported type used for context keys in this package
// to avoid collisions with keys from other packages.
type contextKey struct{ name string }

var usernameCtxKey = &contextKey{"github-username"}

// PrepareUsernameSlot returns a new request whose context carries a mutable
// string slot. Inner handlers call SetUsername to populate it; outer handlers
// call GetUsername to read the result. This pattern allows the access-log
// middleware to learn the username that a downstream handler resolved.
func PrepareUsernameSlot(r *http.Request) (*http.Request, *string) {
	slot := new(string)
	ctx := context.WithValue(r.Context(), usernameCtxKey, slot)
	return r.WithContext(ctx), slot
}

// SetUsername stores the resolved GitHub username in the request's context
// slot. It is a no-op if no slot was prepared.
func SetUsername(r *http.Request, username string) {
	if slot, ok := r.Context().Value(usernameCtxKey).(*string); ok {
		*slot = username
	}
}

// GetUsername returns the GitHub username stored in the request context, or ""
// if none has been set.
func GetUsername(r *http.Request) string {
	if slot, ok := r.Context().Value(usernameCtxKey).(*string); ok {
		return *slot
	}
	return ""
}
