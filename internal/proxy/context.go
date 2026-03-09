package proxy

import (
	"context"
	"net/http"
)

// contextKey is an unexported type used for context keys in this package
// to avoid collisions with keys from other packages.
type contextKey struct{ name string }

var usernameCtxKey = &contextKey{"github-username"}
var userIDCtxKey = &contextKey{"user-id"}

// AccessLogSlots holds the mutable string slots that downstream handlers
// populate so the access-log middleware can read them after the request.
type AccessLogSlots struct {
	Username *string
	UserID   *string
}

// PrepareAccessLogSlots returns a new request whose context carries mutable
// string slots for both the GitHub username and the internal user ID. Inner
// handlers call SetUsername / SetUserID to populate them; the access-log
// middleware reads the results after the request completes.
func PrepareAccessLogSlots(r *http.Request) (*http.Request, *AccessLogSlots) {
	usernameSlot := new(string)
	userIDSlot := new(string)
	ctx := context.WithValue(r.Context(), usernameCtxKey, usernameSlot)
	ctx = context.WithValue(ctx, userIDCtxKey, userIDSlot)
	return r.WithContext(ctx), &AccessLogSlots{Username: usernameSlot, UserID: userIDSlot}
}

// PrepareUsernameSlot returns a new request whose context carries a mutable
// string slot. Inner handlers call SetUsername to populate it; outer handlers
// call GetUsername to read the result. This pattern allows the access-log
// middleware to learn the username that a downstream handler resolved.
//
// Deprecated: use PrepareAccessLogSlots for new code.
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

// SetUserID stores the internal user ID in the request's context slot.
// It is a no-op if no slot was prepared.
func SetUserID(r *http.Request, userID string) {
	if slot, ok := r.Context().Value(userIDCtxKey).(*string); ok {
		*slot = userID
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

// GetUserID returns the internal user ID stored in the request context, or ""
// if none has been set.
func GetUserID(r *http.Request) string {
	if slot, ok := r.Context().Value(userIDCtxKey).(*string); ok {
		return *slot
	}
	return ""
}
