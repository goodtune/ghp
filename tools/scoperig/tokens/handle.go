// Package tokens mints, tracks and revokes the ghx_ tokens the scope
// regression rig uses. Token values never leave a Handle except through
// Authorize and GHEnv.
package tokens

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
)

// Handle is a minted token. Every formatting path prints only a placeholder.
type Handle struct {
	id    string
	value string
}

// ID returns the token record ID.
func (h Handle) ID() string { return h.id }

// String returns "ghx_[REDACTED:<id>]".
func (h Handle) String() string { return "ghx_[REDACTED:" + h.id + "]" }

// GoString returns the same placeholder as String, so %#v is safe.
func (h Handle) GoString() string { return h.String() }

// MarshalJSON encodes the placeholder as a JSON string.
func (h Handle) MarshalJSON() ([]byte, error) { return json.Marshal(h.String()) }

// LogValue makes slog print the placeholder.
func (h Handle) LogValue() slog.Value { return slog.StringValue(h.String()) }

// Authorize sets "Authorization: token <value>" on r.
func (h Handle) Authorize(r *http.Request) { r.Header.Set("Authorization", "token "+h.value) }

// GHEnv returns the environment entries that make gh use this token.
func (h Handle) GHEnv() []string { return []string{"GH_ENTERPRISE_TOKEN=" + h.value} }

// GitExtraHeader returns the git http.extraHeader value that makes git send
// this token as a Basic credential (username x-access-token), the form git
// clients use for GitHub tokens.
func (h Handle) GitExtraHeader() string {
	return "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+h.value))
}
