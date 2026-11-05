// Package permissions holds the canonical list of permission names that GHP
// accepts in token scopes. Both token creation (internal/token,
// internal/server) and scope enforcement (internal/proxy) use this list, so a
// name that a token can carry is always a name that enforcement or GitHub
// understands.
package permissions

import (
	"fmt"
	"sort"
	"strings"
)

// Levels a scope can grant. "write" implies "read".
const (
	LevelRead  = "read"
	LevelWrite = "write"
)

// Rejection reasons, used as the bounded "reason" metric label.
const (
	ReasonUnknownPermission = "unknown_permission"
	ReasonInvalidLevel      = "invalid_level"
)

// known is the union of:
//   - every permission name used by the proxy enforcement tables
//     (internal/proxy/scope.go and internal/proxy/graphql.go; a test there
//     fails if a table uses a name not listed here), and
//   - the repository and organization permission names of the GitHub App
//     permissions object, which agent (gha_) tokens pass to GitHub's
//     POST /app/installations/{id}/access_tokens API.
//
// There are no aliases: GitHub has no "pulls" permission (the name is
// "pull_requests"), so "pulls" is rejected rather than normalised.
var known = map[string]struct{}{
	// Repository permissions.
	"actions":                      {},
	"administration":               {},
	"checks":                       {},
	"codespaces":                   {},
	"contents":                     {},
	"dependabot_secrets":           {},
	"deployments":                  {},
	"discussions":                  {},
	"environments":                 {},
	"issues":                       {},
	"metadata":                     {},
	"packages":                     {},
	"pages":                        {},
	"projects":                     {}, // used by GraphQL enforcement (Projects v2)
	"pull_requests":                {},
	"repository_custom_properties": {},
	"repository_hooks":             {},
	"repository_projects":          {},
	"secret_scanning_alerts":       {},
	"secrets":                      {},
	"security_events":              {},
	"single_file":                  {},
	"statuses":                     {},
	"vulnerability_alerts":         {},
	"workflows":                    {},
	// Organization permissions.
	"members":                          {},
	"organization_administration":      {},
	"organization_custom_roles":        {},
	"organization_hooks":               {},
	"organization_packages":            {},
	"organization_plan":                {},
	"organization_projects":            {},
	"organization_secrets":             {},
	"organization_self_hosted_runners": {},
	"organization_user_blocking":       {},
	"team_discussions":                 {},
}

var sortedNames = func() []string {
	names := make([]string, 0, len(known))
	for n := range known {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}()

// IsKnown reports whether name is a canonical permission name.
func IsKnown(name string) bool {
	_, ok := known[name]
	return ok
}

// Names returns the canonical permission names, sorted.
func Names() []string {
	out := make([]string, len(sortedNames))
	copy(out, sortedNames)
	return out
}

// ValidationError describes a rejected permission:level pair.
type ValidationError struct {
	Reason     string
	Permission string
	Level      string
}

func (e *ValidationError) Error() string {
	switch e.Reason {
	case ReasonInvalidLevel:
		return fmt.Sprintf("invalid scope level %q for %q (must be read or write)", truncate(e.Level), truncate(e.Permission))
	default:
		return fmt.Sprintf("unknown scope permission %q (valid permissions: %s)", truncate(e.Permission), strings.Join(sortedNames, ", "))
	}
}

// Validate checks that permission is a canonical name and level is read or
// write. It returns a *ValidationError otherwise.
func Validate(permission, level string) error {
	if !IsKnown(permission) {
		return &ValidationError{Reason: ReasonUnknownPermission, Permission: permission, Level: level}
	}
	if level != LevelRead && level != LevelWrite {
		return &ValidationError{Reason: ReasonInvalidLevel, Permission: permission, Level: level}
	}
	return nil
}

// maxEcho bounds how much of a user-supplied value an error message repeats.
const maxEcho = 64

func truncate(s string) string {
	r := []rune(s)
	if len(r) <= maxEcho {
		return s
	}
	return string(r[:maxEcho]) + "…"
}
