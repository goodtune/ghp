// Package permissions holds the canonical list of permission names that GHP
// accepts in token scopes. Both token creation (internal/token,
// internal/server) and scope enforcement (internal/proxy) use this list, so a
// name that a token can carry is always a name that enforcement or GitHub
// understands.
package permissions

import (
	"fmt"
	"log/slog"
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
// The GitHub App names come from the app-permissions schema in GitHub's REST
// description (https://github.com/github/rest-api-description), which backs
// https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app.
// Account (user) permissions are not listed: installation tokens act on an
// installation, not a user account.
//
// Names are not normalised: GitHub has no "pulls" permission (the name is
// "pull_requests"), so "pulls" is rejected. Two enforcement aliases exist; see
// Grants and ForGitHubApp.
var known = map[string]struct{}{
	// Repository permissions.
	"actions":                      {},
	"administration":               {},
	"artifact_metadata":            {},
	"attestations":                 {},
	"checks":                       {},
	"code_quality":                 {},
	"codespaces":                   {},
	"contents":                     {},
	"dependabot_secrets":           {},
	"deployments":                  {},
	"discussions":                  {},
	"environments":                 {},
	"issues":                       {},
	"merge_queues":                 {},
	"metadata":                     {},
	"packages":                     {},
	"pages":                        {},
	"projects":                     {}, // enforcement-only; see Grants and ForGitHubApp
	"pull_requests":                {},
	"repository_custom_properties": {},
	"repository_hooks":             {},
	"repository_projects":          {},
	"secret_scanning_alerts":       {},
	"secrets":                      {},
	"security_events":              {},
	"single_file":                  {},
	"statuses":                     {},
	"variables":                    {},
	"vulnerability_alerts":         {},
	"workflows":                    {}, // write only at GitHub; read is a deprecated alias of actions:read
	// Organization permissions.
	"custom_properties_for_organizations":            {},
	"enterprise_custom_properties_for_organizations": {},
	"members":                                     {},
	"organization_administration":                 {},
	"organization_announcement_banners":           {},
	"organization_copilot_agent_settings":         {},
	"organization_copilot_requests":               {},
	"organization_copilot_seat_management":        {},
	"organization_custom_org_roles":               {},
	"organization_custom_properties":              {},
	"organization_custom_roles":                   {},
	"organization_events":                         {},
	"organization_external_properties_for_repos":  {},
	"organization_hooks":                          {},
	"organization_packages":                       {},
	"organization_personal_access_token_requests": {},
	"organization_personal_access_tokens":         {},
	"organization_plan":                           {},
	"organization_projects":                       {},
	"organization_secrets":                        {},
	"organization_self_hosted_runners":            {},
	"organization_user_blocking":                  {},
	"team_discussions":                            {},
}

// warnLogger returns the logger for deprecation warnings; tests swap it.
var warnLogger = slog.Default

// isDeprecatedWorkflowsRead reports whether permission:level is the
// deprecated workflows:read alias. GitHub's workflows permission has only a
// write level (it governs editing workflow files); the workflow REST
// endpoints are gated on actions. workflows:read is accepted for one release
// and treated as actions:read.
func isDeprecatedWorkflowsRead(permission, level string) bool {
	return permission == "workflows" && level == LevelRead
}

// levelGrants reports whether a granted level satisfies a required level.
// "write" implies "read".
func levelGrants(granted, required string) bool {
	if required == LevelRead {
		return granted == LevelRead || granted == LevelWrite
	}
	return granted == required
}

// Grants reports whether scopes satisfy permission at level. Besides the
// exact name, two aliases apply:
//
//   - "actions:read" is satisfied by the deprecated "workflows:read".
//   - "projects:<level>" (the enforcement name used by the GraphQL Projects
//     tables and the classic REST project rules) is satisfied by
//     "repository_projects" or "organization_projects" at that level.
func Grants(scopes map[string]string, permission, level string) bool {
	if granted, ok := scopes[permission]; ok && levelGrants(granted, level) {
		return true
	}
	switch permission {
	case "actions":
		return level == LevelRead && scopes["workflows"] == LevelRead
	case "projects":
		return levelGrants(scopes["repository_projects"], level) ||
			levelGrants(scopes["organization_projects"], level)
	}
	return false
}

// ForGitHubApp returns a copy of scopes that uses only GitHub App permission
// names, for the access_tokens request of agent (gha_) tokens:
//
//   - "projects:<level>" becomes "repository_projects" and
//     "organization_projects" at that level.
//   - the deprecated "workflows:read" becomes "actions:read".
//
// When a translated key is already present, the higher level wins. A nil
// map is returned unchanged.
func ForGitHubApp(scopes map[string]string) map[string]string {
	if scopes == nil {
		return nil
	}
	out := make(map[string]string, len(scopes)+1)
	for k, v := range scopes {
		out[k] = v
	}
	raise := func(name, level string) {
		if out[name] != LevelWrite {
			if level == LevelWrite || out[name] == "" {
				out[name] = level
			}
		}
	}
	if level, ok := out["projects"]; ok {
		delete(out, "projects")
		raise("repository_projects", level)
		raise("organization_projects", level)
	}
	if isDeprecatedWorkflowsRead("workflows", out["workflows"]) {
		delete(out, "workflows")
		raise("actions", LevelRead)
	}
	return out
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
	if isDeprecatedWorkflowsRead(permission, level) {
		warnLogger().Warn("scope workflows:read is deprecated and is treated as actions:read; use actions:read",
			"permission", permission, "level", level)
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
