package token

import (
	"reflect"
	"sort"
	"strings"
	"unicode"

	"github.com/google/go-github/v68/github"
)

// Permission describes a single GitHub App installation permission.
type Permission struct {
	Key         string   // JSON tag from InstallationPermissions, e.g. "pull_requests"
	DisplayName string   // Human-friendly name, e.g. "Pull requests"
	Description string   // Short description for the UI
	Levels      []string // Allowed access levels, e.g. ["read", "write"]
}

// commonKeys is the curated subset of permissions typically needed by coding agents.
var commonKeys = map[string]bool{
	"actions":       true,
	"checks":        true,
	"contents":      true,
	"deployments":   true,
	"issues":        true,
	"metadata":      true,
	"packages":      true,
	"pull_requests": true,
	"statuses":      true,
	"workflows":     true,
}

// descriptions provides short UI descriptions for common permissions.
var descriptions = map[string]string{
	"actions":       "GitHub Actions workflows and runs",
	"checks":        "Check runs and check suites",
	"contents":      "Repository contents, commits, branches, and merges",
	"deployments":   "Deployment creation and status",
	"issues":        "Issues and related comments, labels, and milestones",
	"metadata":      "Repository metadata (read-only)",
	"packages":      "GitHub Packages",
	"pull_requests": "Pull requests and related comments, reviews, and merges",
	"statuses":      "Commit statuses",
	"workflows":     "GitHub Actions workflow files",
}

var (
	allPermissions []Permission
	permissionMap  map[string]Permission
)

func init() {
	allPermissions = buildRegistry()
	permissionMap = make(map[string]Permission, len(allPermissions))
	for _, p := range allPermissions {
		permissionMap[p.Key] = p
	}
}

// AllPermissions returns all permissions derived from the go-github SDK.
func AllPermissions() []Permission {
	out := make([]Permission, len(allPermissions))
	copy(out, allPermissions)
	return out
}

// CommonPermissions returns a curated subset of permissions for coding agents.
func CommonPermissions() []Permission {
	var out []Permission
	for _, p := range allPermissions {
		if commonKeys[p.Key] {
			out = append(out, p)
		}
	}
	return out
}

// PermissionByKey looks up a permission by its JSON key.
func PermissionByKey(key string) (Permission, bool) {
	p, ok := permissionMap[key]
	return p, ok
}

// buildRegistry uses reflection on github.InstallationPermissions to build
// the canonical permission list.
func buildRegistry() []Permission {
	t := reflect.TypeOf(github.InstallationPermissions{})
	perms := make([]Permission, 0, t.NumField())

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Extract the JSON tag key.
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		key := strings.SplitN(tag, ",", 2)[0]
		if key == "" {
			continue
		}

		levels := []string{"read", "write"}
		if key == "metadata" {
			levels = []string{"read"}
		}

		perms = append(perms, Permission{
			Key:         key,
			DisplayName: fieldNameToDisplay(field.Name),
			Description: descriptions[key],
			Levels:      levels,
		})
	}

	sort.Slice(perms, func(i, j int) bool {
		return perms[i].Key < perms[j].Key
	})

	return perms
}

// fieldNameToDisplay converts a Go struct field name like "PullRequests" to
// a human-friendly display name like "Pull requests".
func fieldNameToDisplay(name string) string {
	// Handle known acronyms that should stay uppercase.
	acronyms := map[string]string{
		"Api":  "API",
		"Gpg":  "GPG",
		"Ssh":  "SSH",
		"Url":  "URL",
		"Urls": "URLs",
	}

	// Split on camelCase boundaries.
	var words []string
	var current []rune
	for _, r := range name {
		if unicode.IsUpper(r) && len(current) > 0 {
			words = append(words, string(current))
			current = []rune{r}
		} else {
			current = append(current, r)
		}
	}
	if len(current) > 0 {
		words = append(words, string(current))
	}

	// Apply acronym replacements and lowercase non-first words.
	for i, w := range words {
		if replacement, ok := acronyms[w]; ok {
			words[i] = replacement
		} else if i > 0 {
			words[i] = strings.ToLower(w)
		}
	}

	return strings.Join(words, " ")
}
