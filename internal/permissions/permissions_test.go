package permissions

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name       string
		permission string
		level      string
		wantReason string
	}{
		{"canonical pull_requests write", "pull_requests", "write", ""},
		{"canonical contents read", "contents", "read", ""},
		{"github app only name", "organization_administration", "read", ""},
		{"pulls alias rejected", "pulls", "write", ReasonUnknownPermission},
		{"unknown name", "foo", "read", ReasonUnknownPermission},
		{"admin level rejected", "contents", "admin", ReasonInvalidLevel},
		{"empty level", "contents", "", ReasonInvalidLevel},
		{"case sensitive", "Contents", "read", ReasonUnknownPermission},
		{"deprecated workflows read alias accepted", "workflows", "read", ""},
		{"workflows write", "workflows", "write", ""},
		{"projects enforcement name", "projects", "read", ""},
		{"admin level not accepted for projects", "organization_projects", "admin", ReasonInvalidLevel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.permission, tt.level)
			if tt.wantReason == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("expected *ValidationError, got %v", err)
			}
			if ve.Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", ve.Reason, tt.wantReason)
			}
			if tt.wantReason == ReasonUnknownPermission && !strings.Contains(err.Error(), "pull_requests") {
				t.Errorf("message should list valid names: %v", err)
			}
		})
	}
}

func TestNamesSortedAndKnown(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Fatal("no names")
	}
	for i, n := range names {
		if !IsKnown(n) {
			t.Errorf("%q not known", n)
		}
		if i > 0 && names[i-1] >= n {
			t.Errorf("names not sorted/unique at %q", n)
		}
	}
}

// TestDocsListEveryName keeps the user-facing list in token-scoping.md in
// step with the canonical list.
func TestDocsListEveryName(t *testing.T) {
	data, err := os.ReadFile("../../docs/features/token-scoping.md")
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	doc := string(data)
	for _, n := range Names() {
		if !strings.Contains(doc, "`"+n+"`") {
			t.Errorf("docs/features/token-scoping.md does not list %q", n)
		}
	}
}

func TestValidationErrorBoundsEcho(t *testing.T) {
	long := strings.Repeat("x", 5000)
	for _, err := range []error{Validate(long, "read"), Validate("contents", long)} {
		msg := err.Error()
		if strings.Contains(msg, strings.Repeat("x", 65)) {
			t.Errorf("echoed value not truncated (len %d)", len(msg))
		}
		if !strings.Contains(msg, "…") {
			t.Errorf("missing truncation marker: %.100s", msg)
		}
		if len(msg) > 2000 {
			t.Errorf("message too long: %d", len(msg))
		}
	}
}

// TestGitHubAppNamesKnown covers the repository and organization names of
// GitHub's app-permissions schema (#318).
func TestGitHubAppNamesKnown(t *testing.T) {
	for _, n := range []string{
		"artifact_metadata", "attestations", "code_quality", "merge_queues",
		"custom_properties_for_organizations",
		"enterprise_custom_properties_for_organizations",
		"organization_announcement_banners", "organization_copilot_agent_settings",
		"organization_copilot_requests", "organization_copilot_seat_management",
		"organization_custom_org_roles", "organization_custom_properties",
		"organization_events", "organization_external_properties_for_repos",
		"organization_personal_access_token_requests",
		"organization_personal_access_tokens",
	} {
		t.Run(n, func(t *testing.T) {
			if err := Validate(n, LevelRead); err != nil {
				t.Errorf("Validate(%q, read) = %v", n, err)
			}
		})
	}
}

func TestGrants(t *testing.T) {
	tests := []struct {
		name   string
		scopes map[string]string
		perm   string
		level  string
		want   bool
	}{
		{"exact read", map[string]string{"issues": "read"}, "issues", "read", true},
		{"write implies read", map[string]string{"issues": "write"}, "issues", "read", true},
		{"read does not imply write", map[string]string{"issues": "read"}, "issues", "write", false},
		{"missing", map[string]string{"contents": "write"}, "issues", "read", false},
		{"workflows read alias grants actions read", map[string]string{"workflows": "read"}, "actions", "read", true},
		{"workflows read alias does not grant actions write", map[string]string{"workflows": "read"}, "actions", "write", false},
		{"workflows write does not grant actions read", map[string]string{"workflows": "write"}, "actions", "read", false},
		{"repository_projects read grants projects read", map[string]string{"repository_projects": "read"}, "projects", "read", true},
		{"organization_projects read grants projects read", map[string]string{"organization_projects": "read"}, "projects", "read", true},
		{"repository_projects write grants projects write", map[string]string{"repository_projects": "write"}, "projects", "write", true},
		{"organization_projects read does not grant projects write", map[string]string{"organization_projects": "read"}, "projects", "write", false},
		{"projects does not grant repository_projects", map[string]string{"projects": "write"}, "repository_projects", "read", false},
		{"nil scopes", nil, "issues", "read", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Grants(tt.scopes, tt.perm, tt.level); got != tt.want {
				t.Errorf("Grants(%v, %q, %q) = %v, want %v", tt.scopes, tt.perm, tt.level, got, tt.want)
			}
		})
	}
}

func TestForGitHubApp(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]string
		want map[string]string
	}{
		{"nil stays nil", nil, nil},
		{"unchanged", map[string]string{"contents": "read"}, map[string]string{"contents": "read"}},
		{"projects read", map[string]string{"projects": "read"},
			map[string]string{"repository_projects": "read", "organization_projects": "read"}},
		{"projects write keeps higher explicit level", map[string]string{"projects": "read", "repository_projects": "write"},
			map[string]string{"repository_projects": "write", "organization_projects": "read"}},
		{"projects write raises explicit read", map[string]string{"projects": "write", "organization_projects": "read"},
			map[string]string{"repository_projects": "write", "organization_projects": "write"}},
		{"workflows read becomes actions read", map[string]string{"workflows": "read"}, map[string]string{"actions": "read"}},
		{"workflows read with actions write", map[string]string{"workflows": "read", "actions": "write"}, map[string]string{"actions": "write"}},
		{"workflows write passes through", map[string]string{"workflows": "write"}, map[string]string{"workflows": "write"}},
		// Levels are not checked here; Validate is the guard at creation.
		{"invalid level left untouched", map[string]string{"contents": "admin"}, map[string]string{"contents": "admin"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ForGitHubApp(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ForGitHubApp(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidateWarnsOnDeprecatedAlias(t *testing.T) {
	var buf bytes.Buffer
	orig := warnLogger
	warnLogger = func() *slog.Logger { return slog.New(slog.NewTextHandler(&buf, nil)) }
	t.Cleanup(func() { warnLogger = orig })

	if err := Validate("workflows", "read"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "deprecated") || !strings.Contains(buf.String(), "actions:read") {
		t.Errorf("expected deprecation warning, got %q", buf.String())
	}
	buf.Reset()
	if err := Validate("workflows", "write"); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("unexpected warning for workflows:write: %q", buf.String())
	}
}
