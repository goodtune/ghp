package webhook

import "testing"

func TestSanitizeToken(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", "_"},
		{"   ", "_"},
		{"pull_request", "pull_request"},
		{"opened", "opened"},
		{"my.repo", "my_repo"},
		{"with space", "with_space"},
		{"wild*card>", "wild_card_"},
		{"d2a1f1c2-0a9f-4d0c-8a1e-123456789abc", "d2a1f1c2-0a9f-4d0c-8a1e-123456789abc"},
		{"ünïcode", "__n__code"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := SanitizeToken(tt.in); got != tt.want {
				t.Errorf("SanitizeToken(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSubject(t *testing.T) {
	got := Subject("github.webhooks", SubjectParts{
		AppRecordID: "abc-123",
		Event:       "pull_request",
		Action:      "opened",
		Owner:       "goodtune",
		Repo:        "ghp.site",
	})
	want := "github.webhooks.abc-123.pull_request.opened.goodtune.ghp_site"
	if got != want {
		t.Errorf("Subject = %q, want %q", got, want)
	}

	got = Subject("github.webhooks", SubjectParts{Event: "ping"})
	want = "github.webhooks._.ping._._._"
	if got != want {
		t.Errorf("Subject (ping) = %q, want %q", got, want)
	}
}

func TestValidFilter(t *testing.T) {
	const prefix = "github.webhooks"
	tests := []struct {
		filter string
		want   bool
	}{
		{"github.webhooks", true},
		{"github.webhooks.>", true},
		{"github.webhooks.*.pull_request.>", true},
		{"github.webhooks._.ping._._._", true},
		{"", false},
		{"other.>", false},
		{"github.webhooksx.>", false},
		{"github.webhooks..x", false},
		{"github.webhooks.>.x", false},
		{"github.webhooks.a>", false},
		{"github.webhooks.a*", false},
		{"github.webhooks.a b", false},
	}
	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			if got := ValidFilter(prefix, tt.filter); got != tt.want {
				t.Errorf("ValidFilter(%q) = %v, want %v", tt.filter, got, tt.want)
			}
		})
	}
}
