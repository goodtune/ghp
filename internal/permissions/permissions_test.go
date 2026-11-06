package permissions

import (
	"errors"
	"os"
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
		if len(msg) > 1200 {
			t.Errorf("message too long: %d", len(msg))
		}
	}
}
