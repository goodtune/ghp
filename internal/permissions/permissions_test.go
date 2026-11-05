package permissions

import (
	"errors"
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
