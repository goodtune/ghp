package main

import (
	"strings"
	"testing"
)

func TestValidateScopeFlag(t *testing.T) {
	tests := []struct {
		scope   string
		wantErr string
	}{
		{"", ""},
		{"contents:read,pull_requests:write", ""},
		{"pulls:write", "unknown scope permission \"pulls\""},
		{"foo:read", "valid permissions"},
		{"contents:admin", "must be read or write"},
	}
	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			err := validateScopeFlag(tt.scope)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
