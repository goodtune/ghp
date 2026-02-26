package database

import (
	"encoding/json"
	"testing"
)

func TestScopes_HasPermission(t *testing.T) {
	scopes := Scopes{
		"contents":      "read",
		"pull_requests": "write",
	}

	tests := []struct {
		permission string
		level      string
		want       bool
	}{
		{"contents", "read", true},
		{"contents", "write", false},
		{"pull_requests", "read", true},  // write implies read
		{"pull_requests", "write", true},
		{"issues", "read", false},
		{"issues", "write", false},
	}

	for _, tt := range tests {
		got := scopes.HasPermission(tt.permission, tt.level)
		if got != tt.want {
			t.Errorf("HasPermission(%q, %q) = %v, want %v", tt.permission, tt.level, got, tt.want)
		}
	}
}

func TestParseScopes(t *testing.T) {
	data := json.RawMessage(`{"contents":"read","pull_requests":"write"}`)
	scopes, err := ParseScopes(data)
	if err != nil {
		t.Fatalf("ParseScopes: %v", err)
	}
	if scopes["contents"] != "read" {
		t.Errorf("contents = %q, want read", scopes["contents"])
	}
	if scopes["pull_requests"] != "write" {
		t.Errorf("pull_requests = %q, want write", scopes["pull_requests"])
	}
}
