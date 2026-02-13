package database

import (
	"encoding/json"
	"testing"
)

func TestScopes_HasPermission(t *testing.T) {
	scopes := Scopes{
		"contents": "read",
		"pulls":    "write",
	}

	tests := []struct {
		permission string
		level      string
		want       bool
	}{
		{"contents", "read", true},
		{"contents", "write", false},
		{"pulls", "read", true},  // write implies read
		{"pulls", "write", true},
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
	data := json.RawMessage(`{"contents":"read","pulls":"write"}`)
	scopes, err := ParseScopes(data)
	if err != nil {
		t.Fatalf("ParseScopes: %v", err)
	}
	if scopes["contents"] != "read" {
		t.Errorf("contents = %q, want read", scopes["contents"])
	}
	if scopes["pulls"] != "write" {
		t.Errorf("pulls = %q, want write", scopes["pulls"])
	}
}
