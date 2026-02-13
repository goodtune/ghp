package token

import (
	"strings"
	"testing"
)

func TestGenerateToken(t *testing.T) {
	tok, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken() error: %v", err)
	}
	if !strings.HasPrefix(tok, Prefix) {
		t.Errorf("token should start with %q, got %q", Prefix, tok[:4])
	}
	if len(tok) < 40 {
		t.Errorf("token too short: %d chars", len(tok))
	}

	// Generate another and confirm uniqueness.
	tok2, err := generateToken()
	if err != nil {
		t.Fatal(err)
	}
	if tok == tok2 {
		t.Error("two generated tokens should differ")
	}
}

func TestHash(t *testing.T) {
	h1 := Hash("ghp_testtoken1")
	h2 := Hash("ghp_testtoken2")

	if h1 == h2 {
		t.Error("different tokens should produce different hashes")
	}

	// Same input should produce same hash.
	h3 := Hash("ghp_testtoken1")
	if h1 != h3 {
		t.Error("same input should produce same hash")
	}
}

func TestParseScopeString(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
		want    map[string]string
	}{
		{
			input: "contents:read,pulls:write,issues:write",
			want: map[string]string{
				"contents": "read",
				"pulls":    "write",
				"issues":   "write",
			},
		},
		{
			input: "contents:read",
			want:  map[string]string{"contents": "read"},
		},
		{
			input:   "invalid",
			wantErr: true,
		},
		{
			input:   "",
			wantErr: true,
		},
		{
			input:   "contents:execute",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		scopes, err := ParseScopeString(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseScopeString(%q) expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseScopeString(%q) error: %v", tt.input, err)
			continue
		}
		for k, v := range tt.want {
			if scopes[k] != v {
				t.Errorf("ParseScopeString(%q)[%q] = %q, want %q", tt.input, k, scopes[k], v)
			}
		}
	}
}
