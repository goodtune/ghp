package token

import (
	"strings"
	"testing"
)

func TestGenerateToken(t *testing.T) {
	tok, err := generateToken(TokenTypeProxy)
	if err != nil {
		t.Fatalf("generateToken(proxy) error: %v", err)
	}
	if !strings.HasPrefix(tok, PrefixProxy) {
		t.Errorf("token should start with %q, got %q", PrefixProxy, tok[:4])
	}
	if len(tok) < 40 {
		t.Errorf("token too short: %d chars", len(tok))
	}

	// Generate another and confirm uniqueness.
	tok2, err := generateToken(TokenTypeProxy)
	if err != nil {
		t.Fatal(err)
	}
	if tok == tok2 {
		t.Error("two generated tokens should differ")
	}

	// Agent token should use gha_ prefix.
	aTok, err := generateToken(TokenTypeAgent)
	if err != nil {
		t.Fatalf("generateToken(agent) error: %v", err)
	}
	if !strings.HasPrefix(aTok, PrefixAgent) {
		t.Errorf("agent token should start with %q, got %q", PrefixAgent, aTok[:4])
	}
}

func TestHash(t *testing.T) {
	h1 := Hash("ghx_testtoken1")
	h2 := Hash("ghx_testtoken2")

	if h1 == h2 {
		t.Error("different tokens should produce different hashes")
	}

	// Same input should produce same hash.
	h3 := Hash("ghx_testtoken1")
	if h1 != h3 {
		t.Error("same input should produce same hash")
	}
}

func TestTokenTypeFromPrefix(t *testing.T) {
	tests := []struct {
		input    string
		wantType TokenType
		wantOK   bool
	}{
		{"ghx_abc123", TokenTypeProxy, true},
		{"gha_abc123", TokenTypeAgent, true},
		{"ghp_abc123", "", false},
		{"gho_abc123", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := TokenTypeFromPrefix(tt.input)
		if ok != tt.wantOK || got != tt.wantType {
			t.Errorf("TokenTypeFromPrefix(%q) = (%q, %v), want (%q, %v)",
				tt.input, got, ok, tt.wantType, tt.wantOK)
		}
	}
}

func TestParseScopeString(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
		want    map[string]string
	}{
		{
			input: "contents:read,pull_requests:write,issues:write",
			want: map[string]string{
				"contents": "read",
				"pull_requests": "write",
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
