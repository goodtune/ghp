package webhook

import "testing"

func TestVerifySignature(t *testing.T) {
	secret := []byte("It's a Secret to Everybody")
	body := []byte("Hello, World!")
	// Reference value from GitHub's webhook documentation.
	const want = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"

	if got := Sign(secret, body); got != want {
		t.Fatalf("Sign = %q, want %q", got, want)
	}

	tests := []struct {
		name   string
		secret []byte
		body   []byte
		header string
		want   bool
	}{
		{"valid", secret, body, want, true},
		{"valid with surrounding whitespace", secret, body, " " + want + " ", true},
		{"wrong secret", []byte("nope"), body, want, false},
		{"tampered body", secret, []byte("Hello, World?"), want, false},
		{"missing header", secret, body, "", false},
		{"sha1 header rejected", secret, body, "sha1=0123456789abcdef0123456789abcdef01234567", false},
		{"bad hex", secret, body, "sha256=zz", false},
		{"truncated digest", secret, body, want[:20], false},
		{"empty secret", nil, body, want, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifySignature(tt.secret, tt.body, tt.header); got != tt.want {
				t.Errorf("VerifySignature = %v, want %v", got, tt.want)
			}
		})
	}
}
