package asciiutil

import "testing"

func TestEqualFold(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"goodtune/ghp", "goodtune/ghp", true},
		{"GoodTune/GHP", "goodtune/ghp", true},
		{"", "", true},
		{"users/r", "uſers/r", false}, // U+017F long s
		{"kit/r", "Kit/r", false},     // Kelvin sign
		{"a", "b", false},
		{"abc", "ab", false},
		{"ß", "ß", true},
		{"[", "{", false},
	}
	for _, tc := range tests {
		t.Run(tc.a+"|"+tc.b, func(t *testing.T) {
			if got := EqualFold(tc.a, tc.b); got != tc.want {
				t.Errorf("EqualFold(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestToLower(t *testing.T) {
	tests := []struct{ in, want string }{
		{"GoodTune/GHP", "goodtune/ghp"},
		{"already", "already"},
		{"Kit", "Kit"},
		{"Uſers", "uſers"},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := ToLower(tc.in); got != tc.want {
				t.Errorf("ToLower(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
