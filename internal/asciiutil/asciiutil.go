// Package asciiutil provides ASCII-only case-insensitive string helpers.
//
// GitHub owner logins and repository names are ASCII. The standard library
// helpers strings.EqualFold and strings.ToLower apply Unicode case rules, so
// "ſ" (U+017F) folds to "s" and the Kelvin sign (U+212A) lowercases to "k".
// Using them on owner or repository names lets a non-ASCII spelling match an
// ASCII allowlist entry (#317). These helpers fold only A-Z.
package asciiutil

// EqualFold reports whether a and b are equal under ASCII case folding.
// Non-ASCII bytes must match exactly.
func EqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lower(a[i]) != lower(b[i]) {
			return false
		}
	}
	return true
}

// ToLower maps A-Z to a-z and leaves every other byte unchanged.
func ToLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				b[j] = lower(b[j])
			}
			return string(b)
		}
	}
	return s
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
