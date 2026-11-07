package redact

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
)

func TestString(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"ghx", "ghx_abcdefgh12345678", "ghx_[REDACTED]"},
		{"gha", "gha_test00000000", "gha_[REDACTED]"},
		{"ghpr", "ghpr_test00000000", "ghpr_[REDACTED]"},
		{"gho", "gho_test00000000", "gho_[REDACTED]"},
		{"ghu", "ghu_test00000000", "ghu_[REDACTED]"},
		{"ghs", "ghs_test00000000", "ghs_[REDACTED]"},
		{"ghp", "ghp_test00000000", "ghp_[REDACTED]"},
		{"ghr", "ghr_test00000000", "ghr_[REDACTED]"},
		{"github_pat", "github_pat_11ABCtest0000_fake", "github_pat_[REDACTED]"},
		{"embedded", "Authorization: token ghx_test00000000 end", "Authorization: token [REDACTED] end"},
		{"embedded no header", "saw ghx_test00000000 end", "saw ghx_[REDACTED] end"},
		{"two", "ghx_test00000000 gha_test11111111", "ghx_[REDACTED] gha_[REDACTED]"},
		{"ghp base62", "ghp_aB3dE6gH9jK2mN5pQ8", "ghp_[REDACTED]"},
		{"env GHP_SERVER_URL", "GHP_SERVER_URL is not set", "GHP_SERVER_URL is not set"},
		{"env GHP_RIG_REPO_A", "GHP_RIG_REPO_A=goodtune/x", "GHP_RIG_REPO_A=goodtune/x"},
		// Upper-case prefixes are not real tokens; not redacting them is accepted.
		{"upper gho", "GHO_TEST00000000", "GHO_TEST00000000"},
		{"basic line", "Authorization: Basic eDpzZWNyZXQ=", "Authorization: Basic [REDACTED]"},
		{"basic json", `{"Authorization": "Basic eDpzZWNyZXQ="}`, `{"Authorization": "Basic [REDACTED]"}`},
		{"basic json compact", `{"authorization":"basic eDpzZWNyZXQ="}`, `{"authorization":"basic [REDACTED]"}`},
		{"bearer json", `{"Authorization": "Bearer opaque-value"}`, `{"Authorization": "Bearer [REDACTED]"}`},
		{"already redacted", "token REDACTED", "token REDACTED"},
		{"prefix alone", "ghx_", "ghx_"},
		{"too short", "ghx_abc1234", "ghx_abc1234"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := String(tt.in); got != tt.want {
				t.Errorf("String(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestBytes_JSONStaysValid(t *testing.T) {
	in := []byte(`{"outer":{"inner":["x","bearer ghx_test00000000"]},"n":1}`)
	out := Bytes(in)
	if Contains(out) {
		t.Fatalf("token survived: %s", out)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("redacted JSON invalid: %v (%s)", err, out)
	}
	inner := v["outer"].(map[string]any)["inner"].([]any)
	if inner[1] != "bearer ghx_[REDACTED]" {
		t.Errorf("inner = %v", inner[1])
	}
}

func TestHeader(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "token ghx_test00000000")
	h.Add("Cookie", "session=abc")
	h.Add("Set-Cookie", "a=b")
	h.Add("X-Echo", "saw gha_test00000000")
	h.Add("Accept", "application/json")

	got := Header(h)
	for _, k := range []string{"Authorization", "Cookie", "Set-Cookie"} {
		if got.Get(k) != "[REDACTED]" {
			t.Errorf("%s = %q", k, got.Get(k))
		}
	}
	if got.Get("X-Echo") != "saw gha_[REDACTED]" {
		t.Errorf("X-Echo = %q", got.Get("X-Echo"))
	}
	if got.Get("Accept") != "application/json" {
		t.Errorf("Accept = %q", got.Get("Accept"))
	}
	if h.Get("Authorization") != "token ghx_test00000000" {
		t.Error("input header was mutated")
	}
	raw := Header(http.Header{"authorization": {"token ghx_test00000000"}})
	if raw["authorization"][0] != "[REDACTED]" { //nolint:staticcheck // deliberately non-canonical key
		t.Errorf("non-canonical key not masked: %v", raw)
	}
	if Header(nil) == nil {
		t.Error("Header(nil) should return empty non-nil header")
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"ghx_test00000000", true},
		{"ghx_[REDACTED]", false},
		{"nothing here", false},
		{"github_pat_11ABCtest0000", true},
		{"GHP_SERVER_URL_and_more", false},
		{"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x:ghx_test00000000")), true},
		{"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x:plainpass")), false},
		{"Authorization: Basic [REDACTED]", false},
		// Trailing punctuation after the credential.
		{"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x:ghx_test00000000")) + ".", true},
		{"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x:ghx_test00000000")) + "\",", true},
		// JSON-quoted header.
		{`{"Authorization": "Basic ` + base64.StdEncoding.EncodeToString([]byte("x:ghx_test00000000")) + `"}`, true},
		// URL-safe alphabet ("-" and "_" instead of "+" and "/").
		{"Authorization: Basic " + base64.URLEncoding.EncodeToString([]byte("\xfb\xff:ghx_test00000000")), true},
		{"Authorization: Basic " + base64.RawURLEncoding.EncodeToString([]byte("\xfb\xff:ghx_test00000000")), true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := Contains([]byte(tt.in)); got != tt.want {
				t.Errorf("Contains(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestRedact_ExecutorOutputs(t *testing.T) {
	basic := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghx_test00000000"))
	outputs := []struct{ name, in string }{
		{"gh stderr", "HTTP 401: Bad credentials (https://h/api/v3/user)\nGH_ENTERPRISE_TOKEN=ghx_test00000000"},
		{"rest body", `{"message":"echo","token":"gha_test00000000","nested":{"t":"ghs_test00000000"}}`},
		{"git url", "git: fatal: Authentication failed for 'https://x-access-token:ghx_test00000000@h/o/r.git/'"},
		{"basic header line", "> GET /o/r.git/info/refs\n> " + basic + "\n"},
	}
	for _, o := range outputs {
		t.Run(o.name, func(t *testing.T) {
			if !Contains([]byte(o.in)) {
				t.Fatalf("fixture should contain a token: %q", o.in)
			}
			if r := String(o.in); Contains([]byte(r)) {
				t.Errorf("token survived String: %q", r)
			}
			if r := Bytes([]byte(o.in)); Contains(r) {
				t.Errorf("token survived Bytes: %q", r)
			}
		})
	}

	h := http.Header{"Authorization": {"token ghx_test00000000"}, "X-Other": {"ghp_test00000000"}}
	for k, vs := range Header(h) {
		for _, v := range vs {
			if Contains([]byte(v)) {
				t.Errorf("header %s leaked: %q", k, v)
			}
		}
	}
}

// TestRedact_EncodedForms covers the forms from issue #337: a
// percent-encoded token, a JSON \uXXXX-escaped token (the tail must not
// leak) and a bare base64 "<user>:<token>" credential with no
// Authorization label.
func TestRedact_EncodedForms(t *testing.T) {
	b64 := func(enc *base64.Encoding, s string) string { return enc.EncodeToString([]byte(s)) }
	tests := []struct {
		name, in, want string
		leak           bool // Contains(in) must be true
	}{
		{"percent prefix", "q=%67hx_test00000000&x=1", "q=ghx_[REDACTED]&x=1", true},
		{"percent underscore", "q=ghx%5Ftest00000000", "q=ghx_[REDACTED]", true},
		{"percent in tail", "ghx_test%30%30%30%30%30%30", "ghx_[REDACTED]", true},
		{"percent upper hex", "%67%68%78%5Ftest00000000", "ghx_[REDACTED]", true},
		{"json escaped prefix", `{"t":"ghx_test00000000"}`, `{"t":"ghx_[REDACTED]"}`, true},
		{"json escaped tail", `{"t":"ghx_abcdefghABCDSECRETTAIL"}`, `{"t":"ghx_[REDACTED]"}`, true},
		{"json escaped tail short plain", `{"t":"ghx_abcdefghij"}`, `{"t":"ghx_[REDACTED]"}`, true},
		{"bare base64 std", "cred " + b64(base64.StdEncoding, "x:ghx_test00000000") + " end", "cred [REDACTED] end", true},
		{"bare base64 raw url", "cred=" + b64(base64.RawURLEncoding, "\xfb\xff:gha_test00000000"), "cred=[REDACTED]", true},
		{"bare base64 json", `{"c":"` + b64(base64.StdEncoding, "x-access-token:ghs_test00000000") + `"}`, `{"c":"[REDACTED]"}`, true},
		{"percent after non-token escape", "a%20%67hx_test00000000", "a%20ghx_[REDACTED]", true},
		{"json escape after newline escape", `{"m":"x\u000a\u0067hx_test00000000"}`, `{"m":"x\u000aghx_[REDACTED]"}`, true},
		// Non-token neighbours are left alone.
		{"percent non token", "a%20b%2Fc", "a%20b%2Fc", false},
		{"json escape non token", `{"m":"line\u000aend"}`, `{"m":"line\u000aend"}`, false},
		{"bare base64 non token", "x " + b64(base64.StdEncoding, "x:plainpassword") + " y", "x " + b64(base64.StdEncoding, "x:plainpassword") + " y", false},
		{"bare base64 no user", b64(base64.StdEncoding, "just some text here"), b64(base64.StdEncoding, "just some text here"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Contains([]byte(tt.in)); got != tt.leak {
				t.Errorf("Contains(%q) = %v, want %v", tt.in, got, tt.leak)
			}
			got := String(tt.in)
			if got != tt.want {
				t.Errorf("String(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if b := Bytes([]byte(tt.in)); string(b) != tt.want {
				t.Errorf("Bytes(%q) = %q, want %q", tt.in, b, tt.want)
			}
			if Contains([]byte(got)) {
				t.Errorf("token survived: %q", got)
			}
		})
	}
}
