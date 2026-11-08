package gitcred

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestParseRequest(t *testing.T) {
	basic := Request{Protocol: "https", Host: "github.com", Path: "goodtune/ghp.git"}
	tests := []struct {
		name       string
		input      string
		want       Request
		wantErr    bool
		errMessage string
		secret     string
	}{
		{
			name:  "basic",
			input: "protocol=https\nhost=github.com\npath=goodtune/ghp.git\n\n",
			want:  basic,
		},
		{
			name:  "eof",
			input: "protocol=https\nhost=github.com\npath=goodtune/ghp.git\n",
			want:  basic,
		},
		{
			name:  "eof without final newline",
			input: "protocol=https\nhost=github.com\npath=goodtune/ghp.git",
			want:  basic,
		},
		{
			name:  "crlf",
			input: "protocol=https\r\nhost=github.com\r\npath=goodtune/ghp.git\r\n\r\n",
			want:  basic,
		},
		{
			name:  "stops at blank line",
			input: "protocol=https\n\nhost=evil\n",
			want:  Request{Protocol: "https"},
		},
		{
			name:  "unknown keys ignored",
			input: "capability[]=authtype\nwwwauth[]=Basic\nprotocol=https\n",
			want:  Request{Protocol: "https"},
		},
		{
			name:  "array form of a known key ignored",
			input: "host[]=evil\nhost=github.com\n",
			want:  Request{Host: "github.com"},
		},
		{
			name:  "last wins",
			input: "host=a\nhost=b\n",
			want:  Request{Host: "b"},
		},
		{
			name:  "value split on first equals",
			input: "password=a=b\n",
			want:  Request{Password: "a=b"},
		},
		{
			name:  "password",
			input: "username=x-access-token\npassword=gha_x\n",
			want:  Request{Username: "x-access-token", Password: "gha_x"},
		},
		{
			name:  "empty input",
			input: "",
			want:  Request{},
		},
		{
			name:       "no equals",
			input:      "garbage\n",
			wantErr:    true,
			errMessage: `invalid credential line (no "=")`,
			secret:     "garbage",
		},
		{
			name:       "nul",
			input:      "path=secretvalue\x00\n",
			wantErr:    true,
			errMessage: `invalid value for key "path"`,
			secret:     "secretvalue",
		},
		{
			name:       "nul in key",
			input:      "pass\x00word=secretvalue\n",
			wantErr:    true,
			errMessage: "invalid credential line (NUL in key)",
			secret:     "secretvalue",
		},
		{
			name:       "oversize",
			input:      strings.Repeat("x=0123456789abcdef\n", (65<<10)/19+1),
			wantErr:    true,
			errMessage: "credential request larger than 64 KiB",
		},
		{
			name:       "oversize single line",
			input:      "password=" + strings.Repeat("s", 65<<10) + "\n",
			wantErr:    true,
			errMessage: "credential request larger than 64 KiB",
			secret:     "sss",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRequest(strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseRequest() error = nil, want %q", tt.errMessage)
				}
				if err.Error() != tt.errMessage {
					t.Errorf("ParseRequest() error = %q, want %q", err.Error(), tt.errMessage)
				}
				if tt.secret != "" && strings.Contains(err.Error(), tt.secret) {
					t.Errorf("ParseRequest() error %q echoes the value %q", err.Error(), tt.secret)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRequest() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ParseRequest() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseRequest_ExactlyAtLimit(t *testing.T) {
	// A request of exactly 64 KiB is accepted; one byte more is not.
	line := "x=" + strings.Repeat("a", 64<<10-3) + "\n"
	if len(line) != 64<<10 {
		t.Fatalf("test setup: line is %d bytes", len(line))
	}
	if _, err := ParseRequest(strings.NewReader(line)); err != nil {
		t.Fatalf("ParseRequest() at limit error = %v", err)
	}
	if _, err := ParseRequest(strings.NewReader(line + "y")); err == nil {
		t.Fatal("ParseRequest() over limit error = nil")
	}
}

func TestWriteCredential(t *testing.T) {
	tests := []struct {
		name       string
		cred       Credential
		want       string
		errMessage string
		secret     string
	}{
		{
			name: "with expiry",
			cred: Credential{Username: "x-access-token", Password: "ghx_abc", Expiry: time.Unix(1767225600, 0)},
			want: "username=x-access-token\npassword=ghx_abc\npassword_expiry_utc=1767225600\n",
		},
		{
			name: "zero expiry",
			cred: Credential{Username: "x-access-token", Password: "ghx_abc"},
			want: "username=x-access-token\npassword=ghx_abc\n",
		},
		{
			name:       "newline in password",
			cred:       Credential{Username: "x-access-token", Password: "sec\nret"},
			errMessage: `invalid value for key "password"`,
			secret:     "sec",
		},
		{
			name:       "carriage return in password",
			cred:       Credential{Username: "x-access-token", Password: "sec\rret"},
			errMessage: `invalid value for key "password"`,
			secret:     "sec",
		},
		{
			name:       "nul in password",
			cred:       Credential{Username: "x-access-token", Password: "sec\x00ret"},
			errMessage: `invalid value for key "password"`,
			secret:     "sec",
		},
		{
			name:       "newline in username",
			cred:       Credential{Username: "x\nquit=true", Password: "ghx_abc"},
			errMessage: `invalid value for key "username"`,
			secret:     "quit",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer
			err := WriteCredential(&b, tt.cred)
			if tt.errMessage != "" {
				if err == nil {
					t.Fatalf("WriteCredential() error = nil, want %q", tt.errMessage)
				}
				if err.Error() != tt.errMessage {
					t.Errorf("WriteCredential() error = %q, want %q", err.Error(), tt.errMessage)
				}
				if strings.Contains(err.Error(), tt.secret) {
					t.Errorf("WriteCredential() error %q echoes the value", err.Error())
				}
				if b.Len() != 0 {
					t.Errorf("WriteCredential() wrote %q on error, want nothing", b.String())
				}
				return
			}
			if err != nil {
				t.Fatalf("WriteCredential() error = %v", err)
			}
			if b.String() != tt.want {
				t.Errorf("WriteCredential() wrote %q, want %q", b.String(), tt.want)
			}
			if strings.Contains(b.String(), "quit") {
				t.Errorf("WriteCredential() output %q contains quit", b.String())
			}
		})
	}
}
