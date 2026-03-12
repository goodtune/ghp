package proxy

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseNetrc(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    map[string]netrcEntry
		wantErr bool
	}{
		{
			name: "single machine",
			content: `machine releases.example.com
login deploy
password s3cret`,
			want: map[string]netrcEntry{
				"releases.example.com": {Login: "deploy", Password: "s3cret"},
			},
		},
		{
			name:    "single line format",
			content: `machine mirror.example.com login admin password hunter2`,
			want: map[string]netrcEntry{
				"mirror.example.com": {Login: "admin", Password: "hunter2"},
			},
		},
		{
			name: "multiple machines",
			content: `machine a.example.com login u1 password p1
machine b.example.com login u2 password p2`,
			want: map[string]netrcEntry{
				"a.example.com": {Login: "u1", Password: "p1"},
				"b.example.com": {Login: "u2", Password: "p2"},
			},
		},
		{
			name: "default entry",
			content: `machine specific.example.com login user1 password pass1
default login fallback password fallpass`,
			want: map[string]netrcEntry{
				"specific.example.com": {Login: "user1", Password: "pass1"},
				"":                     {Login: "fallback", Password: "fallpass"},
			},
		},
		{
			name: "comments and blank lines",
			content: `# this is a comment
machine releases.example.com

login deploy
password s3cret
`,
			want: map[string]netrcEntry{
				"releases.example.com": {Login: "deploy", Password: "s3cret"},
			},
		},
		{
			name:    "machine without value",
			content: `machine`,
			wantErr: true,
		},
		{
			name:    "login without value",
			content: `machine example.com login`,
			wantErr: true,
		},
		{
			name:    "password without value",
			content: `machine example.com login user password`,
			wantErr: true,
		},
		{
			name:    "empty file",
			content: ``,
			want:    map[string]netrcEntry{},
		},
		{
			name: "macdef body with keyword-like lines is not parsed as credentials",
			content: `machine mirror.example.com login deploy password s3cret
macdef uploadtest
machine fake.example.com
login notreal
password notreal

machine other.example.com login other password otherpass`,
			want: map[string]netrcEntry{
				"mirror.example.com": {Login: "deploy", Password: "s3cret"},
				"other.example.com":  {Login: "other", Password: "otherpass"},
			},
		},
		{
			name: "macdef name on same line",
			content: `machine mirror.example.com login user password pass
macdef init
cd /pub
get README

machine backup.example.com login buser password bpass`,
			want: map[string]netrcEntry{
				"mirror.example.com": {Login: "user", Password: "pass"},
				"backup.example.com": {Login: "buser", Password: "bpass"},
			},
		},
		{
			name: "account token is skipped",
			content: `machine mirror.example.com account myacct login deploy password s3cret`,
			want: map[string]netrcEntry{
				"mirror.example.com": {Login: "deploy", Password: "s3cret"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "netrc")
			if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
				t.Fatal(err)
			}

			got, err := parseNetrc(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(got) != len(tt.want) {
				t.Fatalf("got %d entries, want %d", len(got), len(tt.want))
			}
			for k, wantEntry := range tt.want {
				gotEntry, ok := got[k]
				if !ok {
					t.Errorf("missing entry for %q", k)
					continue
				}
				if gotEntry.Login != wantEntry.Login {
					t.Errorf("entry[%q].Login = %q, want %q", k, gotEntry.Login, wantEntry.Login)
				}
				if gotEntry.Password != wantEntry.Password {
					t.Errorf("entry[%q].Password = %q, want %q", k, gotEntry.Password, wantEntry.Password)
				}
			}
		})
	}
}

func TestParseNetrcFileNotFound(t *testing.T) {
	_, err := parseNetrc("/nonexistent/netrc")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestNetrcTransport(t *testing.T) {
	dir := t.TempDir()
	netrcPath := filepath.Join(dir, "netrc")
	if err := os.WriteFile(netrcPath, []byte("machine mirror.example.com login deploy password s3cret\n"), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		url      string
		wantAuth bool
		wantUser string
		wantPass string
	}{
		{
			name:     "matching host gets auth",
			url:      "https://mirror.example.com/some/asset",
			wantAuth: true,
			wantUser: "deploy",
			wantPass: "s3cret",
		},
		{
			name:     "non-matching host gets no auth",
			url:      "https://other.example.com/some/asset",
			wantAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedReq *http.Request
			base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				capturedReq = req
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			})

			transport, err := newNetrcTransport(netrcPath, base)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			client := &http.Client{Transport: transport}
			req, _ := http.NewRequest(http.MethodHead, tt.url, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			resp.Body.Close()

			user, pass, ok := capturedReq.BasicAuth()
			if tt.wantAuth {
				if !ok {
					t.Error("expected Basic auth to be set")
				}
				if user != tt.wantUser {
					t.Errorf("user = %q, want %q", user, tt.wantUser)
				}
				if pass != tt.wantPass {
					t.Errorf("pass = %q, want %q", pass, tt.wantPass)
				}
			} else {
				if ok {
					t.Errorf("did not expect Basic auth, got user=%q", user)
				}
			}
		})
	}
}

func TestNetrcTransportExistingAuth(t *testing.T) {
	dir := t.TempDir()
	netrcPath := filepath.Join(dir, "netrc")
	if err := os.WriteFile(netrcPath, []byte("machine mirror.example.com login deploy password s3cret\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var capturedReq *http.Request
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		capturedReq = req
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})

	transport, err := newNetrcTransport(netrcPath, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	client := &http.Client{Transport: transport}
	req, _ := http.NewRequest(http.MethodHead, "https://mirror.example.com/asset", nil)
	req.Header.Set("Authorization", "Bearer existing-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()

	// Should preserve the existing Authorization header, not override.
	if got := capturedReq.Header.Get("Authorization"); got != "Bearer existing-token" {
		t.Errorf("Authorization = %q, want original Bearer token", got)
	}
}

func TestNetrcTransportDefault(t *testing.T) {
	dir := t.TempDir()
	netrcPath := filepath.Join(dir, "netrc")
	if err := os.WriteFile(netrcPath, []byte("default login fallback password fallpass\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var capturedReq *http.Request
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		capturedReq = req
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})

	transport, err := newNetrcTransport(netrcPath, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	client := &http.Client{Transport: transport}
	req, _ := http.NewRequest(http.MethodHead, "https://any-host.example.com/asset", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()

	user, pass, ok := capturedReq.BasicAuth()
	if !ok {
		t.Fatal("expected Basic auth from default entry")
	}
	if user != "fallback" || pass != "fallpass" {
		t.Errorf("got user=%q pass=%q, want fallback/fallpass", user, pass)
	}
}
