package gitcred

import (
	"errors"
	"testing"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name     string
		req      Request
		want     Target
		fullName string
		wantErr  error
	}{
		{name: "plain", req: Request{Protocol: "https", Path: "goodtune/ghp.git"}, want: Target{"goodtune", "ghp"}, fullName: "goodtune/ghp"},
		{name: "leading slash", req: Request{Protocol: "https", Path: "/goodtune/ghp.git"}, want: Target{"goodtune", "ghp"}, fullName: "goodtune/ghp"},
		{name: "no .git suffix", req: Request{Protocol: "https", Path: "goodtune/ghp"}, want: Target{"goodtune", "ghp"}, fullName: "goodtune/ghp"},
		{name: "trailing segments", req: Request{Protocol: "https", Path: "goodtune/ghp.git/info/refs"}, want: Target{"goodtune", "ghp"}, fullName: "goodtune/ghp"},
		{name: "case preserved", req: Request{Protocol: "https", Path: "GoodTune/GHP.git"}, want: Target{"GoodTune", "GHP"}, fullName: "GoodTune/GHP"},
		{name: "only one .git stripped", req: Request{Protocol: "https", Path: "goodtune/x.git.git"}, want: Target{"goodtune", "x.git"}, fullName: "goodtune/x.git"},
		{name: "dots and dashes", req: Request{Protocol: "https", Path: "my-org/repo_name.v2"}, want: Target{"my-org", "repo_name.v2"}, fullName: "my-org/repo_name.v2"},
		{name: "http", req: Request{Protocol: "http", Path: "goodtune/ghp.git"}, wantErr: ErrNotHTTPS},
		{name: "empty protocol", req: Request{Path: "goodtune/ghp.git"}, wantErr: ErrNotHTTPS},
		{name: "empty path", req: Request{Protocol: "https", Path: ""}, wantErr: ErrNoPath},
		{name: "owner only", req: Request{Protocol: "https", Path: "goodtune"}, wantErr: ErrNoPath},
		{name: "slash only", req: Request{Protocol: "https", Path: "/"}, wantErr: ErrNoPath},
		{name: "empty repo after .git", req: Request{Protocol: "https", Path: "goodtune/.git"}, wantErr: ErrBadPath},
		{name: "dot dot owner", req: Request{Protocol: "https", Path: "../x.git"}, wantErr: ErrBadPath},
		{name: "dot owner", req: Request{Protocol: "https", Path: "./x.git"}, wantErr: ErrBadPath},
		{name: "dot dot repo", req: Request{Protocol: "https", Path: "goodtune/.."}, wantErr: ErrBadPath},
		{name: "dot repo after .git", req: Request{Protocol: "https", Path: "goodtune/..git"}, wantErr: ErrBadPath},
		{name: "encoded slash", req: Request{Protocol: "https", Path: "own%2Fer/repo.git"}, wantErr: ErrBadPath},
		{name: "space", req: Request{Protocol: "https", Path: "own er/repo.git"}, wantErr: ErrBadPath},
		{name: "empty owner", req: Request{Protocol: "https", Path: "//goodtune/ghp.git"}, wantErr: ErrBadPath},
		{name: "empty repo", req: Request{Protocol: "https", Path: "goodtune//ghp.git"}, wantErr: ErrBadPath},
		{name: "backslash", req: Request{Protocol: "https", Path: `goodtune/..\x`}, wantErr: ErrBadPath},
		{name: "non-ascii", req: Request{Protocol: "https", Path: "goodtune/ſecret"}, wantErr: ErrBadPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTarget(tt.req)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseTarget() error = %v, want %v", err, tt.wantErr)
				}
				if got != (Target{}) {
					t.Errorf("ParseTarget() = %+v on error, want zero Target", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ParseTarget() = %+v, want %+v", got, tt.want)
			}
			if got.FullName() != tt.fullName {
				t.Errorf("FullName() = %q, want %q", got.FullName(), tt.fullName)
			}
		})
	}
}
