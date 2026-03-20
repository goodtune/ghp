package gitcache

import "testing"

func TestParseGitPath(t *testing.T) {
	tests := []struct {
		path      string
		wantOwner string
		wantRepo  string
		wantGit   string
	}{
		{"/owner/repo.git/info/refs", "owner", "repo", "info/refs"},
		{"/owner/repo.git/git-upload-pack", "owner", "repo", "git-upload-pack"},
		{"/owner/repo.git/git-receive-pack", "owner", "repo", "git-receive-pack"},
		{"/owner/repo/info/refs", "owner", "repo", "info/refs"},
		{"/owner/repo/git-upload-pack", "owner", "repo", "git-upload-pack"},
		// Non-git paths.
		{"/owner/repo", "", "", ""},
		{"/owner/repo/tree/main", "", "", ""},
		{"/", "", "", ""},
		{"/owner", "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			owner, repo, gitPath := parseGitPath(tc.path)
			if owner != tc.wantOwner {
				t.Errorf("owner = %q, want %q", owner, tc.wantOwner)
			}
			if repo != tc.wantRepo {
				t.Errorf("repo = %q, want %q", repo, tc.wantRepo)
			}
			if gitPath != tc.wantGit {
				t.Errorf("gitPath = %q, want %q", gitPath, tc.wantGit)
			}
		})
	}
}
