package exec

import (
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"testing"
)

func TestUserAgent(t *testing.T) {
	if got := UserAgent("v1.2.3", "20261107T0137Z-75ec"); got != "ghp-scoperig/v1.2.3 (run=20261107T0137Z-75ec)" {
		t.Errorf("UserAgent = %q", got)
	}
	if got := UserAgent("", "r"); got != "ghp-scoperig/dev (run=r)" {
		t.Errorf("UserAgent empty version = %q", got)
	}
	if RigVersion() == "" {
		t.Error("RigVersion is empty")
	}
}

func TestWithUserAgent(t *testing.T) {
	var got []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("User-Agent"))
	}))
	defer ts.Close()
	base := ts.Client()
	c := WithUserAgent(base, "ua-1")
	// Re-wrapping replaces the agent rather than stacking wrappers.
	c = WithUserAgent(c, "ua-2")
	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "caller")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(got) != 1 || got[0] != "ua-2" {
		t.Errorf("server saw %v, want [ua-2]", got)
	}
	if req.Header.Get("User-Agent") != "caller" {
		t.Error("caller's request was mutated")
	}
	if UserAgentOf(c) != "ua-2" || UserAgentOf(base) != "" {
		t.Errorf("UserAgentOf = %q / %q", UserAgentOf(c), UserAgentOf(base))
	}
	if BaseTransport(c.Transport) != base.Transport {
		t.Error("BaseTransport did not unwrap to the original transport")
	}
	if BaseTransport(nil) != http.DefaultTransport {
		t.Error("BaseTransport(nil) is not the default transport")
	}
	if base.Transport == c.Transport {
		t.Error("WithUserAgent modified the original client")
	}
}

func TestRigVersionAndCommit(t *testing.T) {
	const sha = "d8f3b9de0123456789abcdef0123456789abcdef"
	parent := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.0.0-20261030203245-63f1a39c0404+dirty"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "63f1a39c0404aaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	devel := &debug.BuildInfo{
		Main:     debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: sha}},
	}
	tests := []struct {
		name        string
		stamp       string
		bi          *debug.BuildInfo
		ok          bool
		wantVersion string
		wantCommit  string
	}{
		{"stamp wins over parent checkout VCS info", sha, parent, true, "d8f3b9de0123", sha},
		{"dirty stamp keeps suffix", sha + "-dirty", parent, true, "d8f3b9de0123-dirty", sha + "-dirty"},
		{"no stamp falls back to module version and VCS", "", parent, true, "v0.0.0-20261030203245-63f1a39c0404+dirty", "63f1a39c0404aaaaaaaaaaaaaaaaaaaaaaaaaaaa-dirty"},
		{"no stamp devel uses short revision", "", devel, true, "d8f3b9de0123", sha},
		{"no stamp no build info", "", nil, false, "dev", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rigVersion(tt.stamp, tt.bi, tt.ok); got != tt.wantVersion {
				t.Errorf("rigVersion = %q, want %q", got, tt.wantVersion)
			}
			if got := rigCommit(tt.stamp, tt.bi, tt.ok); got != tt.wantCommit {
				t.Errorf("rigCommit = %q, want %q", got, tt.wantCommit)
			}
		})
	}
}
