package exec

import (
	"net/http"
	"net/http/httptest"
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
