package tokens

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestHandle_NeverFormatsValue(t *testing.T) {
	h := Handle{id: "id-1", value: "ghx_secret0000"}
	checks := map[string]string{
		"fmt": fmt.Sprintf("%v %+v %#v %s", h, h, h, h),
	}
	j, err := json.Marshal(struct{ H Handle }{h})
	if err != nil {
		t.Fatal(err)
	}
	checks["json"] = string(j)
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "h", h)
	checks["slog"] = buf.String()
	for name, s := range checks {
		t.Run(name, func(t *testing.T) {
			if strings.Contains(s, "ghx_secret") {
				t.Fatalf("value leaked: %s", s)
			}
			if !strings.Contains(s, "ghx_[REDACTED:id-1]") {
				t.Fatalf("missing placeholder: %s", s)
			}
		})
	}
	if h.ID() != "id-1" {
		t.Fatalf("ID = %q", h.ID())
	}
}

func TestHandle_AuthorizeAndEnv(t *testing.T) {
	h := Handle{id: "id-1", value: "ghx_test0000"}
	r, _ := http.NewRequest("GET", "http://x", nil)
	h.Authorize(r)
	if got := r.Header.Get("Authorization"); got != "token ghx_test0000" {
		t.Fatalf("Authorization = %q", got)
	}
	env := h.GHEnv()
	if len(env) != 1 || env[0] != "GH_ENTERPRISE_TOKEN=ghx_test0000" {
		t.Fatalf("GHEnv = %v", env)
	}
}
