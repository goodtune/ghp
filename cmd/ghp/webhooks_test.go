package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHelpOutput_Webhooks(t *testing.T) {
	cmd := newWebhooksCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	_ = cmd.Execute()
	for _, want := range []string{"status", "tail"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("expected %q in help:\n%s", want, buf.String())
		}
	}

	buf.Reset()
	cmd = newWebhooksCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"tail", "--help"})
	_ = cmd.Execute()
	for _, want := range []string{"--filter", "--from", "--durable", "--json", "--payload", "--count"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("expected %q in tail help:\n%s", want, buf.String())
		}
	}
}

func TestWebhooksStatusCmd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/webhooks/status" || r.Header.Get("Authorization") != "Bearer ghpr_test" {
			t.Errorf("unexpected request: %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"enabled":true,"ingress_path":"/webhooks/github","ingress_url":"https://x.ngrok.app/webhooks/github",
			"global_secret_configured":false,"ngrok":{"enabled":true,"connected":true,"url":"https://x.ngrok.app"},
			"nats":{"listen":"","stream":"GITHUB_WEBHOOKS","subject_prefix":"github.webhooks"},
			"stream":{"messages":3,"bytes":1200,"first_seq":1,"last_seq":3,"consumers":1,"max_age":"168h0m0s","max_bytes":1073741824},
			"apps":[{"id":"abc","name":"Bot","github_app_id":12,"has_webhook_secret":true}]}`)
	}))
	defer srv.Close()
	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "ghpr_test")
	t.Setenv("HOME", t.TempDir())

	cmd := newWebhooksCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"status"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, want := range []string{"https://x.ngrok.app/webhooks/github", "connected", "in-process only", "3 deliveries", "1 of 1 apps", "Bot (GitHub App 12"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("expected %q in output:\n%s", want, buf.String())
		}
	}

	buf.Reset()
	cmd = newWebhooksCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"status", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("status --json: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("expected JSON output, got %q: %v", buf.String(), err)
	}
}

func TestWebhooksStatusCmd_Disabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"enabled":false,"apps":[]}`)
	}))
	defer srv.Close()
	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "ghpr_test")
	t.Setenv("HOME", t.TempDir())

	cmd := newWebhooksCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"status"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "disabled") {
		t.Errorf("expected disabled notice, got %q", buf.String())
	}
}

func TestWebhooksTailCmd(t *testing.T) {
	var gotQuery, gotLastID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/webhooks/stream" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotQuery = r.URL.RawQuery
		gotLastID = r.Header.Get("Last-Event-ID")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "retry: 3000\n\n: connected\n\n")
		fmt.Fprint(w, ": ping\n\n")
		fmt.Fprint(w, "id: 7\nevent: pull_request\ndata: {\"subject\":\"github.webhooks.a.pull_request.opened.o.r\",\"sequence\":7,\"delivery\":\"d-7\",\"event\":\"pull_request\",\"action\":\"opened\",\"app_name\":\"Bot\",\"repository\":\"o/r\",\"sender\":\"octocat\",\"received_at\":\"2026-10-24T10:00:00Z\",\"payload\":{\"action\":\"opened\"}}\n\n")
		fmt.Fprint(w, "id: 8\nevent: push\ndata: {\"subject\":\"github.webhooks.a.push._.o.r\",\"sequence\":8,\"delivery\":\"d-8\",\"event\":\"push\",\"repository\":\"o/r\",\"received_at\":\"2026-10-24T10:00:01Z\",\"payload\":{\"ref\":\"refs/heads/main\"}}\n\n")
	}))
	defer srv.Close()
	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "ghpr_test")
	t.Setenv("HOME", t.TempDir())

	run := func(args ...string) string {
		cmd := newWebhooksCmd()
		buf := &bytes.Buffer{}
		cmd.SetOut(buf)
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(append([]string{"tail"}, args...))
		if err := cmd.Execute(); err != nil {
			t.Fatalf("tail %v: %v", args, err)
		}
		return buf.String()
	}

	out := run("--count", "2", "--filter", "github.webhooks.*.pull_request.>", "--from", "all", "--durable", "cli")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d:\n%s", len(lines), out)
	}
	if !strings.Contains(lines[0], "seq=7") || !strings.Contains(lines[0], "pull_request/opened") || !strings.Contains(lines[0], "o/r") || !strings.Contains(lines[0], "app=Bot") {
		t.Errorf("unexpected summary line: %q", lines[0])
	}
	for _, want := range []string{"filter=github.webhooks.%2A.pull_request.%3E", "from=all", "durable=cli"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("expected %q in query %q", want, gotQuery)
		}
	}
	if gotLastID != "" {
		t.Errorf("first connection should not send Last-Event-ID, got %q", gotLastID)
	}

	out = run("--count", "1", "--json")
	var env map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &env); err != nil {
		t.Fatalf("--json output not JSON: %q", out)
	}
	if env["delivery"] != "d-7" {
		t.Errorf("unexpected envelope: %v", env)
	}

	out = run("--count", "1", "--payload")
	if strings.TrimSpace(out) != `{"action":"opened"}` {
		t.Errorf("--payload output = %q", out)
	}
}

func TestWebhooksTailCmd_Reconnects(t *testing.T) {
	var conns int
	var lastIDs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conns++
		lastIDs = append(lastIDs, r.Header.Get("Last-Event-ID"))
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if conns == 1 {
			fmt.Fprint(w, "id: 3\nevent: push\ndata: {\"sequence\":3,\"delivery\":\"d-3\",\"event\":\"push\"}\n\n")
			return // server closes: client should reconnect with Last-Event-ID: 3
		}
		fmt.Fprint(w, "id: 4\nevent: push\ndata: {\"sequence\":4,\"delivery\":\"d-4\",\"event\":\"push\"}\n\n")
	}))
	defer srv.Close()
	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "ghpr_test")
	t.Setenv("HOME", t.TempDir())

	cmd := newWebhooksCmd()
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{"tail", "--count", "2"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("tail: %v", err)
	}
	if conns != 2 || len(lastIDs) != 2 || lastIDs[0] != "" || lastIDs[1] != "3" {
		t.Errorf("expected reconnect with Last-Event-ID 3; conns=%d lastIDs=%v", conns, lastIDs)
	}
	if !strings.Contains(buf.String(), "seq=3") || !strings.Contains(buf.String(), "seq=4") {
		t.Errorf("unexpected output:\n%s", buf.String())
	}
	if !strings.Contains(errBuf.String(), "reconnecting") {
		t.Errorf("expected reconnect notice on stderr, got %q", errBuf.String())
	}
}

func TestWebhooksTailCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Webhooks are not enabled on this server"}`)
	}))
	defer srv.Close()
	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "ghpr_test")
	t.Setenv("HOME", t.TempDir())

	cmd := newWebhooksCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"tail"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("expected not-enabled error, got %v", err)
	}

	cmd = newWebhooksCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"tail", "--from", "yesterday"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--from") {
		t.Errorf("expected --from validation error, got %v", err)
	}
}
