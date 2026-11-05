//go:build scoperig_live

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLive runs the full rig against GHP_SERVER_URL through the same CLI
// path as `scoperig run`. It skips when GHP_SERVER_URL or GHP_USER_TOKEN is
// not set, so `go test -tags scoperig_live` is safe without credentials.
//
// Exit codes 0 (all PASS) and 1 (a scenario FAIL) are reported results and logged; 2
// (ERROR or cleanup failure) and 3 (could not start) fail the test.
func TestLive(t *testing.T) {
	server, token := os.Getenv("GHP_SERVER_URL"), os.Getenv("GHP_USER_TOKEN")
	if server == "" || token == "" {
		t.Skip("GHP_SERVER_URL and GHP_USER_TOKEN must be set to run the live rig")
	}
	t.Chdir(filepath.Join("..", "..")) // rig/ is resolved from the repo root

	out := filepath.Join(t.TempDir(), "run.json")
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd(&stdout, &stderr, os.Getenv, runDeps{})
	cmd.SetArgs([]string{"run", "--out", out})
	code := exitCode(cmd.ExecuteContext(t.Context()), &stderr)

	reportJSON, readErr := os.ReadFile(out)
	if readErr != nil && code < 2 {
		t.Errorf("report %s not written: %v", out, readErr)
	}
	for name, s := range map[string]string{
		"stdout": stdout.String(), "stderr": stderr.String(), "report": string(reportJSON),
	} {
		if strings.Contains(s, token) {
			t.Errorf("user token appears in %s", name)
		}
	}
	redact := func(s string) string { return strings.ReplaceAll(s, token, "[REDACTED]") }
	t.Logf("scoperig run exit code %d\n%s", code, redact(stdout.String()))
	if code >= 2 {
		t.Fatalf("scoperig run exit code %d (ERROR or could not start): %s", code, redact(stderr.String()))
	}
	if code == 1 {
		t.Log("scoperig run reported scenario FAILs (exit 1); see the table above")
	}
}
