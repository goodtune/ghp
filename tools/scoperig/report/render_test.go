package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goodtune/ghp/tools/scoperig/redact"
)

var update = flag.Bool("update", false, "regenerate golden files")

func goldenReport() *Report {
	tree := testTree()
	res := testResults()
	for i := range res {
		switch res[i].Status {
		case StatusPass:
			res[i].Detail, res[i].HTTPStatus = "403 Token is not scoped to o/b", 403
			res[i].GHPMessage = "Token is not scoped to o/b"
		case StatusFail:
			res[i].Detail = "status: want 403, got 200"
		case StatusError:
			res[i].Detail, res[i].Error = "revoke call failed: ghp_abcdefghijklmn", "revoke call failed: ghp_abcdefghijklmn"
		case StatusKnown:
			res[i].KnownIssue, res[i].Detail = "https://github.com/goodtune/ghp/issues/290", "https://github.com/goodtune/ghp/issues/290"
		case StatusKnownFixed:
			res[i].KnownIssue = "https://github.com/goodtune/ghp/issues/291"
			res[i].Detail = "remove known_issue and observed: from " + res[i].ID
		case StatusKnownChanged:
			res[i].KnownIssue, res[i].Detail = "https://github.com/goodtune/ghp/issues/295", "observed status: want 200, got 502"
			res[i].GHExit = intp(1)
			res[i].FirstDeniedExchange = "POST /api/graphql 403 denied"
		case StatusGap:
			res[i].Detail = res[i].GapReason
		}
	}
	claims := RollUp(tree, res)
	r := &Report{RunID: "20261105T0412Z-7f3a", StartedAt: "2026-11-05T04:12:00Z", Instance: "ghp.example.test",
		GHPVersion: "0.23.0", GHVersion: "2.102.0", RigCommit: "abc1234", Claims: claims, Summary: Summarise(tree, claims)}
	r.Tokens.Created, r.Tokens.Revoked = 11, 11
	return r
}

func TestRender_Golden(t *testing.T) {
	r := goldenReport()
	for _, tc := range []struct {
		file  string
		write func(*Report, *bytes.Buffer) error
	}{
		{"report.golden.txt", func(r *Report, b *bytes.Buffer) error { return r.WriteTable(b) }},
		{"report.golden.json", func(r *Report, b *bytes.Buffer) error { return r.WriteJSON(b) }},
	} {
		t.Run(tc.file, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.write(r, &buf); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(buf.String(), "ghx_") || redact.Contains(buf.Bytes()) {
				t.Fatalf("output leaks a token:\n%s", buf.String())
			}
			path := filepath.Join("testdata", tc.file)
			if *update {
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("mismatch with %s (run with -update):\n%s", path, buf.String())
			}
		})
	}
}

func TestRender_Sections(t *testing.T) {
	var buf bytes.Buffer
	if err := goldenReport().WriteTable(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	changed := strings.Index(out, "changed (1):\n  C-CHG.a  KNOWN-CHANGED")
	table := strings.Index(out, "CLAIM ")
	if changed < 0 || table < 0 || changed > table {
		t.Errorf("changed section must come before the table:\n%s", out)
	}
	for _, s := range []string{"remove known_issue and observed: from C-FIXED.a", "coverage gaps (1): C-NONE", "manual: C-MAN", "untestable: C-NEV", "confidence: 2/(9-2) = 28.6%"} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q", s)
		}
	}
}
