package exec

import (
	"strings"
	"testing"

	"github.com/goodtune/ghp/tools/scoperig/expect"
	"github.com/goodtune/ghp/tools/scoperig/ghdebug"
)

func parseCapture(t *testing.T, s string) []ghdebug.Exchange {
	t.Helper()
	ex, err := ghdebug.Parse(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return ex
}

func TestGHExchangesIdempotent(t *testing.T) {
	const query = "* Request at x\n* Request to https://h/api/graphql\n> POST /api/graphql HTTP/1.1\n\nGraphQL query:\nquery { viewer { login } }\nGraphQL variables: {}\n\n"
	for _, tc := range []struct {
		name, capture string
		want          bool
	}{
		{"get", "* Request at x\n* Request to https://h/a\n> GET /a HTTP/1.1\n\n", true},
		{"graphql query post", query, true},
		{"no exchanges", "", false},
		{"interleaved mutation block", "* Request at x\n* Request to https://h/a\n> GET /a HTTP/1.1\n\n< HTTP/2.0 200 OK\n\nGraphQL query:\nmutation { addStar(input:{starrableId:\"x\"}) { clientMutationId } }\n", false},
		{"two request lines in one exchange", "* Request at x\n* Request to https://h/a\n> GET /a HTTP/1.1\n> POST /repos/o/r/issues HTTP/1.1\n\n", false},
		{"graphql body on GET", "* Request at x\n* Request to https://h/api/graphql\n> GET /api/graphql HTTP/1.1\n\nGraphQL query:\nquery { a }\nGraphQL variables: {}\n\n", false},
		{"graphql mutation post", strings.Replace(query, "query { viewer { login } }", "mutation { addStar(input:{starrableId:\"x\"}) { clientMutationId } }", 1), false},
		{"rest post", "* Request at x\n* Request to https://h/a\n> POST /repos/o/r/issues HTTP/1.1\n\n{}\n\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ghExchangesIdempotent(parseCapture(t, tc.capture)); got != tc.want {
				t.Errorf("ghExchangesIdempotent = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGHRetryable_Truncated(t *testing.T) {
	ex := parseCapture(t, "* Request at x\n* Request to https://h/a\n> GET /a HTTP/1.1\n\n")
	if !ghRetryable(&expect.Observation{Exchanges: ex}) {
		t.Fatal("complete GET capture should be retryable")
	}
	if ghRetryable(&expect.Observation{Exchanges: ex, GHStderrTruncated: true}) {
		t.Error("truncated capture must not be retryable")
	}
	w := &capWriter{max: 4}
	_, _ = w.Write([]byte("abc"))
	if w.truncated {
		t.Error("truncated before the cap")
	}
	_, _ = w.Write([]byte("de"))
	if !w.truncated || w.buf.String() != "abcd" {
		t.Errorf("truncated=%v buf=%q", w.truncated, w.buf.String())
	}
}
