// Command fakegh stands in for the GitHub CLI in exec tests. It prints its
// working directory, argv and environment to stdout (the token value only as
// its length), writes a GH_DEBUG=api style capture with one 403 exchange to
// stderr, and exits 1. The token it was given is echoed in the debug
// capture's Authorization header, response body and error line, so tests
// can prove that the executor redacts it.
//
// Modes (first argument):
//
//	sleep         sleep for a minute first
//	spawn <file>  start a sleeping child, write its pid to file, then sleep
//	nottook       the request has no "* Request took" line before gh's error
//	between       gh prints a message between two requests
package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

func exchange(tok string, took bool) string {
	s := `* Request at 2026-11-05 12:00:00.000000 +1100 AEDT m=+0.010000000
* Request to https://ghp.example/api/v3/repos/a-owner/a-repo/pulls/2
> GET /api/v3/repos/a-owner/a-repo/pulls/2 HTTP/1.1
> Host: ghp.example
> Authorization: token ` + tok + `
> User-Agent: GitHub CLI 2.102.0

< HTTP/2.0 403 Forbidden
< Content-Type: application/json; charset=utf-8

{"message":"token not scoped","echo":"` + tok + `"}

`
	if took {
		s += "* Request took 10.0ms\n"
	}
	return s
}

const gqlExchange = `* Request at 2026-11-05 12:00:01.000000 +1100 AEDT m=+0.020000000
* Request to https://ghp.example/api/graphql
> POST /api/graphql HTTP/1.1
> Host: ghp.example

GraphQL query:
query Q { viewer { login } }
GraphQL variables: {}

< HTTP/2.0 200 OK
< Content-Type: application/json

{
  "data": {"viewer": {"login": "x"}}
}

* Request took 5.0ms
`

func main() {
	mode := ""
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "sleep":
		time.Sleep(time.Minute)
	case "spawn":
		c := exec.Command("sleep", "60")
		if err := c.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		_ = os.WriteFile(os.Args[2], []byte(fmt.Sprint(c.Process.Pid)), 0o600)
		time.Sleep(time.Minute)
	}
	wd, _ := os.Getwd()
	fmt.Printf("CWD=%s\n", wd)
	fmt.Printf("ARGS=%s\n", strings.Join(os.Args[1:], " "))
	env := os.Environ()
	sort.Strings(env)
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if k == "GH_ENTERPRISE_TOKEN" {
			v = fmt.Sprintf("len=%d", len(v))
		}
		fmt.Printf("ENV %s=%s\n", k, v)
	}
	tok := os.Getenv("GH_ENTERPRISE_TOKEN")
	switch mode {
	case "nottook":
		fmt.Fprint(os.Stderr, exchange(tok, false))
		fmt.Fprint(os.Stderr, "error: no took line marker\n")
	case "between":
		fmt.Fprint(os.Stderr, gqlExchange)
		fmt.Fprint(os.Stderr, "warning: between requests marker\n")
		fmt.Fprint(os.Stderr, exchange(tok, true))
	default:
		fmt.Fprint(os.Stderr, exchange(tok, true))
	}
	fmt.Fprintf(os.Stderr, "HTTP 403: token not scoped (%s)\n", tok)
	os.Exit(1)
}
