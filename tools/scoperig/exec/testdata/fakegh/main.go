// Command fakegh stands in for the GitHub CLI in exec tests. It prints its
// working directory, argv and environment to stdout (the token value only as
// its length), writes a GH_DEBUG=api style capture with one 403 exchange to
// stderr, and exits 1. If the first argument is "sleep" it sleeps for a
// minute first.
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "sleep" {
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
	fmt.Fprint(os.Stderr, `* Request at 2026-11-05 12:00:00.000000 +1100 AEDT m=+0.010000000
* Request to https://ghp.example/api/v3/repos/a-owner/a-repo/pulls/2
> GET /api/v3/repos/a-owner/a-repo/pulls/2 HTTP/1.1
> Host: ghp.example
> Authorization: token ghx_test0000fakevalue
> User-Agent: GitHub CLI 2.102.0

< HTTP/2.0 403 Forbidden
< Content-Type: application/json; charset=utf-8

{"message":"token not scoped","echo":"ghx_test0000fakevalue"}

* Request took 10.0ms
HTTP 403: token not scoped (ghx_test0000fakevalue)
`)
	os.Exit(1)
}
