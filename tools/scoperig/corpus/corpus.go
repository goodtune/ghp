// Package corpus builds the checked-in gh request corpus (rig/corpus/gh/...)
// from GH_DEBUG=api captures. Only the request side is kept: REST method and
// path with placeholders, and sanitised GraphQL query, variables and
// operation name. Response bodies are never written.
package corpus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/goodtune/ghp/tools/scoperig/ghdebug"
	"github.com/goodtune/ghp/tools/scoperig/redact"
)

// Profiles are the token profiles every GraphQL entry carries an expectation for.
var Profiles = []string{"open", "perm-ro", "repo"}

// File is one corpus file: the requests one gh command makes.
type File struct {
	GHVersion string   `json:"gh_version"`
	Command   string   `json:"command"`
	REST      []string `json:"rest"`
	GraphQL   []Entry  `json:"graphql"`
	// SkippedInterleaved lists exchanges left out because gh's debug output
	// for them overlapped another request ("METHOD /path [operation]").
	SkippedInterleaved []string `json:"skipped_interleaved,omitempty"`
}

// Entry is one GraphQL request and its expected verdict per profile.
type Entry struct {
	Operation string                 `json:"operation"`
	Body      Body                   `json:"body"`
	Expect    map[string]Expectation `json:"expect"`
}

// Body is the GraphQL request body as sent to /graphql.
type Body struct {
	Query         string         `json:"query"`
	Variables     map[string]any `json:"variables"`
	OperationName string         `json:"operationName,omitempty"`
}

// Expectation is the expected verdict for one profile.
type Expectation struct {
	Verdict    string `json:"verdict"`
	KnownIssue string `json:"known_issue,omitempty"`
	Current    string `json:"current,omitempty"`
}

var numberedParents = map[string]bool{"pulls": true, "issues": true, "releases": true}

// Build makes the corpus file for one command. owner and repo are the real
// repository the capture was taken against; they are replaced with OWNER and
// REPO, and Build fails if either survives. When prev has an entry with the
// same operation, its expectations are kept; otherwise every profile is
// "allow".
func Build(version, command, owner, repo string, ex []ghdebug.Exchange, prev *File) (File, error) {
	f := File{GHVersion: version, Command: command, REST: make([]string, 0), GraphQL: make([]Entry, 0)}
	ident := identPattern(owner, repo)
	seenREST := map[string]bool{}
	seenGQL := map[string]bool{}
	for _, e := range ex {
		path := e.Path
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		if e.Interleaved {
			s := e.Method + " " + placeholderPath(path, owner, repo)
			if e.GraphQL != nil && e.GraphQL.OperationName != "" {
				s += " " + e.GraphQL.OperationName
			}
			f.SkippedInterleaved = append(f.SkippedInterleaved, s)
			continue
		}
		if e.GraphQL == nil {
			s := e.Method + " " + placeholderPath(path, owner, repo)
			if ident != nil && ident.MatchString(s) {
				return File{}, fmt.Errorf("corpus: owner or repo remains in REST path %q", s)
			}
			if !seenREST[s] {
				seenREST[s] = true
				f.REST = append(f.REST, s)
			}
			continue
		}
		g, err := ghdebug.Sanitise(*e.GraphQL, owner, repo)
		if err != nil {
			return File{}, err
		}
		if g.Variables == nil {
			g.Variables = map[string]any{}
		}
		op := g.OperationName
		if op == "" {
			op = "(anonymous)"
		}
		ent := Entry{Operation: op, Body: Body{Query: g.Query, Variables: g.Variables, OperationName: g.OperationName}}
		key, err := json.Marshal(ent.Body)
		if err != nil {
			return File{}, err
		}
		if seenGQL[string(key)] {
			continue
		}
		seenGQL[string(key)] = true
		ent.Expect = expectFor(op, prev)
		f.GraphQL = append(f.GraphQL, ent)
	}
	return f, nil
}

func expectFor(op string, prev *File) map[string]Expectation {
	if prev != nil {
		for _, p := range prev.GraphQL {
			if p.Operation == op && p.Expect != nil {
				out := make(map[string]Expectation, len(p.Expect))
				for k, v := range p.Expect {
					out[k] = v
				}
				return out
			}
		}
	}
	out := make(map[string]Expectation, len(Profiles))
	for _, p := range Profiles {
		out[p] = Expectation{Verdict: "allow"}
	}
	return out
}

// placeholderPath replaces the owner and repo after /repos/, any other
// segment equal to the owner, and numeric ids after pulls|issues|releases.
func placeholderPath(path, owner, repo string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		switch {
		case i >= 2 && segs[i-1] == "repos" && strings.EqualFold(s, owner):
			segs[i] = "OWNER"
		case i >= 3 && segs[i-2] == "repos" && strings.EqualFold(s, repo):
			segs[i] = "REPO"
		case i >= 1 && numberedParents[segs[i-1]] && isNumber(s):
			segs[i] = "1"
		case owner != "" && strings.EqualFold(s, owner):
			segs[i] = "OWNER"
		}
	}
	return strings.Join(segs, "/")
}

func isNumber(s string) bool {
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}

func identPattern(owner, repo string) *regexp.Regexp {
	var alts []string
	for _, s := range []string{owner, repo} {
		if s != "" {
			alts = append(alts, regexp.QuoteMeta(s))
		}
	}
	if len(alts) == 0 {
		return nil
	}
	return regexp.MustCompile(`(?i)(^|[^a-z0-9_])(` + strings.Join(alts, "|") + `)($|[^a-z0-9_])`)
}

// Marshal encodes f with two-space indentation and a trailing newline. Map
// keys are sorted by encoding/json, so output is deterministic. It refuses to
// return output that contains a token-shaped string.
func Marshal(f File) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	if redact.Contains(buf.Bytes()) {
		return nil, fmt.Errorf("corpus: token-shaped string in output for %q", f.Command)
	}
	return buf.Bytes(), nil
}
