package proxy

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// netrcEntry holds credentials for a single machine in a netrc file.
type netrcEntry struct {
	Login    string
	Password string
}

// parseNetrc reads a netrc-format file and returns a map of machine -> credentials.
// It supports the standard tokens: machine, login, password, and default.
// The "default" keyword matches any host not explicitly listed.
func parseNetrc(path string) (map[string]netrcEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening netrc file: %w", err)
	}
	defer f.Close()

	entries := make(map[string]netrcEntry)
	scanner := bufio.NewScanner(f)

	var currentKey string // hostname, or "" for the default entry
	var current netrcEntry
	inEntry := false
	inMacdef := false // true while consuming lines of a macdef body

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if inMacdef {
			// macdef bodies terminate at a blank line.
			if trimmed == "" {
				inMacdef = false
			}
			continue
		}

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		tokens := strings.Fields(trimmed)
	tokenLoop:
		for i := 0; i < len(tokens); i++ {
			switch tokens[i] {
			case "machine":
				// Save previous entry if any.
				if inEntry {
					entries[currentKey] = current
				}
				i++
				if i >= len(tokens) {
					return nil, fmt.Errorf("netrc: machine keyword without value")
				}
				currentKey = strings.ToLower(tokens[i])
				current = netrcEntry{}
				inEntry = true
			case "default":
				if inEntry {
					entries[currentKey] = current
				}
				// Default entry is stored with empty-string key.
				currentKey = ""
				current = netrcEntry{}
				inEntry = true
			case "login":
				if !inEntry {
					return nil, fmt.Errorf("netrc: login keyword before machine or default")
				}
				i++
				if i >= len(tokens) {
					return nil, fmt.Errorf("netrc: login keyword without value")
				}
				current.Login = tokens[i]
			case "password":
				if !inEntry {
					return nil, fmt.Errorf("netrc: password keyword before machine or default")
				}
				i++
				if i >= len(tokens) {
					return nil, fmt.Errorf("netrc: password keyword without value")
				}
				current.Password = tokens[i]
			case "account":
				// account is a standard netrc token we don't use; skip its value if present.
				if i+1 < len(tokens) {
					i++
				}
			case "macdef":
				// macdef starts a named multi-line macro that terminates at a blank line.
				// Skip the macro name if present on the same line, then consume the body
				// at the outer scanner loop level to avoid misinterpreting macro content
				// as credential tokens.
				if i+1 < len(tokens) {
					i++
				}
				inMacdef = true
				break tokenLoop
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading netrc file: %w", err)
	}

	// Save last entry.
	if inEntry {
		entries[currentKey] = current
	}

	return entries, nil
}

// netrcTransport is an http.RoundTripper that adds Basic auth credentials
// from a netrc file, matched by the request hostname.
type netrcTransport struct {
	entries map[string]netrcEntry
	base    http.RoundTripper
}

// newNetrcTransport creates a RoundTripper that injects Basic auth from a
// netrc file. If base is nil, http.DefaultTransport is used.
func newNetrcTransport(netrcPath string, base http.RoundTripper) (*netrcTransport, error) {
	entries, err := parseNetrc(netrcPath)
	if err != nil {
		return nil, err
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return &netrcTransport{entries: entries, base: base}, nil
}

func (t *netrcTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only inject credentials when the request doesn't already have auth and
	// the scheme is https (to prevent sending credentials in cleartext).
	if _, _, ok := req.BasicAuth(); !ok && req.Header.Get("Authorization") == "" && req.URL.Scheme == "https" {
		host := strings.ToLower(req.URL.Hostname())
		entry, found := t.entries[host]
		if !found {
			// Try the default entry (empty-string key).
			entry, found = t.entries[""]
		}
		if found && entry.Login != "" {
			// Clone the request to avoid mutating the caller's request.
			r2 := req.Clone(req.Context())
			r2.SetBasicAuth(entry.Login, entry.Password)
			return t.base.RoundTrip(r2)
		}
	}
	return t.base.RoundTrip(req)
}
