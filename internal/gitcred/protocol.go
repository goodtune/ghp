// Package gitcred implements the ghp git credential helper.
package gitcred

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// maxRequestBytes bounds the credential request read from git.
const maxRequestBytes = 64 << 10

var (
	errRequestTooLarge = errors.New("credential request larger than 64 KiB")
	errNoEquals        = errors.New(`invalid credential line (no "=")`)
	errNULInKey        = errors.New("invalid credential line (NUL in key)")
)

// Request is the subset of a git credential request the helper uses.
type Request struct{ Protocol, Host, Path, Username, Password string }

// Credential is the answer written back to git.
type Credential struct {
	Username string
	Password string
	Expiry   time.Time // zero → no password_expiry_utc line
}

// redacted stands in for a non-empty password whenever a value is formatted.
const redacted = "<redacted>"

func redact(s string) string {
	if s == "" {
		return ""
	}
	return redacted
}

// String renders r with the password redacted, so %v and %+v never print it.
func (r Request) String() string {
	return fmt.Sprintf("{Protocol:%s Host:%s Path:%s Username:%s Password:%s}",
		r.Protocol, r.Host, r.Path, r.Username, redact(r.Password))
}

// GoString renders r with the password redacted, so %#v never prints it.
func (r Request) GoString() string {
	return fmt.Sprintf("gitcred.Request{Protocol:%q, Host:%q, Path:%q, Username:%q, Password:%q}",
		r.Protocol, r.Host, r.Path, r.Username, redact(r.Password))
}

// String renders c with the password redacted, so %v and %+v never print it.
func (c Credential) String() string {
	return fmt.Sprintf("{Username:%s Password:%s Expiry:%s}",
		c.Username, redact(c.Password), c.Expiry)
}

// GoString renders c with the password redacted, so %#v never prints it.
func (c Credential) GoString() string {
	return fmt.Sprintf("gitcred.Credential{Username:%q, Password:%q, Expiry:%#v}",
		c.Username, redact(c.Password), c.Expiry)
}

// ParseRequest reads a git credential request: key=value lines up to the
// first blank line or EOF, at most 64 KiB. A trailing "\r" is stripped from
// each line; a value still containing "\r" or NUL is rejected. Keys ending in "[]" and unknown keys are ignored; for repeated
// keys the last value wins. Error texts name keys only, never values.
func ParseRequest(r io.Reader) (Request, error) {
	var req Request
	// Read one byte past the limit so an oversize request is detected rather
	// than silently truncated. Bytes are counted per line consumed, so input
	// that follows the terminating blank line never counts against the limit.
	br := bufio.NewReader(io.LimitReader(r, maxRequestBytes+1))
	consumed := 0
	for {
		line, err := br.ReadString('\n')
		consumed += len(line)
		if consumed > maxRequestBytes {
			return Request{}, errRequestTooLarge
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return Request{}, fmt.Errorf("reading credential request: %w", err)
		}
		atEOF := err != nil
		if line == "" && atEOF {
			break
		}
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Request{}, errNoEquals
		}
		if strings.IndexByte(key, 0) >= 0 {
			return Request{}, errNULInKey
		}
		// Only one trailing "\r" is stripped above; any "\r" left in the
		// value is rejected, as is NUL.
		if strings.ContainsAny(value, "\x00\r") {
			return Request{}, fmt.Errorf("invalid value for key %q", key)
		}
		switch key {
		case "protocol":
			req.Protocol = value
		case "host":
			req.Host = value
		case "path":
			req.Path = value
		case "username":
			req.Username = value
		case "password":
			req.Password = value
		}
		if atEOF {
			break
		}
	}
	return req, nil
}

// WriteCredential writes c to w as git credential output. Every value is
// checked before anything is written: a value containing "\n", "\r" or NUL
// could inject extra keys, so it is rejected and w is left untouched.
func WriteCredential(w io.Writer, c Credential) error {
	fields := []struct{ key, value string }{
		{"username", c.Username},
		{"password", c.Password},
	}
	if !c.Expiry.IsZero() {
		fields = append(fields, struct{ key, value string }{"password_expiry_utc", strconv.FormatInt(c.Expiry.Unix(), 10)})
	}
	var b strings.Builder
	for _, f := range fields {
		if strings.ContainsAny(f.value, "\n\r\x00") {
			return fmt.Errorf("invalid value for key %q", f.key)
		}
		b.WriteString(f.key)
		b.WriteByte('=')
		b.WriteString(f.value)
		b.WriteByte('\n')
	}
	_, err := io.WriteString(w, b.String())
	return err
}
