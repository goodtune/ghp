// Package ghdebug parses the request/response log that the GitHub CLI writes
// to stderr when GH_DEBUG=api is set. All retained headers and bodies pass
// through the redact package.
package ghdebug

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/goodtune/ghp/tools/scoperig/redact"
)

// maxBody caps the retained response body size.
const maxBody = 64 * 1024

// Exchange is one request/response pair from a GH_DEBUG=api capture.
type Exchange struct {
	Method, URL, Path string          // Path is the URL path, e.g. "/graphql"
	RequestHeaders    http.Header     // redacted
	GraphQL           *GraphQLRequest // non-nil for GraphQL requests
	Status            int             // from "< HTTP/2.0 200 OK"; 0 if none
	ResponseBody      string          // redacted, capped at 64 KiB
}

// GraphQLRequest is the query, variables and operation name of a GraphQL call.
type GraphQLRequest struct {
	Query         string
	Variables     map[string]any // decoded with json.Decoder.UseNumber()
	OperationName string         // "" if anonymous
}

var opName = regexp.MustCompile(`(?m)^\s*(?:query|mutation|subscription)\s+([_A-Za-z][_0-9A-Za-z]*)`)

type section int

const (
	secNone section = iota
	secReqHeaders
	secReqBody
	secGraphQL
	secRespHeaders
	secRespBody
)

type builder struct {
	ex       Exchange
	sec      section
	reqLine  bool
	respLine bool
	reqBody  strings.Builder
	query    strings.Builder
	vars     string
	gqlBlock bool
	body     strings.Builder
}

// Parse reads a GH_DEBUG=api capture and returns its exchanges in order.
func Parse(r io.Reader) ([]Exchange, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []Exchange
	var b *builder
	flush := func() error {
		if b == nil {
			return nil
		}
		ex, err := b.finish()
		if err != nil {
			return err
		}
		out = append(out, ex)
		b = nil
		return nil
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "* Request at "):
			if err := flush(); err != nil {
				return nil, err
			}
			b = &builder{ex: Exchange{RequestHeaders: http.Header{}}}
			continue
		case b == nil:
			continue
		case strings.HasPrefix(line, "* Request to "):
			b.ex.URL = strings.TrimSpace(strings.TrimPrefix(line, "* Request to "))
			if u, err := url.Parse(b.ex.URL); err == nil {
				b.ex.Path = u.Path
			}
			continue
		case strings.HasPrefix(line, "* Request took "):
			continue
		}
		if b.sec == secGraphQL {
			if v, ok := strings.CutPrefix(line, "GraphQL variables: "); ok {
				b.vars = v
				b.sec = secReqBody
			} else {
				b.query.WriteString(line)
				b.query.WriteByte('\n')
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "> ") && b.sec <= secReqHeaders:
			b.sec = secReqHeaders
			b.addRequestLine(strings.TrimPrefix(line, "> "))
		case strings.HasPrefix(line, "< ") && b.sec != secRespBody:
			b.sec = secRespHeaders
			b.addResponseLine(strings.TrimPrefix(line, "< "))
		case line == "GraphQL query:" && b.sec < secRespHeaders:
			b.sec = secGraphQL
			b.gqlBlock = true
		case b.sec >= secRespHeaders:
			b.sec = secRespBody
			if b.body.Len() <= maxBody {
				b.body.WriteString(line)
				b.body.WriteByte('\n')
			}
		default:
			b.sec = secReqBody
			b.reqBody.WriteString(line)
			b.reqBody.WriteByte('\n')
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ghdebug: read capture: %w", err)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

func (b *builder) addRequestLine(s string) {
	if !b.reqLine {
		b.reqLine = true
		if f := strings.Fields(s); len(f) >= 2 && !strings.Contains(f[0], ":") {
			b.ex.Method = f[0]
			return
		}
	}
	if k, v, ok := strings.Cut(s, ":"); ok {
		b.ex.RequestHeaders.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
}

func (b *builder) addResponseLine(s string) {
	if b.respLine {
		return // response headers are not retained
	}
	b.respLine = true
	if f := strings.Fields(s); len(f) >= 2 && strings.HasPrefix(f[0], "HTTP/") {
		b.ex.Status, _ = strconv.Atoi(f[1])
	}
}

func (b *builder) finish() (Exchange, error) {
	ex := b.ex
	ex.RequestHeaders = redact.Header(ex.RequestHeaders)
	body := strings.TrimSpace(b.body.String())
	if len(body) > maxBody {
		body = body[:maxBody]
	}
	ex.ResponseBody = redact.String(body)

	switch {
	case b.gqlBlock:
		g := &GraphQLRequest{Query: strings.TrimSpace(b.query.String())}
		if v := strings.TrimSpace(b.vars); v != "" {
			vars, err := decodeVars([]byte(v))
			if err != nil {
				return Exchange{}, fmt.Errorf("ghdebug: %s: decode GraphQL variables: %w", ex.URL, err)
			}
			g.Variables = vars
		}
		ex.GraphQL = g
	case ex.Path == "/graphql":
		// gh api graphql prints the JSON body rather than a GraphQL block.
		var req struct {
			Query     string          `json:"query"`
			Variables json.RawMessage `json:"variables"`
		}
		if err := json.Unmarshal([]byte(b.reqBody.String()), &req); err == nil && req.Query != "" {
			g := &GraphQLRequest{Query: req.Query}
			if len(req.Variables) > 0 && string(req.Variables) != "null" {
				if vars, err := decodeVars(req.Variables); err == nil {
					g.Variables = vars
				}
			}
			ex.GraphQL = g
		}
	}
	if ex.GraphQL != nil {
		if m := opName.FindStringSubmatch(ex.GraphQL.Query); m != nil {
			ex.GraphQL.OperationName = m[1]
		}
	}
	return ex, nil
}

func decodeVars(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// FirstDenied returns the first exchange with Status >= 400, or nil.
func FirstDenied(ex []Exchange) *Exchange {
	for i := range ex {
		if ex[i].Status >= 400 {
			return &ex[i]
		}
	}
	return nil
}
