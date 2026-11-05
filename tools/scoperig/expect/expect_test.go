package expect

import (
	"net/http"
	"strings"
	"testing"

	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

func boolp(b bool) *bool { return &b }
func intp(i int) *int    { return &i }

func TestMatch(t *testing.T) {
	denial := []byte(`{"message":"Token is not scoped to o/r","documentation_url":"https://docs.github.com/rest"}`)
	hdr := http.Header{"X-Github-Request-Id": {"abc"}}
	obs := &Observation{Status: 403, Header: hdr, Body: denial, GHExit: intp(1), Stdout: "hello world", Stderr: "HTTP 403"}
	tests := []struct {
		name    string
		e       scenario.Expect
		o       *Observation
		wantErr []string
	}{
		{"empty", scenario.Expect{}, obs, nil},
		{"status ok", scenario.Expect{Status: 403}, obs, nil},
		{"status miss", scenario.Expect{Status: 200}, obs, []string{"status: want 200, got 403"}},
		{"status_in ok", scenario.Expect{StatusIn: []int{401, 403}}, obs, nil},
		{"status_in miss", scenario.Expect{StatusIn: []int{200, 204}}, obs, []string{"status_in: want one of [200 204], got 403"}},
		{"body_contains miss", scenario.Expect{BodyContains: []string{"nope"}}, obs, []string{`body: want contains "nope"`}},
		{"body_not_contains hit", scenario.Expect{BodyNotContains: []string{"scoped"}}, obs, []string{`body: want not contains "scoped"`}},
		{"header ok", scenario.Expect{Header: map[string]string{"x-github-request-id": "abc"}}, obs, nil},
		{"header miss", scenario.Expect{Header: map[string]string{"X-Foo": "1"}}, obs, []string{`header X-Foo: want "1", got ""`}},
		{"json ok", scenario.Expect{JSON: map[string]string{"$.message": "Token is not scoped to o/r"}}, obs, nil},
		{"json miss", scenario.Expect{JSON: map[string]string{"$.documentation_url": "x"}}, obs, []string{`json $.documentation_url: want "x", got "https://docs.github.com/rest"`}},
		{"json missing path", scenario.Expect{JSON: map[string]string{"$.nope": "x"}}, obs, []string{`json $.nope: want "x", got error`}},
		{"denial true ok", scenario.Expect{GHPDenial: boolp(true)}, obs, nil},
		{"denial false miss", scenario.Expect{GHPDenial: boolp(false)}, obs, []string{"ghp_denial: want false, got true"}},
		{"denial true miss", scenario.Expect{GHPDenial: boolp(true)}, &Observation{Body: []byte(`{"message":"Not Found"}`)}, []string{"ghp_denial: want true, got false"}},
		{"denial needs 4xx", scenario.Expect{GHPDenial: boolp(false)}, &Observation{Status: 200, Body: denial}, nil},
		{"denial true on 200 miss", scenario.Expect{GHPDenial: boolp(true)}, &Observation{Status: 200, Body: denial}, []string{"ghp_denial: want true, got false"}},
		{"github 403 not denial", scenario.Expect{GHPDenial: boolp(false)}, &Observation{Status: 403, Body: []byte(`{"message":"Resource not accessible by integration"}`)}, nil},
		{"exit ok", scenario.Expect{ExitCode: intp(1)}, obs, nil},
		{"exit miss", scenario.Expect{ExitCode: intp(0)}, obs, []string{"exit_code: want 0, got 1"}},
		{"exit nil", scenario.Expect{ExitCode: intp(0)}, &Observation{}, []string{"exit_code: want 0, got none"}},
		{"stdout ok", scenario.Expect{StdoutContains: []string{"world"}}, obs, nil},
		{"stdout miss", scenario.Expect{StdoutContains: []string{"bye"}}, obs, []string{`stdout: want contains "bye"`}},
		{"stderr miss", scenario.Expect{StderrContains: []string{"404"}}, obs, []string{`stderr: want contains "404"`}},
		{"redacts", scenario.Expect{BodyContains: []string{"ghx_test0000"}}, obs, []string{"ghx_[REDACTED]"}},
		{"multiple", scenario.Expect{Status: 200, ExitCode: intp(0)}, obs, []string{"status:", "exit_code:"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := Match(&tt.e, tt.o)
			if len(errs) != len(tt.wantErr) {
				t.Fatalf("got %d errors %v, want %d", len(errs), errs, len(tt.wantErr))
			}
			for i, w := range tt.wantErr {
				if !strings.Contains(errs[i].Error(), w) {
					t.Errorf("err[%d] = %q, want substring %q", i, errs[i], w)
				}
				if strings.Contains(errs[i].Error(), "test0000") {
					t.Errorf("token leaked: %q", errs[i])
				}
			}
		})
	}
	for _, m := range []string{MsgTokenResolutionFailed, MsgInvalidPrefix, MsgLookupFailed} {
		if !IsGHPDenialResponse(401, []byte(`{"message":"`+m+` x"}`)) {
			t.Errorf("want 401 denial for %q", m)
		}
	}
	if IsGHPDenialResponse(200, denial) {
		t.Error("200 must not be a denial")
	}
	if Match(nil, obs) != nil {
		t.Error("nil expect should match")
	}
}

func TestJSONPath(t *testing.T) {
	body := []byte(`{"a":{"b":"x"},"items":[{"id":12345678901},{"id":2}],"f":1.5,"t":true,"n":null,"o":{"k":1}}`)
	tests := []struct {
		path, want string
		err        bool
	}{
		{"$.a.b", "x", false},
		{"$.items[0].id", "12345678901", false},
		{"$.items[1].id", "2", false},
		{"$.f", "1.5", false},
		{"$.t", "true", false},
		{"$.n", "null", false},
		{"$.o", `{"k":1}`, false},
		{"$.items[5].id", "", true},
		{"$.missing", "", true},
		{"a.b", "", true},
		{"$.a[0]", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := JSONPath(body, tt.path)
			if (err != nil) != tt.err || got != tt.want {
				t.Fatalf("JSONPath(%q) = %q, %v; want %q, err=%v", tt.path, got, err, tt.want, tt.err)
			}
		})
	}
	if _, err := JSONPath([]byte("not json"), "$.a"); err == nil {
		t.Error("want error for non-JSON")
	}
}

func TestIsGHPDenial(t *testing.T) {
	for _, p := range denialPrefixes {
		t.Run(p, func(t *testing.T) {
			b := []byte(`{"message":"` + p + ` extra"}`)
			if !IsGHPDenial(b) {
				t.Errorf("want denial for %q", p)
			}
		})
	}
	for _, b := range []string{`{"message":"Not Found"}`, `not json`, `{"message":"Bad credentials"}`, `{"message":"Resource not accessible by integration"}`, `{"message":"API rate limit exceeded for 1.2.3.4"}`, ``} {
		if IsGHPDenial([]byte(b)) {
			t.Errorf("unexpected denial for %q", b)
		}
	}
	if GHPMessage([]byte(`{"message":"hi"}`)) != "hi" || GHPMessage([]byte(`[1]`)) != "" || GHPMessage([]byte(`{"message":42}`)) != "" {
		t.Error("GHPMessage")
	}
}
