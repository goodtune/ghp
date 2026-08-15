package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/goodtune/ghp/internal/auth"
)

func adminCtx() context.Context {
	return auth.NewContextWithSession(context.Background(), &auth.Session{Username: "admin"})
}

func TestForwardProxyRulesetsCRUD(t *testing.T) {
	a := newTestAPIWithStore(t)

	appRuleID := uuid.New().String()

	// Create
	body := `{
		"name": "ci-egress",
		"description": "CI split",
		"algorithm": "weighted",
		"proxies": [
			{"url": "http://proxy-a.internal:3128", "weight": 80},
			{"url": "http://proxy-b.internal:3128", "weight": 20}
		],
		"rules": [
			{"type": "net", "value": "10.42.0.0/16"},
			{"type": "app", "value": "` + appRuleID + `"}
		]
	}`
	req := httptest.NewRequest("POST", "/api/forward-proxy-rulesets", strings.NewReader(body)).WithContext(adminCtx())
	w := httptest.NewRecorder()
	a.handleCreateForwardProxyRuleset(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
	}
	var created map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	id := created["id"].(string)
	if created["enabled"] != true {
		t.Errorf("expected enabled to default to true, got %v", created["enabled"])
	}

	// Duplicate name → 409
	req = httptest.NewRequest("POST", "/api/forward-proxy-rulesets",
		strings.NewReader(`{"name":"ci-egress","algorithm":"round_robin","proxies":[{"url":"http://p:1"}]}`)).WithContext(adminCtx())
	w = httptest.NewRecorder()
	a.handleCreateForwardProxyRuleset(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate create: expected %d, got %d: %s", http.StatusConflict, w.Code, w.Body.String())
	}

	// List
	req = httptest.NewRequest("GET", "/api/forward-proxy-rulesets", nil)
	w = httptest.NewRecorder()
	a.handleListForwardProxyRulesets(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected %d, got %d", http.StatusOK, w.Code)
	}
	var list []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list: expected 1 item, got %d", len(list))
	}

	// Get
	req = httptest.NewRequest("GET", "/api/forward-proxy-rulesets/"+id, nil)
	req.SetPathValue("id", id)
	w = httptest.NewRecorder()
	a.handleGetForwardProxyRuleset(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get: expected %d, got %d", http.StatusOK, w.Code)
	}
	var got map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got["algorithm"] != "weighted" {
		t.Errorf("algorithm = %v, want weighted", got["algorithm"])
	}
	if n := len(got["proxies"].([]interface{})); n != 2 {
		t.Errorf("proxies len = %d, want 2", n)
	}
	if n := len(got["rules"].([]interface{})); n != 2 {
		t.Errorf("rules len = %d, want 2", n)
	}

	// Patch: disable, change algorithm, clear rules.
	req = httptest.NewRequest("PATCH", "/api/forward-proxy-rulesets/"+id,
		strings.NewReader(`{"enabled":false,"algorithm":"sticky","rules":[]}`)).WithContext(adminCtx())
	req.SetPathValue("id", id)
	w = httptest.NewRecorder()
	a.handleUpdateForwardProxyRuleset(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("patch: expected %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
	var patched map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&patched); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	if patched["enabled"] != false || patched["algorithm"] != "sticky" {
		t.Errorf("patched = %v, want disabled sticky", patched)
	}
	if n := len(patched["rules"].([]interface{})); n != 0 {
		t.Errorf("patched rules len = %d, want 0", n)
	}
	// Omitted fields are untouched.
	if n := len(patched["proxies"].([]interface{})); n != 2 {
		t.Errorf("patched proxies len = %d, want 2 (field was omitted)", n)
	}

	// Delete
	req = httptest.NewRequest("DELETE", "/api/forward-proxy-rulesets/"+id, nil).WithContext(adminCtx())
	req.SetPathValue("id", id)
	w = httptest.NewRecorder()
	a.handleDeleteForwardProxyRuleset(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: expected %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Get after delete → 404
	req = httptest.NewRequest("GET", "/api/forward-proxy-rulesets/"+id, nil)
	req.SetPathValue("id", id)
	w = httptest.NewRecorder()
	a.handleGetForwardProxyRuleset(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("get after delete: expected %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestForwardProxyRulesets_CreateValidation(t *testing.T) {
	a := newTestAPIWithStore(t)

	tests := []struct {
		name string
		body string
	}{
		{"missing name", `{"algorithm":"round_robin","proxies":[{"url":"http://p:1"}]}`},
		{"bad name chars", `{"name":"bad name!","algorithm":"round_robin","proxies":[{"url":"http://p:1"}]}`},
		{"bad algorithm", `{"name":"ok","algorithm":"lru","proxies":[{"url":"http://p:1"}]}`},
		{"no proxies", `{"name":"ok","algorithm":"round_robin","proxies":[]}`},
		{"bad proxy scheme", `{"name":"ok","algorithm":"round_robin","proxies":[{"url":"ftp://p:21"}]}`},
		{"proxy without host", `{"name":"ok","algorithm":"round_robin","proxies":[{"url":"http://"}]}`},
		{"negative weight", `{"name":"ok","algorithm":"round_robin","proxies":[{"url":"http://p:1","weight":-1}]}`},
		{"bad rule type", `{"name":"ok","algorithm":"round_robin","proxies":[{"url":"http://p:1"}],"rules":[{"type":"user","value":"x"}]}`},
		{"bad cidr", `{"name":"ok","algorithm":"round_robin","proxies":[{"url":"http://p:1"}],"rules":[{"type":"net","value":"10.0.0.1"}]}`},
		{"app rule not uuid", `{"name":"ok","algorithm":"round_robin","proxies":[{"url":"http://p:1"}],"rules":[{"type":"app","value":"not-a-uuid"}]}`},
		{"token rule not uuid", `{"name":"ok","algorithm":"round_robin","proxies":[{"url":"http://p:1"}],"rules":[{"type":"token","value":"not-a-uuid"}]}`},
		{"system rule with value", `{"name":"ok","algorithm":"round_robin","proxies":[{"url":"http://p:1"}],"rules":[{"type":"system","value":"x"}]}`},
		{"invalid json", `{`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/forward-proxy-rulesets", strings.NewReader(tt.body)).WithContext(adminCtx())
			w := httptest.NewRecorder()
			a.handleCreateForwardProxyRuleset(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
			}
		})
	}
}

func TestForwardProxyRulesets_BodyTooLarge(t *testing.T) {
	a := newTestAPIWithStore(t)
	big := strings.Repeat("x", maxRequestBodySize+1)
	req := httptest.NewRequest("POST", "/api/forward-proxy-rulesets", strings.NewReader(`{"name":"`+big+`"}`)).WithContext(adminCtx())
	w := httptest.NewRecorder()
	a.handleCreateForwardProxyRuleset(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected %d, got %d", http.StatusRequestEntityTooLarge, w.Code)
	}
}

func TestForwardProxyRulesets_InvalidAndMissingIDs(t *testing.T) {
	a := newTestAPIWithStore(t)

	// Malformed UUIDs → 400 on every ID-taking handler.
	for _, tc := range []struct {
		method string
		h      func(http.ResponseWriter, *http.Request)
	}{
		{"GET", a.handleGetForwardProxyRuleset},
		{"PATCH", a.handleUpdateForwardProxyRuleset},
		{"DELETE", a.handleDeleteForwardProxyRuleset},
	} {
		req := httptest.NewRequest(tc.method, "/api/forward-proxy-rulesets/nope", strings.NewReader(`{}`)).WithContext(adminCtx())
		req.SetPathValue("id", "nope")
		w := httptest.NewRecorder()
		tc.h(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s with malformed id: expected %d, got %d", tc.method, http.StatusBadRequest, w.Code)
		}
	}

	// Well-formed but unknown UUID → 404.
	missing := uuid.New().String()
	req := httptest.NewRequest("PATCH", "/api/forward-proxy-rulesets/"+missing, strings.NewReader(`{"enabled":true}`)).WithContext(adminCtx())
	req.SetPathValue("id", missing)
	w := httptest.NewRecorder()
	a.handleUpdateForwardProxyRuleset(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("patch unknown id: expected %d, got %d", http.StatusNotFound, w.Code)
	}
	req = httptest.NewRequest("DELETE", "/api/forward-proxy-rulesets/"+missing, nil).WithContext(adminCtx())
	req.SetPathValue("id", missing)
	w = httptest.NewRecorder()
	a.handleDeleteForwardProxyRuleset(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("delete unknown id: expected %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestForwardProxyRulesets_RenameConflict(t *testing.T) {
	a := newTestAPIWithStore(t)

	mk := func(name string) string {
		req := httptest.NewRequest("POST", "/api/forward-proxy-rulesets",
			strings.NewReader(`{"name":"`+name+`","algorithm":"round_robin","proxies":[{"url":"http://p:1"}]}`)).WithContext(adminCtx())
		w := httptest.NewRecorder()
		a.handleCreateForwardProxyRuleset(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("create %s: got %d: %s", name, w.Code, w.Body.String())
		}
		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		return resp["id"].(string)
	}
	mk("first")
	secondID := mk("second")

	req := httptest.NewRequest("PATCH", "/api/forward-proxy-rulesets/"+secondID,
		strings.NewReader(`{"name":"first"}`)).WithContext(adminCtx())
	req.SetPathValue("id", secondID)
	w := httptest.NewRecorder()
	a.handleUpdateForwardProxyRuleset(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("rename conflict: expected %d, got %d: %s", http.StatusConflict, w.Code, w.Body.String())
	}
}
