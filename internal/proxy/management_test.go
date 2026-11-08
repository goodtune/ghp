package proxy

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/metrics"
)

func TestRequireGHPToken(t *testing.T) {
	basic := func(user, pass string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}
	tests := []struct {
		name       string
		block      config.BlockConfig
		auth       string
		wantStatus int
		wantNext   bool
		wantMsg    string
		wantReason string
	}{
		{name: "anonymous", wantStatus: http.StatusUnauthorized, wantMsg: msgManagementAnonymous, wantReason: reasonAnonymous},
		{name: "unparseable header", auth: "garbage", wantStatus: http.StatusUnauthorized, wantMsg: msgManagementAnonymous, wantReason: reasonAnonymous},
		{name: "gho not blocked", auth: "Bearer gho_realtoken123", wantStatus: http.StatusForbidden, wantMsg: msgManagementNative, wantReason: reasonNativeToken},
		{name: "ghp not blocked", auth: "token ghp_realtoken123", wantStatus: http.StatusForbidden, wantMsg: msgManagementNative, wantReason: reasonNativeToken},
		{name: "ghs not blocked", auth: "token ghs_realtoken123", wantStatus: http.StatusForbidden, wantMsg: msgManagementNative, wantReason: reasonNativeToken},
		{name: "github_pat not blocked", auth: "Bearer github_pat_realtoken123", wantStatus: http.StatusForbidden, wantMsg: msgManagementNative, wantReason: reasonNativeToken},
		{name: "unknown bearer", auth: "Bearer something", wantStatus: http.StatusForbidden, wantMsg: msgManagementNative, wantReason: reasonNativeToken},
		{name: "basic native password", auth: basic("x-access-token", "gho_realtoken123"), wantStatus: http.StatusForbidden, wantMsg: msgManagementNative, wantReason: reasonNativeToken},
		{name: "ghp blocked keeps border message", block: config.BlockConfig{GHP: true}, auth: "token ghp_realtoken123", wantStatus: http.StatusForbidden, wantMsg: "Token type is not permitted by the border policy", wantReason: reasonNativeToken},
		{name: "empty header value", auth: "", wantStatus: http.StatusUnauthorized, wantMsg: msgManagementAnonymous, wantReason: reasonAnonymous},
		{name: "bare bearer", auth: "Bearer", wantStatus: http.StatusUnauthorized, wantMsg: msgManagementAnonymous, wantReason: reasonAnonymous},
		{name: "basic other user ghx password", auth: basic("someone", "ghx_abc123"), wantStatus: http.StatusForbidden, wantMsg: msgManagementNative, wantReason: reasonNativeToken},
		{name: "mixed-case scheme ghx", auth: "BEARER ghx_abc123", wantStatus: http.StatusTeapot, wantNext: true},
		{name: "ghx bearer", auth: "Bearer ghx_abc123", wantStatus: http.StatusTeapot, wantNext: true},
		{name: "gha token", auth: "token gha_abc123", wantStatus: http.StatusTeapot, wantNext: true},
		{name: "ghx basic", auth: basic("x-access-token", "ghx_abc123"), wantStatus: http.StatusTeapot, wantNext: true},
	}
	for _, path := range []string{"/api/v3/user", "/api/graphql"} {
		for _, tc := range tests {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				cfg := &config.Config{Block: tc.block}
				called := false
				next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					called = true
					w.WriteHeader(http.StatusTeapot)
				})
				var before float64
				if tc.wantReason != "" {
					before = getCounterValue(t, metrics.ManagementHostRejectedTotal, prometheus.Labels{"reason": tc.wantReason})
				}
				req := httptest.NewRequest(http.MethodGet, path, nil)
				if tc.auth != "" || tc.name == "empty header value" {
					req.Header.Set("Authorization", tc.auth)
				}
				rr := httptest.NewRecorder()
				RequireGHPToken(next, cfg).ServeHTTP(rr, req)

				if rr.Code != tc.wantStatus {
					t.Fatalf("status = %d, want %d (body %s)", rr.Code, tc.wantStatus, rr.Body.String())
				}
				if called != tc.wantNext {
					t.Fatalf("next called = %v, want %v", called, tc.wantNext)
				}
				if tc.wantMsg != "" {
					var body map[string]string
					if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
						t.Fatalf("decoding body: %v", err)
					}
					if body["message"] != tc.wantMsg {
						t.Errorf("message = %q, want %q", body["message"], tc.wantMsg)
					}
				}
				if tc.wantStatus == http.StatusUnauthorized && rr.Header().Get("WWW-Authenticate") == "" {
					t.Error("401 without WWW-Authenticate header")
				}
				if tc.wantReason != "" {
					after := getCounterValue(t, metrics.ManagementHostRejectedTotal, prometheus.Labels{"reason": tc.wantReason})
					if after-before != 1 {
						t.Errorf("%s counter delta = %v, want 1", tc.wantReason, after-before)
					}
				}
			})
		}
	}
}

// decisionStageSampleCount returns the observation count of a decision stage
// histogram for the given token type label.
func decisionStageSampleCount(t *testing.T, stage, tokenType string) uint64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "ghp_proxy_decision_duration_seconds" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["stage"] == stage && labels["token_type"] == tokenType {
				return m.GetHistogram().GetSampleCount()
			}
		}
	}
	return 0
}

// decisionStageSampleSum returns the observation sum (seconds) of a decision
// stage histogram for the given token type label.
func decisionStageSampleSum(t *testing.T, stage, tokenType string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "ghp_proxy_decision_duration_seconds" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["stage"] == stage && labels["token_type"] == tokenType {
				return m.GetHistogram().GetSampleSum()
			}
		}
	}
	return 0
}

// TestRequireGHPToken_PassObservesBorderStage checks that the pass path is
// timed under border_policy_check with the token type from the prefix, and
// that total is left to the downstream handler.
func TestRequireGHPToken_PassObservesBorderStage(t *testing.T) {
	tests := []struct {
		auth      string
		tokenType string
	}{
		{auth: "Bearer ghx_abc123", tokenType: "proxy"},
		{auth: "token gha_abc123", tokenType: "agent"},
	}
	for _, tc := range tests {
		t.Run(tc.tokenType, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
			borderBefore := decisionStageSampleCount(t, metrics.StageBorderPolicyCheck, tc.tokenType)
			totalBefore := decisionStageSampleCount(t, metrics.StageTotal, tc.tokenType)
			req := httptest.NewRequest(http.MethodGet, "/api/v3/user", nil)
			req.Header.Set("Authorization", tc.auth)
			RequireGHPToken(next, &config.Config{}).ServeHTTP(httptest.NewRecorder(), req)
			if got := decisionStageSampleCount(t, metrics.StageBorderPolicyCheck, tc.tokenType) - borderBefore; got != 1 {
				t.Errorf("border_policy_check observations = %d, want 1", got)
			}
			if got := decisionStageSampleCount(t, metrics.StageTotal, tc.tokenType) - totalBefore; got != 0 {
				t.Errorf("total observations = %d, want 0", got)
			}
		})
	}
}
