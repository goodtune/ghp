package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateScopeFlag(t *testing.T) {
	tests := []struct {
		scope   string
		wantErr string
	}{
		{"", ""},
		{"contents:read,pull_requests:write", ""},
		{"pulls:write", "unknown scope permission \"pulls\""},
		{"foo:read", "valid permissions"},
		{"contents:admin", "must be read or write"},
	}
	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			err := validateScopeFlag(tt.scope)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestResolveAppByName_ASCIIFold(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/apps" {
			t.Errorf("path = %q, want /api/apps", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `[{"id":"a1","name":"staging"}]`); err != nil {
			t.Errorf("writing response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := &cliConfig{ServerURL: srv.URL, UserToken: "ghpr_test"}

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "ascii upper case", in: "STAGING", want: "a1"},
		{name: "long s does not fold", in: "ſtaging", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveAppByName(cfg, tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveAppByName(%q) = %q, want error", tt.in, got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("resolveAppByName(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
			}
		})
	}
}

func TestResolveInstallationByLogin_ASCIIFold(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/apps/a1/installations" {
			t.Errorf("path = %q, want /api/apps/a1/installations", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `[{"id":7,"account":{"login":"kube"}}]`); err != nil {
			t.Errorf("writing response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := &cliConfig{ServerURL: srv.URL, UserToken: "ghpr_test"}

	tests := []struct {
		name    string
		in      string
		want    int64
		wantErr bool
	}{
		{name: "ascii upper case", in: "KUBE", want: 7},
		{name: "kelvin sign does not fold", in: "Kube", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveInstallationByLogin(cfg, "a1", tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveInstallationByLogin(%q) = %d, want error", tt.in, got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("resolveInstallationByLogin(%q) = %d, %v; want %d", tt.in, got, err, tt.want)
			}
		})
	}
}
