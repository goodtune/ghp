package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"
)

// fakeInstallationGitHub serves GET /app/installations/{id} with the given
// account login (or the given status) and records every access_tokens body.
type fakeInstallationGitHub struct {
	mu            sync.Mutex
	account       string
	accountStatus int
	accountCalls  int
	mintBodies    []map[string]json.RawMessage
}

func (f *fakeInstallationGitHub) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/app/installations/77":
			f.accountCalls++
			if f.accountStatus != 0 && f.accountStatus != http.StatusOK {
				w.WriteHeader(f.accountStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      77,
				"account": map[string]string{"login": f.account},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/77/access_tokens":
			var body map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode mint body: %v", err)
			}
			f.mintBodies = append(f.mintBodies, body)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "ghs_narrowed",
				"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func newFakeProvider(t *testing.T, f *fakeInstallationGitHub) *AppTokenProvider {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	p, err := NewAppTokenProvider(AppConfig{AppID: 1, PrivateKey: testRSAKey, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGetInstallationToken_RepositoriesNarrowing(t *testing.T) {
	tests := []struct {
		name          string
		account       string
		accountStatus int
		repos         []string
		wantErr       bool
		wantMint      bool
		wantRepos     []string // nil means no "repositories" key
	}{
		{name: "owner stripped", account: "acme", repos: []string{"acme/api", "acme/web"}, wantMint: true, wantRepos: []string{"api", "web"}},
		{name: "mixed-case owner", account: "Acme", repos: []string{"ACME/api", "acme/Web"}, wantMint: true, wantRepos: []string{"api", "Web"}},
		{name: "bare names pass through", account: "acme", repos: []string{"api"}, wantMint: true, wantRepos: []string{"api"}},
		{name: "empty list means no narrowing", account: "acme", repos: nil, wantMint: true, wantRepos: nil},
		{name: "empty slice means no narrowing", account: "acme", repos: []string{}, wantMint: true, wantRepos: nil},
		{name: "owner mismatch rejected", account: "acme", repos: []string{"acme/api", "evil/api"}, wantErr: true},
		{name: "all repositories rejected", account: "acme", repos: []string{"evil/api"}, wantErr: true},
		{name: "unicode fold not accepted", account: "acmes", repos: []string{"acmeſ/api"}, wantErr: true},
		{name: "malformed entry rejected", account: "acme", repos: []string{"acme/api/x"}, wantErr: true},
		{name: "empty name rejected", account: "acme", repos: []string{"acme/"}, wantErr: true},
		{name: "account lookup fails closed", accountStatus: http.StatusNotFound, repos: []string{"acme/api"}, wantErr: true},
		{name: "empty account login fails closed", account: "", repos: []string{"acme/api"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeInstallationGitHub{account: tt.account, accountStatus: tt.accountStatus}
			p := newFakeProvider(t, f)
			tok, err := p.GetInstallationToken(context.Background(), 77, tt.repos, map[string]string{"contents": "read"})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got token %q", tok)
				}
				if tok != "" {
					t.Errorf("expected empty token on error, got %q", tok)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.wantMint {
				if len(f.mintBodies) != 0 {
					t.Fatalf("expected no access_tokens request, got %d", len(f.mintBodies))
				}
				return
			}
			if len(f.mintBodies) != 1 {
				t.Fatalf("expected 1 access_tokens request, got %d", len(f.mintBodies))
			}
			raw, ok := f.mintBodies[0]["repositories"]
			if tt.wantRepos == nil {
				if ok {
					t.Fatalf("expected no repositories field, got %s", raw)
				}
				return
			}
			var got []string
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("decode repositories: %v", err)
			}
			if !reflect.DeepEqual(got, tt.wantRepos) {
				t.Errorf("repositories = %v, want %v", got, tt.wantRepos)
			}
		})
	}
}

func TestGetInstallationToken_OwnerMismatchNamesRepository(t *testing.T) {
	f := &fakeInstallationGitHub{account: "acme"}
	p := newFakeProvider(t, f)
	_, err := p.GetInstallationToken(context.Background(), 77, []string{"evil/api"}, nil)
	var mm *RepositoryOwnerMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected RepositoryOwnerMismatchError, got %v", err)
	}
	if mm.Repository != "evil/api" || mm.Account != "acme" {
		t.Errorf("unexpected error fields: %+v", mm)
	}
}

func TestInstallationAccountLogin_Cached(t *testing.T) {
	f := &fakeInstallationGitHub{account: "acme"}
	p := newFakeProvider(t, f)
	for i := 0; i < 3; i++ {
		login, err := p.InstallationAccountLogin(context.Background(), 77)
		if err != nil {
			t.Fatal(err)
		}
		if login != "acme" {
			t.Fatalf("login = %q", login)
		}
	}
	if f.accountCalls != 1 {
		t.Errorf("expected 1 installation lookup, got %d", f.accountCalls)
	}
}

func TestNarrowRepositoriesForAccount(t *testing.T) {
	tests := []struct {
		name        string
		repos       []string
		requireFull bool
		want        []string
		wantErr     bool
	}{
		{name: "full names", repos: []string{"Acme/a"}, requireFull: true, want: []string{"a"}},
		{name: "bare rejected when full required", repos: []string{"a"}, requireFull: true, wantErr: true},
		{name: "bare allowed", repos: []string{"a"}, want: []string{"a"}},
		{name: "empty owner", repos: []string{"/a"}, wantErr: true},
		{name: "empty entry", repos: []string{""}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NarrowRepositoriesForAccount("acme", tt.repos, tt.requireFull)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
