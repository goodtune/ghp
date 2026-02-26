package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/ghp/internal/crypto"
)

func TestWizardStateRoundTrip(t *testing.T) {
	enc := testEncryptor(t)

	state := &WizardState{
		Step:        2,
		Repository:  "owner/repo",
		Permissions: map[string]string{"contents": "write", "pull_requests": "read"},
		Duration:    "24h",
		SessionID:   "test-session",
	}

	w := httptest.NewRecorder()
	if err := setWizardCookie(w, enc, state); err != nil {
		t.Fatal(err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookies set")
	}

	r := httptest.NewRequest("GET", "/dashboard/token/add/", nil)
	r.AddCookie(cookies[0])

	got, err := getWizardCookie(r, enc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Repository != "owner/repo" {
		t.Errorf("repository = %q, want %q", got.Repository, "owner/repo")
	}
	if got.Step != 2 {
		t.Errorf("step = %d, want 2", got.Step)
	}
	if got.Permissions["pull_requests"] != "read" {
		t.Errorf("pull_requests = %q, want %q", got.Permissions["pull_requests"], "read")
	}
	if got.Duration != "24h" {
		t.Errorf("duration = %q, want %q", got.Duration, "24h")
	}
}

func TestWizardStateNoCookie(t *testing.T) {
	enc := testEncryptor(t)
	r := httptest.NewRequest("GET", "/dashboard/token/add/", nil)
	state, err := getWizardCookie(r, enc)
	if err != nil {
		t.Fatal(err)
	}
	if state.Step != 1 {
		t.Errorf("step = %d, want 1 (fresh wizard)", state.Step)
	}
}

func TestWizardStateCorruptCookie(t *testing.T) {
	enc := testEncryptor(t)
	r := httptest.NewRequest("GET", "/dashboard/token/add/", nil)
	r.AddCookie(&http.Cookie{Name: wizardCookieName, Value: "garbage"})
	state, err := getWizardCookie(r, enc)
	if err != nil {
		t.Fatal(err)
	}
	if state.Step != 1 {
		t.Errorf("step = %d, want 1 (corrupt cookie resets)", state.Step)
	}
}

func TestClearWizardCookie(t *testing.T) {
	w := httptest.NewRecorder()
	clearWizardCookie(w)
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookies set")
	}
	if cookies[0].MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", cookies[0].MaxAge)
	}
}

func testEncryptor(t *testing.T) *crypto.Encryptor {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}
