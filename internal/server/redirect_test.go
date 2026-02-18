package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPSRedirectHandler(t *testing.T) {
	handler := httpsRedirectHandler()

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.Host = "github.com"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("expected 308, got %d", rr.Code)
	}

	loc := rr.Header().Get("Location")
	expected := "https://github.com/org/repo"
	if loc != expected {
		t.Errorf("expected location %q, got %q", expected, loc)
	}
}

func TestHTTPSRedirectHandler_PreservesQueryString(t *testing.T) {
	handler := httpsRedirectHandler()

	req := httptest.NewRequest("GET", "http://github.com/org/repo?ref=main", nil)
	req.Host = "github.com"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	loc := rr.Header().Get("Location")
	expected := "https://github.com/org/repo?ref=main"
	if loc != expected {
		t.Errorf("expected location %q, got %q", expected, loc)
	}
}
