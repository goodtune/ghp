package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleCreateToken_BodyTooLarge(t *testing.T) {
	a := &API{}

	// Body must be valid-looking JSON so the decoder reads past the 1 MB limit.
	body := strings.NewReader(`{"repository":"` + strings.Repeat("x", maxRequestBodySize) + `"}`)
	req := httptest.NewRequest("POST", "/api/tokens", body)
	w := httptest.NewRecorder()
	a.handleCreateToken(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected %d, got %d", http.StatusRequestEntityTooLarge, w.Code)
	}
}

func TestHandleCreateToken_InvalidJSON(t *testing.T) {
	a := &API{}

	req := httptest.NewRequest("POST", "/api/tokens", strings.NewReader("not valid json"))
	w := httptest.NewRecorder()
	a.handleCreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}
