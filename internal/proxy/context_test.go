package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRawAuthSlot(t *testing.T) {
	t.Run("round trips through the slot", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/o/r/main/f.txt", nil)
		req, slots := PrepareAccessLogSlots(req)
		SetRawAuth(req, "query_token")
		if *slots.RawAuth != "query_token" {
			t.Errorf("RawAuth = %q, want %q", *slots.RawAuth, "query_token")
		}
	})

	t.Run("no-op without a prepared slot", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/o/r/main/f.txt", nil)
		SetRawAuth(req, "anonymous") // must not panic
	})
}
