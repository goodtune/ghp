package netutil

import (
	"net/http/httptest"
	"testing"
)

func TestParseIPHeader(t *testing.T) {
	tests := []struct {
		in      string
		want    IPHeader
		wantErr bool
	}{
		{in: "", want: IPHeaderNone},
		{in: "forwarded", want: IPHeaderForwarded},
		{in: "x-real-ip", want: IPHeaderXRealIP},
		{in: "x-forwarded-for", want: IPHeaderXForwardedFor},
		{in: "X-Forwarded-For", want: IPHeaderXForwardedFor},
		{in: "  Forwarded  ", want: IPHeaderForwarded},
		{in: "x_forwarded_for", wantErr: true},
		{in: "cf-connecting-ip", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseIPHeader(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseIPHeader(%q) expected error, got %q", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseIPHeader(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseIPHeader(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		forwarded  string
		xRealIP    string
		xForwarded string
		header     IPHeader
		want       string
	}{
		{name: "remote addr only", remoteAddr: "192.168.1.10:54321", want: "192.168.1.10"},
		{name: "remote addr without port", remoteAddr: "192.168.1.10", want: "192.168.1.10"},
		{name: "x-real-ip ignored when no header configured", remoteAddr: "192.168.1.10:54321", xRealIP: "10.0.0.1", want: "192.168.1.10"},
		{name: "x-forwarded-for ignored when no header configured", remoteAddr: "192.168.1.10:54321", xForwarded: "10.0.0.1", want: "192.168.1.10"},
		{name: "forwarded ignored when no header configured", remoteAddr: "192.168.1.10:54321", forwarded: "for=10.0.0.1", want: "192.168.1.10"},
		{name: "x-real-ip configured", remoteAddr: "192.168.1.10:54321", xRealIP: "10.0.0.1", header: IPHeaderXRealIP, want: "10.0.0.1"},
		{name: "x-real-ip trimmed", remoteAddr: "192.168.1.10:54321", xRealIP: "  10.0.0.1  ", header: IPHeaderXRealIP, want: "10.0.0.1"},
		{name: "x-real-ip invalid falls back", remoteAddr: "192.168.1.10:54321", xRealIP: "not-an-ip", header: IPHeaderXRealIP, want: "192.168.1.10"},
		{name: "x-forwarded-for single", remoteAddr: "192.168.1.10:54321", xForwarded: "10.0.0.1", header: IPHeaderXForwardedFor, want: "10.0.0.1"},
		{name: "x-forwarded-for chain uses rightmost", remoteAddr: "192.168.1.10:54321", xForwarded: "10.0.0.1, 10.0.0.2, 10.0.0.3", header: IPHeaderXForwardedFor, want: "10.0.0.3"},
		{name: "x-forwarded-for spoofed prefix ignored", remoteAddr: "192.168.1.10:54321", xForwarded: "1.1.1.1, 172.16.0.5", header: IPHeaderXForwardedFor, want: "172.16.0.5"},
		{name: "x-forwarded-for with port", remoteAddr: "192.168.1.10:54321", xForwarded: "10.0.0.1:8080", header: IPHeaderXForwardedFor, want: "10.0.0.1"},
		{name: "x-forwarded-for invalid falls back", remoteAddr: "192.168.1.10:54321", xForwarded: "garbage", header: IPHeaderXForwardedFor, want: "192.168.1.10"},
		{name: "x-forwarded-for missing falls back", remoteAddr: "192.168.1.10:54321", header: IPHeaderXForwardedFor, want: "192.168.1.10"},
		{name: "forwarded single element", remoteAddr: "192.168.1.10:54321", forwarded: "for=10.0.0.1", header: IPHeaderForwarded, want: "10.0.0.1"},
		{name: "forwarded chain uses rightmost element", remoteAddr: "192.168.1.10:54321", forwarded: "for=1.1.1.1, for=172.16.0.5", header: IPHeaderForwarded, want: "172.16.0.5"},
		{name: "forwarded with other fields", remoteAddr: "192.168.1.10:54321", forwarded: "by=203.0.113.43;for=10.0.0.1;proto=https", header: IPHeaderForwarded, want: "10.0.0.1"},
		{name: "forwarded quoted with port", remoteAddr: "192.168.1.10:54321", forwarded: `for="10.0.0.1:8080"`, header: IPHeaderForwarded, want: "10.0.0.1"},
		{name: "forwarded bracketed ipv6", remoteAddr: "192.168.1.10:54321", forwarded: `for="[2001:db8::1]"`, header: IPHeaderForwarded, want: "2001:db8::1"},
		{name: "forwarded bracketed ipv6 with port", remoteAddr: "192.168.1.10:54321", forwarded: `for="[2001:db8::1]:443"`, header: IPHeaderForwarded, want: "2001:db8::1"},
		{name: "forwarded ipv6 canonicalized", remoteAddr: "192.168.1.10:54321", forwarded: `for="[2001:DB8::1]"`, header: IPHeaderForwarded, want: "2001:db8::1"},
		{name: "forwarded unknown falls back to peer", remoteAddr: "192.168.1.10:54321", forwarded: "for=unknown", xRealIP: "10.0.0.1", header: IPHeaderForwarded, want: "192.168.1.10"},
		{name: "forwarded obfuscated falls back to peer", remoteAddr: "192.168.1.10:54321", forwarded: "for=_hidden", xForwarded: "10.0.0.2", header: IPHeaderForwarded, want: "192.168.1.10"},
		{name: "spoofed forwarded ignored when x-forwarded-for configured", remoteAddr: "192.168.1.10:54321", forwarded: "for=1.2.3.4", xForwarded: "10.0.0.5", header: IPHeaderXForwardedFor, want: "10.0.0.5"},
		{name: "spoofed x-real-ip ignored when x-forwarded-for configured", remoteAddr: "192.168.1.10:54321", xRealIP: "1.2.3.4", xForwarded: "10.0.0.5", header: IPHeaderXForwardedFor, want: "10.0.0.5"},
		{name: "spoofed forwarded ignored when x-real-ip configured", remoteAddr: "192.168.1.10:54321", forwarded: "for=1.2.3.4", xRealIP: "10.0.0.5", header: IPHeaderXRealIP, want: "10.0.0.5"},
		{name: "spoofed x-forwarded-for ignored when forwarded configured", remoteAddr: "192.168.1.10:54321", xForwarded: "1.2.3.4", forwarded: "for=10.0.0.5", header: IPHeaderForwarded, want: "10.0.0.5"},
		{name: "spoofed x-real-ip does not fall through when forwarded configured but absent", remoteAddr: "192.168.1.10:54321", xRealIP: "1.2.3.4", header: IPHeaderForwarded, want: "192.168.1.10"},
		{name: "configured header missing falls back", remoteAddr: "192.168.1.10:54321", header: IPHeaderXRealIP, want: "192.168.1.10"},
		{name: "ipv6 remote addr", remoteAddr: "[2001:db8::1]:443", want: "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.forwarded != "" {
				r.Header.Set("Forwarded", tt.forwarded)
			}
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if tt.xForwarded != "" {
				r.Header.Set("X-Forwarded-For", tt.xForwarded)
			}
			if got := ClientIP(r, tt.header); got != tt.want {
				t.Errorf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
