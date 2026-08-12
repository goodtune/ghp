package netutil

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

type IPHeader string

const (
	IPHeaderNone          IPHeader = ""
	IPHeaderForwarded     IPHeader = "forwarded"
	IPHeaderXRealIP       IPHeader = "x-real-ip"
	IPHeaderXForwardedFor IPHeader = "x-forwarded-for"
)

func ParseIPHeader(s string) (IPHeader, error) {
	switch h := IPHeader(strings.ToLower(strings.TrimSpace(s))); h {
	case IPHeaderNone, IPHeaderForwarded, IPHeaderXRealIP, IPHeaderXForwardedFor:
		return h, nil
	default:
		return IPHeaderNone, fmt.Errorf("unsupported client IP header %q (expected %q, %q, or %q)", s, IPHeaderForwarded, IPHeaderXRealIP, IPHeaderXForwardedFor)
	}
}

func ClientIP(r *http.Request, header IPHeader) string {
	switch header {
	case IPHeaderForwarded:
		if ip := parseIPCandidate(rightmostForwardedFor(r.Header.Get("Forwarded"))); ip != "" {
			return ip
		}
	case IPHeaderXRealIP:
		if ip := parseIPCandidate(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
	case IPHeaderXForwardedFor:
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			if ip := parseIPCandidate(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func rightmostForwardedFor(header string) string {
	if header == "" {
		return ""
	}
	last := header
	if i := strings.LastIndexByte(last, ','); i >= 0 {
		last = last[i+1:]
	}
	for _, part := range strings.Split(last, ";") {
		part = strings.TrimSpace(part)
		eq := strings.IndexByte(part, '=')
		if eq < 0 || !strings.EqualFold(part[:eq], "for") {
			continue
		}
		return strings.Trim(strings.TrimSpace(part[eq+1:]), `"`)
	}
	return ""
}

func parseIPCandidate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		if ip := net.ParseIP(s[1 : len(s)-1]); ip != nil {
			return ip.String()
		}
	}
	return ""
}
