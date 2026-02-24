package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/goodtune/ghp/internal/config"
)

// loadTLSConfig loads certificate files and builds a tls.Config with
// SNI-based certificate selection. Returns nil if no certificates are configured.
func loadTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	if len(cfg.Certificates) == 0 {
		return nil, nil
	}

	tlsCfg := &tls.Config{
		// Explicitly require TLS 1.2+ to document intent and guard against
		// future Go default changes.
		MinVersion: tls.VersionTLS12,
		// Enable HTTP/2 via ALPN negotiation.
		NextProtos: []string{"h2", "http/1.1"},
	}

	for _, cc := range cfg.Certificates {
		cert, err := tls.LoadX509KeyPair(cc.CertFile, cc.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading cert %s: %w", cc.CertFile, err)
		}
		// Parse leaf so Go can match by SNI (including wildcards).
		if cert.Leaf == nil {
			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, fmt.Errorf("parsing leaf cert %s: %w", cc.CertFile, err)
			}
		}
		tlsCfg.Certificates = append(tlsCfg.Certificates, cert)
	}

	return tlsCfg, nil
}
