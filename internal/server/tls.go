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

	minVersion, err := parseTLSMinVersion(cfg.MinVersion)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		// Minimum TLS version from config, defaulting to TLS 1.2.
		MinVersion: minVersion,
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

// parseTLSMinVersion maps a version string ("1.2", "1.3") to the corresponding
// tls constant. An empty string defaults to TLS 1.2.
func parseTLSMinVersion(v string) (uint16, error) {
	switch v {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported tls.min_version %q: allowed values are \"1.2\" and \"1.3\"", v)
	}
}
