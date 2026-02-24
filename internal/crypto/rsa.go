package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseRSAPrivateKey parses a PEM-encoded RSA private key.
// It supports both PKCS1 ("RSA PRIVATE KEY") and PKCS8 ("PRIVATE KEY") formats.
func ParseRSAPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS1 private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS8 private key: %w", err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not RSA")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}
