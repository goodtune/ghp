package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func generateTestRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA key: %v", err)
	}
	return privKey, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestParseRSAPrivateKey(t *testing.T) {
	privKey, pkcs8PEM := generateTestRSAKey(t)

	t.Run("valid PKCS8", func(t *testing.T) {
		key, err := ParseRSAPrivateKey(pkcs8PEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key.PublicKey.N.Cmp(privKey.PublicKey.N) != 0 {
			t.Error("loaded key does not match original")
		}
	})

	t.Run("valid PKCS1", func(t *testing.T) {
		pkcs1PEM := string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		}))
		key, err := ParseRSAPrivateKey(pkcs1PEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key.PublicKey.N.Cmp(privKey.PublicKey.N) != 0 {
			t.Error("loaded key does not match original")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		_, err := ParseRSAPrivateKey("not a pem")
		if err == nil {
			t.Error("expected error for invalid PEM")
		}
	})

	t.Run("unsupported PEM type", func(t *testing.T) {
		badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("dummy")}))
		_, err := ParseRSAPrivateKey(badPEM)
		if err == nil {
			t.Error("expected error for unsupported PEM type")
		}
	})
}
