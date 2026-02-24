package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/config"
)

func TestLoadTLSConfig(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateTestCert(t, dir, "test.example.com")

	cfg := &config.TLSConfig{
		Certificates: []config.CertificateConfig{
			{CertFile: certFile, KeyFile: keyFile},
		},
	}

	tlsCfg, err := loadTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(tlsCfg.Certificates))
	}
	if tlsCfg.Certificates[0].Leaf == nil {
		t.Fatal("expected leaf cert to be parsed")
	}
	// Default min_version should be TLS 1.2.
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected MinVersion TLS 1.2, got %d", tlsCfg.MinVersion)
	}
}

func TestLoadTLSConfigMinVersion(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateTestCert(t, dir, "test.example.com")

	tests := []struct {
		minVersion string
		want       uint16
		wantErr    bool
	}{
		{"", tls.VersionTLS12, false},
		{"1.2", tls.VersionTLS12, false},
		{"1.3", tls.VersionTLS13, false},
		{"1.1", 0, true},
		{"invalid", 0, true},
	}

	for _, tc := range tests {
		t.Run("min_version="+tc.minVersion, func(t *testing.T) {
			cfg := &config.TLSConfig{
				Certificates: []config.CertificateConfig{
					{CertFile: certFile, KeyFile: keyFile},
				},
				MinVersion: tc.minVersion,
			}
			tlsCfg, err := loadTLSConfig(cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tlsCfg.MinVersion != tc.want {
				t.Fatalf("expected MinVersion %d, got %d", tc.want, tlsCfg.MinVersion)
			}
		})
	}
}

func TestLoadTLSConfigEmpty(t *testing.T) {
	cfg := &config.TLSConfig{}
	tlsCfg, err := loadTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg != nil {
		t.Fatal("expected nil tls.Config for empty cert list")
	}
}

func TestLoadTLSConfigBadFile(t *testing.T) {
	cfg := &config.TLSConfig{
		Certificates: []config.CertificateConfig{
			{CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem"},
		},
	}
	_, err := loadTLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for bad cert files")
	}
}

func generateTestCert(t *testing.T, dir, hostname string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(dir, hostname+".pem")
	keyPath := filepath.Join(dir, hostname+"-key.pem")

	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		certOut.Close()
		t.Fatal(err)
	}
	certOut.Close()

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		keyOut.Close()
		t.Fatal(err)
	}
	keyOut.Close()

	return certPath, keyPath
}
