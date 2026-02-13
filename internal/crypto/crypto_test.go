package crypto

import (
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	if len(key) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(key))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := "gho_abc123def456"
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	if ciphertext == plaintext {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
	}
}

func TestNewEncryptor_InvalidKey(t *testing.T) {
	_, err := NewEncryptor("tooshort")
	if err == nil {
		t.Error("expected error for short key")
	}

	_, err = NewEncryptor("not-hex-at-all!!!")
	if err == nil {
		t.Error("expected error for non-hex key")
	}
}
