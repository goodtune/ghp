package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Header names GitHub sets on every webhook delivery.
const (
	HeaderDelivery               = "X-GitHub-Delivery"
	HeaderEvent                  = "X-GitHub-Event"
	HeaderHookID                 = "X-GitHub-Hook-ID"
	HeaderInstallationTargetType = "X-GitHub-Hook-Installation-Target-Type"
	HeaderInstallationTargetID   = "X-GitHub-Hook-Installation-Target-ID"
	HeaderSignature256           = "X-Hub-Signature-256"

	// TargetTypeIntegration is the installation target type GitHub sets on
	// deliveries from a GitHub App's webhook. The target ID is then the
	// numeric GitHub App ID.
	TargetTypeIntegration = "integration"

	signaturePrefix = "sha256="
)

// VerifySignature reports whether header (the X-Hub-Signature-256 value) is
// a valid HMAC-SHA256 of body under secret. Comparison is constant-time.
// A missing or malformed header, or an empty secret, never verifies.
func VerifySignature(secret, body []byte, header string) bool {
	if len(secret) == 0 {
		return false
	}
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(header, signaturePrefix) {
		return false
	}
	want, err := hex.DecodeString(header[len(signaturePrefix):])
	if err != nil || len(want) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), want)
}

// Sign computes the X-Hub-Signature-256 header value for body under secret.
// It exists for tests and for the ghp CLI to craft synthetic deliveries.
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return signaturePrefix + hex.EncodeToString(mac.Sum(nil))
}
