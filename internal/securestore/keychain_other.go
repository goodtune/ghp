//go:build !darwin

package securestore

// KeychainTier returns the keychain tier, which exists only on macOS.
func KeychainTier() Tier {
	return unavailableTier(TierKeychain, "the keychain tier is macOS only")
}
