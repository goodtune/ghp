//go:build !windows

package securestore

// DPAPITier returns the dpapi tier, which exists only on Windows.
func DPAPITier() Tier {
	return unavailableTier(TierDPAPI, "the dpapi tier is Windows only")
}
