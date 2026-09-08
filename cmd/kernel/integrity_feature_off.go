//go:build !integrity

package main

// integrityFeatureEnabled reports whether the integrity module's real
// implementation is compiled in. Without the tag the package compiles a
// no-op stub (GetSigner returns a no-op Signer), so results are not signed.
func integrityFeatureEnabled() bool { return false }
