//go:build integrity

package main

// integrityFeatureEnabled reports whether the integrity module's real
// implementation (HMAC signing, algorithm verification) is compiled in.
// Without the integrity build tag the package compiles a no-op stub, so an
// enabled assessor would silently produce unsigned results (coupling audit
// 2026-09-03, finding F3). The kernel startup check uses this to warn when
// integrity-dependent features are enabled without it.
func integrityFeatureEnabled() bool { return true }
