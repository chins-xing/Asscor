//go:build resilience

package main

// resilienceFeatureEnabled reports whether the resilience module's real
// implementation (circuit breakers, panic guards, health tracking) is
// compiled in. Without the tag, resilience.Guard/GuardGo degrade to no-op
// pass-throughs — so an enabled comms module would silently run without
// circuit breaking (coupling audit 2026-09-03, finding F3).
func resilienceFeatureEnabled() bool { return true }
