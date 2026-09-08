//go:build !resilience

package main

// resilienceFeatureEnabled reports whether the resilience module's real
// implementation is compiled in. Without the tag the module degrades to
// no-op pass-throughs.
func resilienceFeatureEnabled() bool { return false }
