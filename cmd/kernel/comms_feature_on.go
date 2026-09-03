//go:build comms

package main

// commsFeatureEnabled reports whether the comms module (gRPC/JSONRPC servers)
// is compiled in. Used by the module-composition startup check.
func commsFeatureEnabled() bool { return true }
