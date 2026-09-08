//go:build !comms

package main

// commsFeatureEnabled reports whether the comms module (gRPC/JSONRPC servers)
// is compiled in.
func commsFeatureEnabled() bool { return false }
