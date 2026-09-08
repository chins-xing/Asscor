//go:build !heartbeat

package main

import "github.com/chins-xing/asscor/internal/kernel"

// newHeartbeat returns nil when the heartbeat module is not compiled in.
func newHeartbeat() kernel.HeartbeatInterface {
	return nil
}
