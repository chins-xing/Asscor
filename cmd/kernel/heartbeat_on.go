//go:build heartbeat

package main

import (
	"github.com/asscor/asscor/internal/heartbeat"
	"github.com/asscor/asscor/internal/kernel"
)

// newHeartbeat returns the heartbeat module, or nil when the heartbeat build
// tag is disabled (kernel zero-bloat). The concrete *heartbeat.Module
// satisfies both kernel.Plugin and kernel.HeartbeatInterface.
func newHeartbeat() kernel.HeartbeatInterface {
	return heartbeat.New()
}
