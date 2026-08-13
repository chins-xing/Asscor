//go:build !linux

package agent

import "fmt"

// PrivilegedConfig configures the privileged agent process (Linux-only). On
// non-Linux platforms the privileged agent is unsupported.
type PrivilegedConfig struct {
	AllowedPeerUID int
	SocketPath     string
}

// PrivilegedAgent is the root-privileged worker process (Linux-only).
type PrivilegedAgent struct {
	cfg PrivilegedConfig
}

// NewPrivilegedAgent always fails on non-Linux platforms.
func NewPrivilegedAgent(cfg PrivilegedConfig) (*PrivilegedAgent, error) {
	return nil, fmt.Errorf("privileged agent is only supported on linux")
}

// Run always fails on non-Linux platforms.
func (p *PrivilegedAgent) Run() error {
	return fmt.Errorf("privileged agent is only supported on linux")
}

// LookupUID is a no-op stub on non-Linux platforms.
func LookupUID(name string) int {
	return 0
}
