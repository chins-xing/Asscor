//go:build !linux

package agent

import (
	"fmt"

	"github.com/asscor/asscor/internal/model"
)

// PrivilegedClient is a stub on non-Linux platforms.
type PrivilegedClient struct{}

// NewPrivilegedClient returns a stub client.
func NewPrivilegedClient(socketPath string) *PrivilegedClient {
	return &PrivilegedClient{}
}

// RunRootChecks returns nil on non-Linux platforms.
func (c *PrivilegedClient) RunRootChecks() []model.CheckResult {
	return nil
}

// RunRootCommand always fails on non-Linux platforms.
func (c *PrivilegedClient) RunRootCommand(command string, params map[string]string) (string, error) {
	return "", fmt.Errorf("privileged agent is only supported on linux")
}
