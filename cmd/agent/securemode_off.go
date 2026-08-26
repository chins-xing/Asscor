//go:build !securemode

package main

import (
	"github.com/asscor/asscor/internal/agent"
	"github.com/asscor/asscor/internal/securemode"
)

// agentSecureVault returns a nil vault when the securemode build tag is
// absent — the agent runs in plaintext default mode exactly as before.
func agentSecureVault(cfg agent.AgentConfig) *securemode.Vault {
	return nil
}
