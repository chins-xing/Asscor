//go:build securemode

package main

import (
	"github.com/asscor/asscor/internal/agent"
	"github.com/asscor/asscor/internal/securemode"
)

// agentSecureVault returns the agent's protected-config vault. When the
// securemode tag is enabled, the agent manages agent.ini encryption itself
// (self-generated ephemeral password, kernel-managed lifecycle, spec §3.1).
func agentSecureVault(cfg agent.AgentConfig) *securemode.Vault {
	return &securemode.Vault{
		DataDir:         "",
		ConfigPath:      cfg.ConfigPath,
		BootstrapHeader: "[bootstrap]",
	}
}
