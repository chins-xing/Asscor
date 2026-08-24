//go:build securemode

package main

import (
	"fmt"

	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/securemode"
)

// initSecureMode assembles the kernel-side secure-mode controller. The
// config.ini path comes from the kernel's resolved -config flag; the
// bootstrap section stays plaintext for connectivity essentials.
func initSecureMode(k kernel.KernelContext, dataDir, configPath string) (*securemode.Controller, error) {
	if dataDir == "" {
		dataDir = "/var/lib/asscor"
	}
	vault := &securemode.Vault{
		DataDir:         dataDir,
		ConfigPath:      configPath,
		BootstrapHeader: "[bootstrap]",
	}
	ctrl := securemode.NewController(dataDir, []*securemode.Vault{vault})
	if err := ctrl.Startup(); err != nil {
		return nil, fmt.Errorf("secure mode startup: %w", err)
	}
	if ctrl.Mode == securemode.ModeRun {
		// Kernel was in run mode at shutdown: serving stays gated until the
		// operator unlocks with the run-mode password. Serving gating is
		// wired in a later task; the CLI unlock flow (Controller.Unlock)
		// complements `mode status`.
	}
	return ctrl, nil
}
