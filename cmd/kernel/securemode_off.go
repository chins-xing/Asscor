//go:build !securemode

package main

import (
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/securemode"
)

// initSecureMode returns a nil controller when the securemode build tag is
// absent — the kernel runs in plaintext default mode exactly as before.
func initSecureMode(k kernel.KernelContext, dataDir, configPath string) (*securemode.Controller, error) {
	return nil, nil
}

// wireSecureModeConfigLoader is a no-op without the securemode tag: the
// config watcher keeps reloading the plaintext config.ini as before.
func wireSecureModeConfigLoader(cw *kernel.ConfigWatcherModule, ctrl *securemode.Controller, configPath string) {
}

// wireSecureModeConfigApply is a no-op without the securemode tag: there is
// no run-mode config to feed into the kernel runtime.
func wireSecureModeConfigApply(k *kernel.Kernel, assessor kernel.AssessorInterface, mcli *securemode.ModeCLI) {
}
