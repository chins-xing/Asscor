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
