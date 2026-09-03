//go:build !linux

// Package agentinstall provides single-binary agent installation as a Linux
// systemd service. On non-Linux platforms the operations are unsupported and
// report an error instead of silently no-op'ing (mirrors the original cli
// stubs). The package stays free of internal/kernel dependencies (coupling
// audit 2026-09-03, finding C1).
package agentinstall

import (
	"fmt"
	"runtime"
)

// Install is unsupported on non-Linux platforms.
func Install() error {
	return fmt.Errorf("--install is only supported on Linux (current OS: %s)", runtime.GOOS)
}

// Uninstall is unsupported on non-Linux platforms.
func Uninstall() error {
	return fmt.Errorf("--uninstall is only supported on Linux (current OS: %s)", runtime.GOOS)
}

// Upgrade is unsupported on non-Linux platforms.
func Upgrade() error {
	return fmt.Errorf("--upgrade is only supported on Linux (current OS: %s)", runtime.GOOS)
}
