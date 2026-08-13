//go:build !linux

package cli

import (
	"fmt"
	"runtime"
)

func InstallAgent() error {
	return fmt.Errorf("--install is only supported on Linux (current OS: %s)", runtime.GOOS)
}

func UninstallAgent() error {
	return fmt.Errorf("--uninstall is only supported on Linux (current OS: %s)", runtime.GOOS)
}

func UpgradeAgent() error {
	return fmt.Errorf("--upgrade is only supported on Linux (current OS: %s)", runtime.GOOS)
}
