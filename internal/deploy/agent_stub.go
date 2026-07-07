//go:build !linux

package deploy

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

func uninstallAgent() error {
	return fmt.Errorf("--uninstall is only supported on Linux with systemd (current OS: %s)", runtime.GOOS)
}

func upgradeAgent() error {
	return fmt.Errorf("--upgrade is only supported on Linux with systemd (current OS: %s)", runtime.GOOS)
}
