//go:build !linux

package main

import (
	"fmt"
	"runtime"
)

func installService(installPath string) error {
	return fmt.Errorf("--install is only supported on Linux with systemd (current OS: %s)", runtime.GOOS)
}

func uninstallService(installPath string) error {
	return fmt.Errorf("--uninstall is only supported on Linux with systemd (current OS: %s)", runtime.GOOS)
}

func checkInstallation(installPath string) error {
	return fmt.Errorf("--check-install is only supported on Linux with systemd (current OS: %s)", runtime.GOOS)
}
