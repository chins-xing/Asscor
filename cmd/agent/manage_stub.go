//go:build !linux

package main

import (
	"fmt"
	"runtime"
)

func installAgent() error {
	return fmt.Errorf("--install is only supported on Linux with systemd (current OS: %s)", runtime.GOOS)
}

func uninstallAgent() error {
	return fmt.Errorf("--uninstall is only supported on Linux with systemd (current OS: %s)", runtime.GOOS)
}

func upgradeAgent() error {
	return fmt.Errorf("--upgrade is only supported on Linux with systemd (current OS: %s)", runtime.GOOS)
}
