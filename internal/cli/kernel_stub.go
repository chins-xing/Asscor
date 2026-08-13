//go:build !linux

package cli

import (
	"fmt"
	"runtime"
)

func InstallKernel(installPath string) error {
	return fmt.Errorf("--install is only supported on Linux (current OS: %s)", runtime.GOOS)
}

func UninstallKernel(installPath string) error {
	return fmt.Errorf("--uninstall is only supported on Linux (current OS: %s)", runtime.GOOS)
}

func CheckKernelInstall(installPath string) error {
	return fmt.Errorf("--check-install is only supported on Linux (current OS: %s)", runtime.GOOS)
}

func UpgradeKernel(installPath string) error {
	return fmt.Errorf("--upgrade is only supported on Linux (current OS: %s)", runtime.GOOS)
}
