//go:build linux

package deploy

import (
	"fmt"
	"os"
	"os/exec"
)

func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this operation requires root privileges")
	}
	return nil
}

func copySelfTo(targetPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return fmt.Errorf("read self: %w", err)
	}
	if err := os.WriteFile(targetPath, data, 0755); err != nil {
		return fmt.Errorf("write binary to %s: %w", targetPath, err)
	}
	return nil
}

func systemctlReload() {
	exec.Command("systemctl", "daemon-reload").Run()
}

func systemctlStopDisable(serviceName string) {
	exec.Command("systemctl", "stop", serviceName).Run()
	exec.Command("systemctl", "disable", serviceName).Run()
}

func chownAsscor(paths ...string) {
	for _, p := range paths {
		exec.Command("chown", "-R", "asscor:asscor", p).Run()
	}
}
