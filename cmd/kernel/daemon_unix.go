//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func daemonizePlatform(pidFilePath string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	args := make([]string, 0, len(os.Args))
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--daemon" || os.Args[i] == "-daemon" {
			continue
		}
		args = append(args, os.Args[i])
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/null: %w", err)
	}

	cmd := exec.Command(exe, args...)
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		devNull.Close()
		return fmt.Errorf("start daemon process: %w", err)
	}
	devNull.Close()

	pid := cmd.Process.Pid
	if err := os.WriteFile(pidFilePath, []byte(fmt.Sprintf("%d\n", pid)), 0644); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}

	fmt.Printf("ARGUS μKernel started as daemon (PID: %d, PID file: %s)\n", pid, pidFilePath)
	os.Exit(0)
	return nil
}
