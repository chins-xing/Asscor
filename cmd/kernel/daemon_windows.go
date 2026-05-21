//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

const (
	_DETACHED_PROCESS       = 0x00000008
	_CREATE_NEW_PROCESS_GROUP = 0x00000200
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

	cmd := exec.Command(exe, args...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start detached process: %w", err)
	}

	pid := cmd.Process.Pid
	if err := os.WriteFile(pidFilePath, []byte(fmt.Sprintf("%d\n", pid)), 0644); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}

	fmt.Printf("ARGUS μKernel started as daemon (PID: %d, PID file: %s)\n", pid, pidFilePath)
	return nil
}
