package common

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

var DefaultTimeout = 10 * time.Second

var allowedCommands = map[string]bool{
	"systemctl":   true,
	"ss":          true,
	"sysctl":      true,
	"iptables":    true,
	"firewall-cmd": true,
	"uname":       true,
	"dmesg":       true,
	"lsmod":       true,
	"mount":       true,
	"mokutil":     true,
	"bpftool":     true,
	"sestatus":    true,
	"aa-status":   true,
	"cat":         true,
	"lsattr":      true,
	"getenforce":  true,
	"getfacl":     true,
	"lsblk":       true,
	"openssl":     true,
	"which":       true,
	"passwd":      true,
	"ps":          true,
	"apt":         true,
	"yum":         true,
	"dnf":         true,
	"chronyc":     true,
	"dmsetup":     true,
	"sh":          true,
	"cmd":         true,
}

func RunCmd(name string, args ...string) (string, error) {
	return RunCmdTimeout(DefaultTimeout, name, args...)
}

func RunCmdTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	if !allowedCommands[name] {
		return "", fmt.Errorf("command %q is not in allowlist", name)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", context.DeadlineExceeded
	}
	if err != nil {
		errStr := stderr.String()
		if errStr != "" {
			return stdout.String(), &CommandError{Msg: errStr}
		}
		return stdout.String(), err
	}
	return stdout.String(), nil
}

type CommandError struct {
	Msg string
}

func (e *CommandError) Error() string {
	return e.Msg
}

func RunCmdQuiet(name string, args ...string) (string, bool) {
	out, err := RunCmd(name, args...)
	if err != nil {
		return out, false
	}
	return out, true
}
