package common

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
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
	"mokutil":     true,
	"bpftool":     true,
	"sestatus":    true,
	"aa-status":   true,
	"lsattr":      true,
	"getenforce":  true,
	"getfacl":     true,
	"lsblk":       true,
	"openssl":     true,
	"which":       true,
	"ps":          true,
	"chronyc":     true,
	"dmsetup":     true,
}

var allowedShellCommands = map[string]bool{
	"systemctl status":  true,
	"ss -tlnp":         true,
	"ss -tln":          true,
	"sysctl net.ipv4.tcp_syncookies": true,
	"iptables -L -n":   true,
	"firewall-cmd --list-all": true,
	"uname -r":         true,
	"dmesg":            true,
	"lsmod":            true,
	"sestatus":         true,
	"aa-status":        true,
	"getenforce":       true,
	"ps aux":           true,
	"chronyc tracking": true,
}

func IsCommandAllowed(name string) bool {
	return allowedCommands[name]
}

func containsShellMetachar(s string) bool {
	return strings.ContainsAny(s, "|;&`$()<>{}\n\r")
}

func IsShellCommandAllowed(cmd string) bool {
	return allowedShellCommands[cmd]
}

func ParseCommand(cmd string) (name string, args []string, ok bool) {
	parts := splitCommand(cmd)
	if len(parts) == 0 {
		return "", nil, false
	}
	name = parts[0]
	args = parts[1:]
	if !allowedCommands[name] {
		return "", nil, false
	}
	return name, args, true
}

func splitCommand(cmd string) []string {
	var parts []string
	var current []byte
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case c == '\'' || c == '"':
			if inQuote {
				if c == quoteChar {
					inQuote = false
					quoteChar = 0
				} else {
					current = append(current, c)
				}
			} else {
				inQuote = true
				quoteChar = c
			}
		case c == ' ' || c == '\t':
			if inQuote {
				current = append(current, c)
			} else if len(current) > 0 {
				parts = append(parts, string(current))
				current = current[:0]
			}
		case c == '|' || c == ';' || c == '&' || c == '`' || c == '$' || c == '(' || c == ')' || c == '<' || c == '>':
			if !inQuote {
				return nil
			}
			current = append(current, c)
		default:
			current = append(current, c)
		}
	}
	if len(current) > 0 {
		parts = append(parts, string(current))
	}
	return parts
}

func RunCmd(name string, args ...string) (string, error) {
	return RunCmdTimeout(DefaultTimeout, name, args...)
}

func RunCmdTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	if !allowedCommands[name] {
		return "", fmt.Errorf("command %q is not in allowlist", name)
	}

	for i, arg := range args {
		if containsShellMetachar(arg) {
			return "", fmt.Errorf("argument %d contains shell metacharacters: %q", i, arg)
		}
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
