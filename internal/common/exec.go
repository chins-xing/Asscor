package common

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var DefaultTimeout = 10 * time.Second

// allowedCommandsMu guards allowedCommands so the kernel→agent config sync
// (AddAllowedCommands) can extend the whitelist at runtime without racing
// concurrent check executions.
var allowedCommandsMu sync.RWMutex

var allowedCommands = map[string]bool{
	"systemctl":    true,
	"ss":           true,
	"sysctl":       true,
	"iptables":     true,
	"nft":          true,
	"firewall-cmd": true,
	"uname":        true,
	"dmesg":        true,
	"lsmod":        true,
	"mokutil":      true,
	"bpftool":      true,
	"sestatus":     true,
	"aa-status":    true,
	"lsattr":       true,
	"getenforce":   true,
	"getfacl":      true,
	"lsblk":        true,
	"openssl":      true,
	"which":        true,
	"ps":           true,
	"chronyc":      true,
	"dmsetup":      true,
	"rpm":          true,
	"dpkg-query":   true,
	"pacman":       true,
}

var allowedShellCommands = map[string]bool{
	"systemctl status":               true,
	"ss -tlnp":                       true,
	"ss -tln":                        true,
	"sysctl net.ipv4.tcp_syncookies": true,
	"iptables -L -n":                 true,
	"firewall-cmd --list-all":        true,
	"uname -r":                       true,
	"dmesg":                          true,
	"lsmod":                          true,
	"sestatus":                       true,
	"aa-status":                      true,
	"getenforce":                     true,
	"ps aux":                         true,
	"chronyc tracking":               true,
}

func IsCommandAllowed(name string) bool {
	allowedCommandsMu.RLock()
	defer allowedCommandsMu.RUnlock()
	return allowedCommands[name]
}

// AddAllowedCommands appends extra whitelisted command names to the execution
// allowlist (idempotent, thread-safe). This is how the kernel extends an
// agent's check-command whitelist centrally via the config-sync channel
// (AgentCheckConfig.AllowedCommands): the built-in 25-command baseline can
// never be removed, only augmented by the trusted control plane.
func AddAllowedCommands(names ...string) {
	allowedCommandsMu.Lock()
	defer allowedCommandsMu.Unlock()
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n != "" {
			allowedCommands[n] = true
		}
	}
}

// ContainsShellMetachar reports whether s contains characters that would be
// interpreted by a shell (pipes, redirection, command substitution, job
// control). Callers that execute commands directly (without a shell) reject
// such input to prevent shell injection via configuration.
func ContainsShellMetachar(s string) bool {
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
	allowedCommandsMu.RLock()
	defer allowedCommandsMu.RUnlock()
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
	allowedCommandsMu.RLock()
	ok := allowedCommands[name]
	allowedCommandsMu.RUnlock()
	if !ok {
		return "", fmt.Errorf("command %q is not in allowlist", name)
	}

	for i, arg := range args {
		if ContainsShellMetachar(arg) {
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
			if isPermissionError(errStr) {
				return stdout.String(), &PermissionError{Msg: errStr}
			}
			return stdout.String(), &CommandError{Msg: errStr}
		}
		if isPermissionError(err.Error()) {
			return stdout.String(), &PermissionError{Msg: err.Error()}
		}
		return stdout.String(), err
	}
	return stdout.String(), nil
}

func isPermissionError(s string) bool {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "permission denied") ||
		strings.Contains(lower, "permission_error") ||
		strings.Contains(lower, "operation not permitted") ||
		strings.Contains(lower, "access denied") ||
		strings.Contains(lower, "access is denied") ||
		strings.Contains(lower, "authentication failure") ||
		strings.Contains(lower, "eacces") ||
		strings.Contains(lower, "eperm") {
		return true
	}
	if strings.Contains(s, "权限") ||
		strings.Contains(s, "无权限") ||
		strings.Contains(s, "拒绝访问") ||
		strings.Contains(s, "許可") {
		return true
	}
	if strings.Contains(lower, "open ") && strings.Contains(lower, "permission denied") {
		return true
	}
	return false
}

type PermissionError struct {
	Msg string
}

func (e *PermissionError) Error() string {
	return "permission denied: " + e.Msg
}

func IsPermissionError(err error) bool {
	_, ok := err.(*PermissionError)
	return ok
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

func ParseInt(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty string in ParseInt")
	}
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid digit in ParseInt: %q in %q", c, s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
