//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// isDebugged attempts to detect whether the current process is being traced
// (gdb, strace, ltrace) or debugged. It reads /proc/self/status TracerPid.
// Returns true if a debugger/tracer is attached.
//
// Security note: this is a best-effort runtime integrity guard. A determined
// attacker can bypass user-space ptrace checks. It is complementary to
// build hardening (-trimpath, -s -w), HMAC signing of assessment results,
// and algorithm constant integrity verification.
func isDebugged() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pid, err := strconv.Atoi(fields[1])
				if err != nil {
					return false
				}
				return pid != 0
			}
		}
	}
	return false
}
