//go:build linux

package securemode

import (
	"os"
	"strconv"
	"strings"
)

// debuggerAttached reports whether a debugger/tracer is currently attached to
// this process (Linux /proc/self/status TracerPid). It mirrors
// integrity.IsDebugged() (spec §7.3 "reuse the existing anti-debug
// capability") but is implemented here so securemode stays independent of the
// integrity module's build tag. Hardening only: a detected tracer is logged
// and sensitive operations are refused, not a tamper-proof guarantee (P1-3).
func debuggerAttached() bool {
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
