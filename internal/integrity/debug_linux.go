//go:build linux && integrity

package integrity

import (
	"os"
	"strconv"
	"strings"
)

func IsDebugged() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pid, _ := strconv.Atoi(fields[1])
				return pid != 0
			}
		}
	}
	return false
}
