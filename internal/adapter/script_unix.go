//go:build linux || darwin

package adapter

import (
	"os"
	"syscall"
)

func isOwnedByRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true // can't determine, err on safe side
	}
	return stat.Uid == 0 && stat.Gid == 0
}
