//go:build !linux && !darwin

package adapter

import "os"

func isOwnedByRoot(info os.FileInfo) bool {
	return true
}
