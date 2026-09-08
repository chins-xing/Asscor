//go:build !windows

package securemode

import "os"

// syncDir fsyncs the directory so the tmp→path rename survives a crash
// (POSIX semantics).
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
