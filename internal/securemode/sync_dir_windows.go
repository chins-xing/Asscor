//go:build windows

package securemode

// syncDir is a no-op on Windows: the OS cannot fsync directory handles
// (FlushFileBuffers fails with access denied, see golang/go#19200), so the
// durable-rename guarantee reduces to the file sync done by syncFile.
func syncDir(dir string) error { return nil }
