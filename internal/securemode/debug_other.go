//go:build !linux

package securemode

// debuggerAttached reports whether a debugger is attached. Non-Linux
// platforms have no portable TracerPid probe; hardening is best-effort and
// returns false (P1-3).
func debuggerAttached() bool { return false }
