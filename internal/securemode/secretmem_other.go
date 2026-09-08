//go:build !linux

package securemode

// disableCoreDumps is a no-op on platforms without portable prctl
// (PR_SET_DUMPABLE). Best-effort hardening (P1-3).
func disableCoreDumps() error { return nil }

// enableCoreDumps is a no-op on non-Linux platforms.
func enableCoreDumps() error { return nil }
