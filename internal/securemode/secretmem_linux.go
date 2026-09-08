//go:build linux

package securemode

import "syscall"

// PR_SET_DUMPABLE constant (prctl(2)); defined here to avoid depending on
// golang.org/x/sys just for one syscall.
const prSetDumpable = 4

// DumpableDisabled reports whether the process currently has core dumps and
// /proc/pid/mem access disabled (PR_SET_DUMPABLE=0).
var dumpableDisabled = false

// disableCoreDumps sets PR_SET_DUMPABLE=0 (audit RC-H2): while a run-mode
// password is retained in this process, coredumps and /proc/<pid>/mem reads
// would let a local observer extract the secret from memory. Best-effort —
// an error is logged by the caller but does not fail the mode transition
// (hardening, P1-3).
func disableCoreDumps() error {
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetDumpable, 0, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	dumpableDisabled = true
	return nil
}

// enableCoreDumps restores PR_SET_DUMPABLE=1 (exit run / password cleared).
func enableCoreDumps() error {
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetDumpable, 1, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	dumpableDisabled = false
	return nil
}
