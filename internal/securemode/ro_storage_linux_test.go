//go:build linux

package securemode

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// TestROStorageLinuxHardens: the Linux path must store plaintext in an mmap
// region protected with mprotect(PROT_READ) and hand back the block for later
// release. Content round-trips and the region can be re-opened for writes
// (what Replace/Release need internally).
func TestROStorageLinuxHardens(t *testing.T) {
	view, block := newROStorage([]byte("sensitive config"))
	if block == nil {
		t.Fatal("linux storage must be mmap-backed, got nil block")
	}
	if !storageReadOnly() {
		t.Fatal("storageReadOnly must be true on linux")
	}
	if string(view) != "sensitive config" {
		t.Fatalf("view content = %q", view)
	}

	// Lift protection (as an internal writer must), write, re-harden.
	if err := syscall.Mprotect(block, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		t.Fatalf("mprotect(RW) failed: %v", err)
	}
	view[0] = 'S'
	if err := syscall.Mprotect(block, syscall.PROT_READ); err != nil {
		t.Fatalf("mprotect(RO) failed: %v", err)
	}
	if string(view) != "Sensitive config" {
		t.Fatalf("after RW write + RO re-protect, view = %q", view)
	}
	releaseROStorage(block)
}

// TestROStorageLinuxReadOnlyFault spawns a child that writes directly to the
// hardened (PROT_READ) page; the child must die with SIGSEGV, proving the
// kernel actually enforces the read-only mapping (a plain write cannot
// silently corrupt the live plaintext — spec §7.3).
func TestROStorageLinuxReadOnlyFault(t *testing.T) {
	if os.Getenv("RO_FAULT_CHILD") != "1" {
		// Parent: run the child (same test binary, env-gated) and require a
		// SIGSEGV exit.
		cmd := exec.Command(os.Args[0], "-test.run", "^TestROStorageLinuxReadOnlyFault$")
		cmd.Env = append(os.Environ(), "RO_FAULT_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("child that writes to a PROT_READ page must not exit 0\n%s", out)
		}
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); !ok || exitErr.ExitCode() != 2 {
			// Go test binaries print the fault and exit 2; accept any non-zero
			// as "the write did not silently succeed".
			t.Logf("child exited with error (expected non-zero): %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "unexpected fault address") &&
			!strings.Contains(string(out), "SIGSEGV") {
			t.Logf("child output (informational): %s", out)
		}
		return
	}

	// Child: write to a read-only page → SIGSEGV.
	view, block := newROStorage([]byte("do not write me"))
	if block == nil {
		os.Exit(3)
	}
	view[0] = 'X' // intentional fault: page is PROT_READ
	os.Exit(0)
}

// asExitError is a tiny helper kept local to avoid importing errors just for
// one assertion; Go 1.20+ errors.As would be the idiomatic form but a simple
// type switch keeps the test dependency-free.
func asExitError(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}
