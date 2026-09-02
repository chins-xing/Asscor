//go:build linux

package securemode

import "syscall"

// mutateGuardData simulates an attacker who lifts the read-only page
// protection (an explicit, detectable mprotect(PROT_READ|PROT_WRITE)), flips
// one byte of the live plaintext, and re-hardens. IntegrityOK must then
// report tampering. On non-Linux the storage is a heap copy and the same
// helper is a plain byte write (see ro_storage_other_test.go).
func mutateGuardData(g *MemoryGuard) {
	block := g.block
	if block == nil {
		// Degraded heap storage — plain write suffices.
		g.data[0] = 'X'
		return
	}
	// block is the page-aligned mmap region; lift protection on it.
	if err := syscall.Mprotect(block, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		panic("test: mprotect(RW) failed: " + err.Error())
	}
	g.data[0] = 'X'
	if err := syscall.Mprotect(block, syscall.PROT_READ); err != nil {
		panic("test: mprotect(RO) failed: " + err.Error())
	}
}
