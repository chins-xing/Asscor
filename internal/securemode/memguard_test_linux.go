//go:build linux

package securemode

import (
	"syscall"
	"testing"
)

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

// TestMemoryGuardBaselineHardened (audit RC-M2): the integrity baseline must
// live in its OWN hardened mmap region — separate from the data block — so an
// attacker who lifts protection to rewrite the plaintext still cannot silently
// rewrite the digest it is checked against (the digest page stays PROT_READ
// until deliberately lifted as well).
func TestMemoryGuardBaselineHardened(t *testing.T) {
	g := NewMemoryGuard([]byte("config that must stay intact"))
	defer g.Release()

	if g.baselineBlock == nil {
		t.Fatal("linux baseline must be mmap-backed (audit RC-M2)")
	}
	if g.block == nil {
		t.Fatal("linux data must be mmap-backed")
	}
	if &g.baselineBlock[0] == &g.block[0] {
		t.Fatal("baseline and data must live in separate allocations")
	}

	// Sanity: untouched guard verifies.
	if !g.IntegrityOK() {
		t.Fatal("pristine guard must pass IntegrityOK")
	}

	// Mutating data alone (even with lifted protection) is still detected
	// because the baseline page was never modified.
	mutateGuardData(g)
	if g.IntegrityOK() {
		t.Error("mutated data must fail IntegrityOK even with hardened baseline")
	}
}

// TestMemoryGuardBaselineReplaceRehardens: Replace must re-install the digest
// into a fresh hardened region (not leave the old block behind or keep a
// writable heap digest).
func TestMemoryGuardBaselineReplaceRehardens(t *testing.T) {
	g := NewMemoryGuard([]byte("v1"))
	defer g.Release()
	oldBaselineBlock := g.baselineBlock

	g.Replace([]byte("version two content"))
	if g.baselineBlock == nil || &g.baselineBlock[0] == &oldBaselineBlock[0] {
		t.Fatal("Replace must allocate a fresh hardened baseline block")
	}
	if !g.IntegrityOK() {
		t.Error("post-Replace guard must verify")
	}
}
