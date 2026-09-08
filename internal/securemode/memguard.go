package securemode

import (
	"crypto/sha256"
	"sync"
)

// MemoryGuard keeps the run-mode in-memory config with an integrity baseline.
// It exposes read-only snapshots and a controlled Replace path; any mutation
// outside those channels is detected by IntegrityOK.
//
// Spec §7.3 hardening: on Linux the live plaintext is held in a page-aligned
// mmap region that is mprotect(PROT_READ) — ordinary or bug-driven writes
// fault instead of silently corrupting the config. The storage degrades to a
// plain heap copy on platforms without portable mprotect (see ro_storage_*).
//
// Positioning (spec §7, review P1-3): this is runtime hardening, not a
// tamper-proof guarantee. The baseline hash raises the bar for silent memory
// modification, the read-only page stops accidental writes and forces a
// deliberate attacker to lift the protection with an explicit syscall, and
// the combination delays forensic extraction — none of it promises to stop
// attackers with kernel-level privileges (root, kernel modules, physical
// memory access). The security model boundary is "plaintext config appears
// only in process memory while in run mode"; these measures make
// reading/rewriting that plaintext harder and more detectable, not impossible.
type MemoryGuard struct {
	mu    sync.RWMutex
	data  []byte // hardened view (len == plaintext len)
	block []byte // backing allocation for release (mmap region, or heap copy)
	// baseline is the SHA-256 of the protected plaintext, held in the SAME
	// hardened storage class as data (audit RC-M2): on Linux it lives in a
	// separate read-only mmap region, so mutating it to defeat IntegrityOK
	// requires the same deliberate mprotect-lift as rewriting the data. On
	// platforms without mprotect both degrade to heap copies and the hash is
	// the remaining backstop.
	baseline      []byte // hardened view of the 32-byte digest
	baselineBlock []byte // backing allocation for release
}

// NewMemoryGuard snapshots the baseline of plaintext and stores it in
// hardened (read-only where supported) memory.
func NewMemoryGuard(plaintext []byte) *MemoryGuard {
	view, block := newROStorage(plaintext)
	g := &MemoryGuard{data: view, block: block}
	g.rebaselineLocked()
	return g
}

// rebaselineLocked computes the digest of the current data and installs it
// into hardened storage. Callers hold g.mu.
func (g *MemoryGuard) rebaselineLocked() {
	digest := sha256.Sum256(g.data)
	if g.baselineBlock != nil {
		releaseROStorage(g.baselineBlock)
	}
	bv, bb := newROStorage(digest[:])
	g.baseline = bv
	g.baselineBlock = bb
}

// Release frees the backing allocations (munmap on Linux). The guard must not
// be used after Release. Controller calls it when a guard is replaced or when
// leaving run mode so repeated enter/exit cycles do not leak mappings.
func (g *MemoryGuard) Release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	releaseROStorage(g.block)
	releaseROStorage(g.baselineBlock)
	g.block = nil
	g.data = nil
	g.baselineBlock = nil
	g.baseline = nil
}

// IntegrityOK recomputes the hash of the current data and compares with the
// hardened baseline. Call before every config read / mode exit.
func (g *MemoryGuard) IntegrityOK() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	digest := sha256.Sum256(g.data)
	if len(g.baseline) != len(digest) {
		return false
	}
	for i := range digest {
		if digest[i] != g.baseline[i] {
			return false
		}
	}
	return true
}

// Snapshot returns an immutable copy of the current config.
func (g *MemoryGuard) Snapshot() []byte {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return append([]byte(nil), g.data...)
}

// Replace rebuilds the config through the controlled channel and re-baselines.
// The old backing allocation is released and a fresh hardened region is
// allocated for the new plaintext.
func (g *MemoryGuard) Replace(newPlaintext []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	view, block := newROStorage(newPlaintext)
	releaseROStorage(g.block)
	g.data = view
	g.block = block
	g.rebaselineLocked()
}
