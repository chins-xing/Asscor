package securemode

import (
	"crypto/sha256"
	"sync"
)

// MemoryGuard keeps the run-mode in-memory config with an integrity baseline.
// It exposes read-only snapshots and a controlled Replace path; any mutation
// outside those channels is detected by IntegrityOK.
//
// Positioning (spec §7, review P1-3): this is runtime hardening, not a
// tamper-proof guarantee. The baseline hash raises the bar for silent memory
// modification, delays forensic extraction, and increases the detection
// probability — it does not promise to stop attackers with kernel-level
// privileges (root, kernel modules, physical memory access). The security
// model boundary is "plaintext config appears only in process memory while
// in run mode"; these measures make reading/rewriting that plaintext harder
// and more detectable, not impossible.
type MemoryGuard struct {
	mu       sync.RWMutex
	data     []byte
	baseline [sha256.Size]byte
}

// NewMemoryGuard snapshots the baseline of plaintext.
func NewMemoryGuard(plaintext []byte) *MemoryGuard {
	g := &MemoryGuard{data: append([]byte(nil), plaintext...)}
	g.baseline = sha256.Sum256(g.data)
	return g
}

// IntegrityOK recomputes the hash of the current data and compares with the
// baseline. Call before every config read / mode exit.
func (g *MemoryGuard) IntegrityOK() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return sha256.Sum256(g.data) == g.baseline
}

// Snapshot returns an immutable copy of the current config.
func (g *MemoryGuard) Snapshot() []byte {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return append([]byte(nil), g.data...)
}

// Replace rebuilds the config through the controlled channel and re-baselines.
func (g *MemoryGuard) Replace(newPlaintext []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.data = append([]byte(nil), newPlaintext...)
	g.baseline = sha256.Sum256(g.data)
}
