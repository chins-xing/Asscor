package securemode

import (
	"bytes"
	"sync"
	"testing"
)

func TestMemoryGuardBaseline(t *testing.T) {
	g := NewMemoryGuard([]byte("config data"))
	if !g.IntegrityOK() {
		t.Error("fresh guard must be intact")
	}
}

func TestMemoryGuardDetectsMutation(t *testing.T) {
	g := NewMemoryGuard([]byte("original"))
	// Simulate an attacker (or bug) mutating the internal buffer. On Linux the
	// storage is mprotect(PROT_READ); the test helper lifts protection first
	// (as a real attacker with write access must), then re-hardens.
	g.mu.Lock()
	mutateGuardData(g)
	g.mu.Unlock()
	if g.IntegrityOK() {
		t.Error("mutation must be detected by baseline hash")
	}
}

func TestMemoryGuardReplaceUpdatesBaseline(t *testing.T) {
	g := NewMemoryGuard([]byte("old"))
	g.Replace([]byte("new value"))
	if !g.IntegrityOK() {
		t.Error("Replace must re-baseline")
	}
	if got := string(g.Snapshot()); got != "new value" {
		t.Errorf("snapshot = %q, want new value", got)
	}
}

func TestMemoryGuardSnapshotImmutable(t *testing.T) {
	g := NewMemoryGuard([]byte("data"))
	snap := g.Snapshot()
	g.Replace([]byte("changed"))
	if bytes.Equal(snap, g.Snapshot()) {
		t.Error("snapshot must be an independent copy, not a view")
	}
}

func TestMemoryGuardConcurrent(t *testing.T) {
	g := NewMemoryGuard([]byte("init"))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				g.IntegrityOK()
				g.Snapshot()
			}
		}()
	}
	wg.Wait()
	if !g.IntegrityOK() {
		t.Error("concurrent reads must not corrupt state")
	}
}
