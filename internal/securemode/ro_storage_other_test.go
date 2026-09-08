//go:build !linux

package securemode

import "testing"

// TestROStorageNonLinuxDegrades: non-Linux platforms store a plain heap copy
// (no mprotect available portably) and the guard still round-trips.
func TestROStorageNonLinuxDegrades(t *testing.T) {
	view, block := newROStorage([]byte("config"))
	if storageReadOnly() {
		t.Fatal("non-linux must report read-only=false")
	}
	if string(view) != "config" {
		t.Fatalf("view content = %q", view)
	}
	// Heap copy must be writable (Replace semantics rely on it).
	view[0] = 'C'
	if string(view) != "Config" {
		t.Fatalf("unexpected view after write: %q", view)
	}
	releaseROStorage(block) // no-op, must not panic
}
