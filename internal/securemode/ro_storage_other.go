//go:build !linux

package securemode

// storageReadOnly reports whether the current platform hardened the region.
// Non-Linux platforms have no portable mprotect for plaintext hardening, so
// the storage is an ordinary heap copy and the guard relies on its SHA-256
// baseline (spec §7.3, P1-3: best-effort runtime hardening).
func storageReadOnly() bool { return false }

// newROStorage copies src into a heap slice. view and block alias the same
// copy; releaseROStorage is a no-op for heap storage.
func newROStorage(src []byte) (view []byte, block []byte) {
	cp := make([]byte, len(src))
	copy(cp, src)
	return cp, cp
}

// releaseROStorage is a no-op for heap-backed storage.
func releaseROStorage(block []byte) {}
