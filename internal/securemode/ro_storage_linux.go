//go:build linux

package securemode

import "syscall"

// storageReadOnly reports that the Linux path hardens the region with
// mprotect(PROT_READ).
func storageReadOnly() bool { return true }

// newROStorage copies src into a page-aligned mmap region and then drops the
// write bit, so the live plaintext cannot be mutated by accidental or
// bug-driven writes (a write faults instead). Returns:
//
//	view  — the read-only slice of len(src) to read from
//	block — the page-aligned allocation, to hand to releaseROStorage
//
// The mmap length is rounded up to the OS page size so mprotect can cover the
// whole region; view trims it back to len(src).
func newROStorage(src []byte) (view []byte, block []byte) {
	if len(src) == 0 {
		return nil, nil
	}
	page := syscall.Getpagesize()
	size := (len(src) + page - 1) &^ (page - 1)
	if size == 0 {
		size = page
	}
	b, err := syscall.Mmap(-1, 0, size,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		// Hardening is best-effort (P1-3): fall back to a plain heap copy so
		// the guard still functions with its SHA-256 baseline.
		cp := make([]byte, len(src))
		copy(cp, src)
		return cp, nil
	}
	copy(b, src)
	if err := syscall.Mprotect(b, syscall.PROT_READ); err != nil {
		// Unlikely (mprotect on our own anonymous map); degrade safely rather
		// than keep a writable page pretending to be hardened.
		syscall.Munmap(b)
		cp := make([]byte, len(src))
		copy(cp, src)
		return cp, nil
	}
	return b[:len(src)], b
}

// releaseROStorage unmaps the page-aligned block (no-op for nil).
func releaseROStorage(block []byte) {
	if block == nil {
		return
	}
	_ = syscall.Munmap(block)
}
