package securemode

// Hardened plaintext storage for MemoryGuard (spec §7.3).
//
// The implementation is platform-split so the guard can hold its plaintext in
// read-only memory where the OS supports it and degrade to a plain heap copy
// elsewhere:
//
//	ro_storage_linux.go  — plaintext in an mmap region mprotect(PROT_READ)
//	ro_storage_other.go  — plaintext in an ordinary heap copy (no mprotect)
//
// Contract implemented by both platform files:
//
//	newROStorage(src []byte) (view []byte, block []byte)
//	    Stores a copy of src. view has len == len(src) and is the read-only
//	    view callers may read (never write). block is the backing allocation
//	    that must be handed to releaseROStorage when the storage is replaced.
//
//	releaseROStorage(block []byte)
//	    Frees the backing allocation (munmap on Linux; no-op for heap copies).
//	    Safe with a nil block.
//
//	storageReadOnly() bool
//	    Reports whether the current platform actually hardened the region
//	    (Linux mprotect). Tests use it to decide whether a deliberate
//	    mutation must first lift the read-only protection.
//
// Positioning (review P1-3): runtime hardening, not a tamper-proof guarantee.
// A read-only page stops accidental or bug-driven mutation of the live
// plaintext and forces an attacker who wants to rewrite it to first lift the
// protection with an explicit, syscall-visible mprotect; it does not stop an
// attacker with kernel-level privileges. Where the platform cannot harden,
// storage degrades to a heap copy and the guard's SHA-256 baseline remains
// the integrity backstop.
