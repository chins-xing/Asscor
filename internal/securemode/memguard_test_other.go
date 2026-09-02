//go:build !linux

package securemode

// mutateGuardData simulates a byte flip in the live plaintext. On non-Linux
// platforms the storage is a plain heap copy (no mprotect), so a direct write
// mirrors what an attacker could do; IntegrityOK must detect it.
func mutateGuardData(g *MemoryGuard) {
	g.data[0] = 'X'
}
