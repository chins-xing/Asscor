package securemode

import (
	"crypto/rand"
	"encoding/binary"

	"golang.org/x/crypto/argon2"
)

// DefaultKDFParams returns argon2id parameters (time, memory KiB, threads, keyLen).
func DefaultKDFParams() (n, r, p, keyLen uint32) {
	return 1, 64 * 1024, 4, 32
}

// deriveKey derives a 32-byte key from password+salt via argon2id.
// Note: argon2.IDKey takes threads as uint8, so p is narrowed explicitly.
func deriveKey(password string, salt []byte, n, r, p, keyLen uint32) []byte {
	return argon2.IDKey([]byte(password), salt, n, r, uint8(p), keyLen)
}

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// serializeUint32 / readUint32 helpers keep header encoding explicit.
func serializeUint32(buf []byte, v uint32) { binary.BigEndian.PutUint32(buf, v) }
func readUint32(buf []byte) uint32         { return binary.BigEndian.Uint32(buf) }
