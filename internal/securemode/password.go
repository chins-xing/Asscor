package securemode

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
)

// PasswordVerifier stores an argon2id hash of the secure-mode password for
// offline verification (verify before attempting decryption). File layout:
// version(1) + saltLen(1) + salt + N(4) + r(4) + p(4) + keyLen(4) + hash.
type PasswordVerifier struct {
	File string
}

// PasswordVerifierPath returns the verifier path under dataDir.
func PasswordVerifierPath(dataDir string) string {
	return filepath.Join(dataDir, ".asscor-pw")
}

// Exists reports whether the verifier file is present.
func (pv *PasswordVerifier) Exists() bool {
	_, err := os.Stat(pv.File)
	return err == nil
}

// Set writes a fresh salt+hash for password (atomic tmp+rename).
func (pv *PasswordVerifier) Set(password string) error {
	if password == "" {
		return errors.New("refusing empty secure-mode password")
	}
	n, r, p, keyLen := DefaultKDFParams()
	salt, err := randomBytes(16)
	if err != nil {
		return err
	}
	hash := deriveKey(password, salt, n, r, p, keyLen)

	var buf []byte
	buf = append(buf, 1) // version
	buf = append(buf, byte(len(salt)))
	buf = append(buf, salt...)
	b4 := make([]byte, 4)
	putU32(b4, n)
	buf = append(buf, b4...)
	putU32(b4, r)
	buf = append(buf, b4...)
	putU32(b4, p)
	buf = append(buf, b4...)
	putU32(b4, keyLen)
	buf = append(buf, b4...)
	buf = append(buf, hash...)

	if err := os.MkdirAll(filepath.Dir(pv.File), 0o700); err != nil {
		return err
	}
	tmp := pv.File + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	if err := syncFile(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, pv.File); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(pv.File))
}

// Verify checks password against the stored hash (constant-time compare).
func (pv *PasswordVerifier) Verify(password string) bool {
	data, err := os.ReadFile(pv.File)
	if err != nil {
		return false
	}
	if len(data) < 1+1+16+16+32 {
		return false
	}
	if data[0] != 1 {
		return false
	}
	saltLen := int(data[1])
	if 1+1+saltLen+16+32 > len(data) {
		return false
	}
	salt := data[2 : 2+saltLen]
	off := 2 + saltLen
	n := getU32(data[off:])
	off += 4
	r := getU32(data[off:])
	off += 4
	p := getU32(data[off:])
	off += 4
	keyLen := getU32(data[off:])
	off += 4
	// n/r/p/keyLen are attacker-controlled file content: feeding non-default
	// values to argon2 can panic (keyLen=0 nil deref, N=0 rounds, p>=256
	// truncated to 0 threads) or cause OOM/CPU DoS, so reject them before any
	// derivation work — same defense as Decrypt's header checks in crypt.go.
	dN, dR, dP, dKL := DefaultKDFParams()
	if n != dN || r != dR || p != dP || keyLen != dKL {
		return false
	}
	expected := data[off : off+int(keyLen)]
	got := deriveKey(password, salt, n, r, p, keyLen)
	if len(got) != len(expected) {
		return false
	}
	return hmac.Equal(got, expected)
}

// Clear removes the verifier file (used when leaving run mode).
func (pv *PasswordVerifier) Clear() error {
	err := os.Remove(pv.File)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func putU32(b []byte, v uint32) { binary.BigEndian.PutUint32(b, v) }
func getU32(b []byte) uint32    { return binary.BigEndian.Uint32(b) }
