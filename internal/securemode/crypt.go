package securemode

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Header is the serialized .enc file header.
type Header struct {
	Magic    [4]byte
	Version  byte
	Salt     []byte
	ArgonN   uint32
	ArgonR   uint32
	ArgonP   uint32
	KeyLen   uint32
	Envelope []byte // DEK encrypted with KEK (AES-GCM)
	Nonce    []byte // GCM nonce for envelope
}

// DefaultKDFParams returns argon2id parameters (time, memory KiB, threads, keyLen).
func DefaultKDFParams() (n, r, p, keyLen uint32) {
	return 1, 64 * 1024, 4, 32
}

// deriveKey derives a key of keyLen bytes from password+salt via argon2id.
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

// NewEphemeralPassword returns a hex-encoded ephemeral unlock secret (32
// random bytes). Agents self-generate it at startup and on rotation; it is a
// TEMPORARY per-run secret (spec §3.1/P1-1) that must never be persisted.
func NewEphemeralPassword() (string, error) {
	b, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// serializeUint32 / readUint32 helpers keep header encoding explicit.
func serializeUint32(buf []byte, v uint32) { binary.BigEndian.PutUint32(buf, v) }
func readUint32(buf []byte) uint32         { return binary.BigEndian.Uint32(buf) }

// zeroize wipes a key buffer after use.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Encrypt envelope-encrypts plaintext with password:
//
//	DEK (random 32B) encrypts plaintext via AES-256-GCM;
//	KEK = argon2id(password, salt) encrypts DEK.
//
// Returns the complete .enc file content (header + ciphertext).
func Encrypt(plaintext []byte, password string) ([]byte, error) {
	n, r, p, keyLen := DefaultKDFParams()
	salt, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	kek := deriveKey(password, salt, n, r, p, keyLen)
	defer zeroize(kek)

	dek, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	defer zeroize(dek)

	// Envelope: KEK encrypts DEK.
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	envNonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, envNonce); err != nil {
		return nil, err
	}
	envelope := gcm.Seal(nil, envNonce, dek, nil)

	// Payload: DEK encrypts plaintext.
	block2, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm2, err := cipher.NewGCM(block2)
	if err != nil {
		return nil, err
	}
	payNonce := make([]byte, gcm2.NonceSize())
	if _, err := io.ReadFull(rand.Reader, payNonce); err != nil {
		return nil, err
	}
	ciphertext := gcm2.Seal(payNonce, payNonce, plaintext, nil) // nonce-prepended

	h := &Header{
		Salt:     salt,
		ArgonN:   n,
		ArgonR:   r,
		ArgonP:   p,
		KeyLen:   keyLen,
		Envelope: envelope,
		Nonce:    envNonce,
	}
	copy(h.Magic[:], Magic)
	h.Version = Version

	head, err := marshalHeader(h)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(head)+len(ciphertext))
	out = append(out, head...)
	out = append(out, ciphertext...)
	return out, nil
}

// Decrypt reverses Encrypt. Wrong password, tampered data, or a malformed
// header all return an error.
func Decrypt(data []byte, password string) ([]byte, error) {
	if len(data) > MaxConfigSize {
		return nil, fmt.Errorf("encrypted config too large: %d bytes", len(data))
	}
	h, off, err := parseHeader(data)
	if err != nil {
		return nil, err
	}
	// v1 files are written only by Encrypt, which always records the default
	// KDF parameters. Any other values are attacker-controlled header input
	// that could panic argon2 (threads<1 after uint8 narrowing) or trigger an
	// OOM/CPU DoS from unbounded memory/time costs, so reject them before any
	// derivation.
	n, r, p, kl := DefaultKDFParams()
	if h.ArgonN != n || h.ArgonR != r || h.ArgonP != p || h.KeyLen != kl {
		return nil, errors.New("unsupported KDF parameters in header")
	}
	kek := deriveKey(password, h.Salt, n, r, p, kl)
	defer zeroize(kek)

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(h.Nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce length in header")
	}
	dek, err := gcm.Open(nil, h.Nonce, h.Envelope, nil)
	if err != nil {
		return nil, errors.New("password incorrect or envelope corrupted")
	}
	defer zeroize(dek)

	block2, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm2, err := cipher.NewGCM(block2)
	if err != nil {
		return nil, err
	}
	payload := data[off:]
	if len(payload) < gcm2.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := payload[:gcm2.NonceSize()]
	ct := payload[gcm2.NonceSize():]
	plain, err := gcm2.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("ciphertext authentication failed (tampered?)")
	}
	return plain, nil
}

func marshalHeader(h *Header) ([]byte, error) {
	if len(h.Magic) != 4 {
		return nil, errors.New("bad magic length")
	}
	if len(h.Salt) > 0xFFFF || len(h.Envelope) > 0xFFFFFFFF || len(h.Nonce) > 0xFFFF {
		return nil, errors.New("header field too large")
	}
	buf := &bytes.Buffer{}
	buf.Write(h.Magic[:])
	buf.WriteByte(h.Version)
	binary.Write(buf, binary.BigEndian, uint16(len(h.Salt)))
	buf.Write(h.Salt)
	var u32 [4]byte
	serializeUint32(u32[:], h.ArgonN)
	buf.Write(u32[:])
	serializeUint32(u32[:], h.ArgonR)
	buf.Write(u32[:])
	serializeUint32(u32[:], h.ArgonP)
	buf.Write(u32[:])
	serializeUint32(u32[:], h.KeyLen)
	buf.Write(u32[:])
	binary.Write(buf, binary.BigEndian, uint32(len(h.Envelope)))
	buf.Write(h.Envelope)
	binary.Write(buf, binary.BigEndian, uint16(len(h.Nonce)))
	buf.Write(h.Nonce)
	return buf.Bytes(), nil
}

func parseHeader(data []byte) (*Header, int, error) {
	if len(data) < 4+1+2 {
		return nil, 0, errors.New("encrypted data too short")
	}
	h := &Header{}
	copy(h.Magic[:], data[:4])
	if string(h.Magic[:]) != Magic {
		return nil, 0, fmt.Errorf("bad magic: %q", h.Magic[:])
	}
	h.Version = data[4]
	if h.Version != Version {
		return nil, 0, fmt.Errorf("unsupported version: %d", h.Version)
	}
	off := 5
	saltLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if off+saltLen > len(data) {
		return nil, 0, errors.New("truncated salt")
	}
	h.Salt = data[off : off+saltLen]
	off += saltLen
	if off+16 > len(data) {
		return nil, 0, errors.New("truncated header")
	}
	h.ArgonN = readUint32(data[off:])
	h.ArgonR = readUint32(data[off+4:])
	h.ArgonP = readUint32(data[off+8:])
	h.KeyLen = readUint32(data[off+12:])
	off += 16
	if off+4 > len(data) {
		return nil, 0, errors.New("truncated header")
	}
	envLen := int(binary.BigEndian.Uint32(data[off:]))
	off += 4
	if off+envLen > len(data) {
		return nil, 0, errors.New("truncated envelope")
	}
	h.Envelope = data[off : off+envLen]
	off += envLen
	if off+2 > len(data) {
		return nil, 0, errors.New("truncated header")
	}
	nonceLen := int(binary.BigEndian.Uint16(data[off:]))
	off += 2
	if off+nonceLen > len(data) {
		return nil, 0, errors.New("truncated nonce")
	}
	h.Nonce = data[off : off+nonceLen]
	off += nonceLen
	return h, off, nil
}
