package securemode

import (
	"bytes"
	"strings"
	"testing"
)

func TestDeriveKeyDeterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")
	a := deriveKey("secret", salt, 1, 64*1024, 4, 32)
	b := deriveKey("secret", salt, 1, 64*1024, 4, 32)
	if !bytes.Equal(a, b) {
		t.Error("same inputs must produce same key")
	}
	if len(a) != 32 {
		t.Errorf("key len = %d, want 32", len(a))
	}
}

func TestDeriveKeySaltSensitive(t *testing.T) {
	a := deriveKey("secret", []byte("salt-one-16bytes"), 1, 64*1024, 4, 32)
	b := deriveKey("secret", []byte("salt-two-16bytes"), 1, 64*1024, 4, 32)
	if bytes.Equal(a, b) {
		t.Error("different salts must produce different keys")
	}
}

func TestDeriveKeyPasswordSensitive(t *testing.T) {
	salt := []byte("0123456789abcdef")
	a := deriveKey("secret", salt, 1, 64*1024, 4, 32)
	b := deriveKey("wrong", salt, 1, 64*1024, 4, 32)
	if bytes.Equal(a, b) {
		t.Error("different passwords must produce different keys")
	}
}

func TestDefaultKDFParams(t *testing.T) {
	n, r, p, kl := DefaultKDFParams()
	if n != 1 || r != 64*1024 || p != 4 || kl != 32 {
		t.Errorf("params = (%d,%d,%d,%d), want (1,65536,4,32)", n, r, p, kl)
	}
}

func TestRandomBytes(t *testing.T) {
	a, err := randomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := randomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 || bytes.Equal(a, b) {
		t.Error("randomBytes must return distinct 32-byte values")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plain := []byte("[weights]\nattack_surface = 35\n")
	enc, err := Encrypt(plain, "correct-password")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(enc, plain) {
		t.Error("ciphertext must not contain plaintext")
	}
	dec, err := Decrypt(enc, "correct-password")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(dec, plain) {
		t.Errorf("round trip mismatch: got %q", dec)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	enc, err := Encrypt([]byte("data"), "right")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(enc, "wrong"); err == nil {
		t.Fatal("wrong password must fail decryption")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	enc, err := Encrypt([]byte("data"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	enc[len(enc)-1] ^= 0xFF // flip last byte of GCM tag region
	if _, err := Decrypt(enc, "pw"); err == nil {
		t.Fatal("tampered ciphertext must fail GCM authentication")
	}
}

func TestDecryptBadMagic(t *testing.T) {
	enc, err := Encrypt([]byte("data"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	enc[0] = 'X'
	if _, err := Decrypt(enc, "pw"); err == nil {
		t.Fatal("bad magic must be rejected")
	} else if !strings.Contains(err.Error(), "magic") {
		t.Errorf("error should mention magic, got: %v", err)
	}
}

func TestEncryptLargeContent(t *testing.T) {
	// 1MB plaintext exercises streaming-safe allocation path.
	plain := bytes.Repeat([]byte("a"), 1<<20)
	enc, err := Encrypt(plain, "pw")
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decrypt(enc, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, plain) {
		t.Error("large round trip mismatch")
	}
}

func TestSerializeReadUint32(t *testing.T) {
	var buf [4]byte
	serializeUint32(buf[:], 0xDEADBEEF)
	if got := readUint32(buf[:]); got != 0xDEADBEEF {
		t.Errorf("round trip = %#x, want 0xDEADBEEF", got)
	}
	// byte order must be big-endian so the .enc format is stable.
	if buf[0] != 0xDE || buf[3] != 0xEF {
		t.Errorf("unexpected byte order: % x", buf[:])
	}
}

func TestMarshalParseHeaderRoundTrip(t *testing.T) {
	h := &Header{
		Salt:     []byte("0123456789abcdef"),
		ArgonN:   1,
		ArgonR:   64 * 1024,
		ArgonP:   4,
		KeyLen:   32,
		Envelope: bytes.Repeat([]byte{0xAB}, 44), // DEK(32) + GCM tag(12)
		Nonce:    []byte("nonce-12-bytes!"),      // GCM nonce, 16 bytes
	}
	copy(h.Magic[:], Magic)
	h.Version = Version

	b, err := marshalHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	got, off, err := parseHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	if off != len(b) {
		t.Errorf("offset = %d, want %d (consumed whole buffer)", off, len(b))
	}
	if string(got.Magic[:]) != Magic || got.Version != Version {
		t.Error("magic/version mismatch after parse")
	}
	if !bytes.Equal(got.Salt, h.Salt) || got.ArgonN != h.ArgonN || got.ArgonR != h.ArgonR ||
		got.ArgonP != h.ArgonP || got.KeyLen != h.KeyLen {
		t.Error("KDF fields mismatch after parse")
	}
	if !bytes.Equal(got.Envelope, h.Envelope) || !bytes.Equal(got.Nonce, h.Nonce) {
		t.Error("envelope/nonce mismatch after parse")
	}
}
