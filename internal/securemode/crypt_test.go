package securemode

import (
	"bytes"
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
