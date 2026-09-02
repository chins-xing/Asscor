package securemode

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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

// TestDeriveKeyArgon2idKAT pins deriveKey to Argon2id v1.3 (version 19) KAT
// vectors from two independent sources:
//
// Group "official24" — the Argon2id vectors shipped by
// golang.org/x/crypto/argon2 (argon2_test.go), generated with the reference
// CLI of https://github.com/P-H-C/phc-winner-argon2 (argon2-specs.pdf) and
// matching RFC 9106's test suite. Their tags are 24 bytes and they use no
// secret/associated data, so they are exactly reproducible through the
// public argon2.IDKey entry point with keyLen=24.
//
// Group "ref32" — the same parameter rows re-derived with a second,
// independent Argon2id implementation (Python argon2-cffi, a binding of the
// PHC reference C code), at keyLen=32, plus one row using the production
// default parameters (DefaultKDFParams). This covers the real keyLen=32
// output path.
//
// A keyLen=32 vector is NOT a prefix of a keyLen=24 one for identical
// inputs: Argon2's tag H' is a BLAKE2b hash whose digest length is a
// parameter of the hash itself (RFC 9106 §3.3), so tags of different
// lengths are unrelated byte strings. Hence the two groups above, not a
// truncation check.
//
// The RFC 9106 §5.3 32-byte vector (password 0x01*32, salt 0x02*16,
// secret 0x03*8, AD 0x04*12, t=3, m=32, p=4, tag
// 0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659) uses
// secret/associated-data, which the public argon2.IDKey entry point does
// not accept; that full path is covered inside x/crypto itself
// (testArgon2id). This test guards against a wrong Argon2 variant, wrong
// version, a parameter mix-up in deriveKey/DefaultKDFParams, and keyLen
// plumbing errors.
func TestDeriveKeyArgon2idKAT(t *testing.T) {
	password := []byte("password")
	salt := []byte("somesalt")

	// Group official24: x/crypto published tags are 24 bytes (keyLen=24).
	type kat24 struct {
		name    string
		n, r, p uint32 // time, memory KiB, parallelism
		want    string // official hex tag (24 bytes)
	}
	official24 := []kat24{
		{"t1 m64 p1", 1, 64, 1, "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb"},
		{"t2 m64 p1", 2, 64, 1, "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7"},
		{"t2 m64 p2", 2, 64, 2, "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362"},
		{"t3 m256 p2", 3, 256, 2, "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b"},
		{"t4 m4096 p4", 4, 4096, 4, "145db9733a9f4ee43edf33c509be96b934d505a4efb33c5a"},
		{"t4 m1024 p8", 4, 1024, 8, "8dafa8e004f8ea96bf7c0f93eecf67a6047476143d15577f"},
		{"t2 m64 p3", 2, 64, 3, "4a15b31aec7c2590b87d1f520be7d96f56658172deaa3079"},
		{"t3 m1024 p6", 3, 1024, 6, "1640b932f4b60e272f5d2207b9a9c626ffa1bd88d2349016"},
	}
	for _, tc := range official24 {
		t.Run("official24/"+tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.want)
			if err != nil {
				t.Fatal(err)
			}
			if len(want) != 24 {
				t.Fatalf("test vector must be 24 bytes, got %d", len(want))
			}
			got := deriveKey(string(password), salt, tc.n, tc.r, tc.p, 24)
			if !bytes.Equal(got, want) {
				t.Errorf("deriveKey (keyLen=24) mismatch\n got: %x\nwant: %s", got, tc.want)
			}
		})
	}

	// Group ref32: argon2-cffi (PHC reference C) derivation at keyLen=32.
	type kat32 struct {
		name    string
		n, r, p uint32
		want    string // 32-byte hex tag
	}
	ref32 := []kat32{
		{"t1 m64 p1", 1, 64, 1, "729c7a54441bc13559bdca71348c4e554599e719c08a952601ed5c83618c1bbd"},
		{"t2 m64 p1", 2, 64, 1, "16a1a498734609dd01456da406de9f3d9da93e6c86c300a12fc1465214ce4922"},
		{"t2 m64 p2", 2, 64, 2, "94387415dfb84ed1977465a1e8626073adf42bd4eeae1faa1dd4e23a1ff6859f"},
		{"t3 m256 p2", 3, 256, 2, "a3161de99d0e7c0762364b2c4b3ea2b950005973f8879d54287fd8bd56921f36"},
		{"t4 m4096 p4", 4, 4096, 4, "512e7e273bf5145f226818a6fd13a2786aea42561b82e0da567f5fb5d4f518cd"},
		{"t4 m1024 p8", 4, 1024, 8, "5fd1bd42041aabc63dd26d5173956051f782418f9f9b19f4144f8cb4039e8ae9"},
		{"t2 m64 p3", 2, 64, 3, "04d76823c05ad4b307692c9ab45cd38ca5bcd6bf98ff510b45ff23389ed4577a"},
		{"t3 m1024 p6", 3, 1024, 6, "c7a13a6e36fb8a959edf34c5da1abcbfd143c222a1fe9214cd221d276af0d24a"},
		// production default parameters (DefaultKDFParams: 1, 64*1024, 4, 32)
		{"t1 m65536 p4 (prod default)", 1, 64 * 1024, 4, "716733ba17477e10c0eac8788a61e795df9c5086d785b7de8e295b910fe9fd4a"},
	}
	for _, tc := range ref32 {
		t.Run("ref32/"+tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.want)
			if err != nil {
				t.Fatal(err)
			}
			if len(want) != 32 {
				t.Fatalf("test vector must be 32 bytes, got %d", len(want))
			}
			got := deriveKey(string(password), salt, tc.n, tc.r, tc.p, 32)
			if !bytes.Equal(got, want) {
				t.Errorf("deriveKey (keyLen=32) mismatch\n got: %x\nwant: %s", got, tc.want)
			}
		})
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

// TestDecryptUnifiedErrorMessage (deferred minor #1): wrong password and
// tampered ciphertext must yield the SAME error message so an attacker cannot
// distinguish "wrong password" from "correct password, corrupted data" — a
// password oracle. Format/header errors are unaffected: they never depend on
// the password.
func TestDecryptUnifiedErrorMessage(t *testing.T) {
	enc, err := Encrypt([]byte("data"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	_, errWrong := Decrypt(enc, "wrong-password")
	if errWrong == nil {
		t.Fatal("wrong password must fail")
	}
	tampered := append([]byte(nil), enc...)
	tampered[len(tampered)-1] ^= 0xFF
	_, errTampered := Decrypt(tampered, "pw")
	if errTampered == nil {
		t.Fatal("tampered ciphertext must fail")
	}
	if errWrong.Error() != errTampered.Error() {
		t.Errorf("messages must not differentiate wrong password vs corrupted data:\nwrong-password: %v\ntampered:      %v", errWrong, errTampered)
	}
	if !strings.Contains(errWrong.Error(), "wrong password or corrupted data") {
		t.Errorf("unified message should be generic, got: %v", errWrong)
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

// headerLayout walks a freshly produced .enc buffer (mirroring parseHeader's
// field order) and returns the KDF block offset, the nonceLen field offset,
// and the end offsets of the salt/envelope/nonce regions.
func headerLayout(enc []byte) (kdfOff, nonceLenOff, saltEnd, envEnd, nonceEnd int) {
	off := 4 + 1
	saltEnd = off + 2 + int(binary.BigEndian.Uint16(enc[off:]))
	kdfOff = saltEnd
	off = saltEnd + 16
	envEnd = off + 4 + int(binary.BigEndian.Uint32(enc[off:]))
	off = envEnd
	nonceLenOff = off
	nonceEnd = off + 2 + int(binary.BigEndian.Uint16(enc[off:]))
	return
}

func TestDecryptBadNonceLen(t *testing.T) {
	enc, err := Encrypt([]byte("data"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	_, nonceLenOff, _, _, _ := headerLayout(enc)
	binary.BigEndian.PutUint16(enc[nonceLenOff:], 4) // 4 != GCM nonce size (12)
	if _, err := Decrypt(enc, "pw"); err == nil {
		t.Fatal("nonce length != 12 must be rejected, not panic")
	}
}

func TestDecryptBadKDFParams(t *testing.T) {
	enc, err := Encrypt([]byte("data"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	kdfOff, _, _, _, _ := headerLayout(enc)
	cases := []struct {
		name string
		mut  func(buf []byte)
	}{
		{"argonP=256 (uint8 narrowing to 0)", func(b []byte) {
			serializeUint32(b[kdfOff+8:], 256)
		}},
		{"keyLen=33 (invalid AES key size)", func(b []byte) {
			serializeUint32(b[kdfOff+12:], 33)
		}},
		{"argonN=2 (non-default)", func(b []byte) {
			serializeUint32(b[kdfOff:], 2)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := append([]byte(nil), enc...)
			tc.mut(buf)
			if _, err := Decrypt(buf, "pw"); err == nil {
				t.Fatal("non-default KDF parameters must be rejected, not panic")
			}
		})
	}
}

func TestDecryptTruncatedSections(t *testing.T) {
	enc, err := Encrypt([]byte("data"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	_, _, saltEnd, envEnd, nonceEnd := headerLayout(enc)
	cases := []struct {
		name string
		cut  int
	}{
		{"salt truncated", saltEnd - 2},
		{"envelope truncated", envEnd - 3},
		{"nonce truncated", nonceEnd - 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decrypt(enc[:tc.cut], "pw"); err == nil {
				t.Fatal("truncated sections must be rejected")
			}
		})
	}
}

func TestEncryptNonceFreshness(t *testing.T) {
	plain := []byte("same plaintext and password")
	a, err := Encrypt(plain, "pw")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(plain, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("same plaintext+password must produce different ciphertexts (fresh salt/nonce)")
	}
}
