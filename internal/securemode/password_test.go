package securemode

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestPasswordVerifierSetVerify(t *testing.T) {
	pv := &PasswordVerifier{File: filepath.Join(t.TempDir(), ".asscor-pw")}
	if pv.Exists() {
		t.Error("should not exist before Set")
	}
	if err := pv.Set("secret-pass"); err != nil {
		t.Fatal(err)
	}
	if !pv.Exists() {
		t.Error("should exist after Set")
	}
	if !pv.Verify("secret-pass") {
		t.Error("correct password must verify")
	}
	if pv.Verify("wrong-pass") {
		t.Error("wrong password must not verify")
	}
	if pv.Verify("") {
		t.Error("empty password must not verify")
	}
}

func TestPasswordVerifierReSet(t *testing.T) {
	pv := &PasswordVerifier{File: filepath.Join(t.TempDir(), ".asscor-pw")}
	if err := pv.Set("first"); err != nil {
		t.Fatal(err)
	}
	if err := pv.Set("second"); err != nil {
		t.Fatal(err)
	}
	if !pv.Verify("second") {
		t.Error("new password should verify after re-Set")
	}
	if pv.Verify("first") {
		t.Error("old password should fail after re-Set")
	}
}

func TestPasswordVerifierClear(t *testing.T) {
	pv := &PasswordVerifier{File: filepath.Join(t.TempDir(), ".asscor-pw")}
	if err := pv.Set("pw"); err != nil {
		t.Fatal(err)
	}
	if err := pv.Clear(); err != nil {
		t.Fatal(err)
	}
	if pv.Exists() {
		t.Error("verifier file should be gone after Clear")
	}
	if pv.Verify("pw") {
		t.Error("verify after clear must fail")
	}
}

func TestPasswordVerifierFilePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".asscor-pw")
	if err := (&PasswordVerifier{File: path}).Set("persist-me"); err != nil {
		t.Fatal(err)
	}
	// Fresh verifier over the same file must still verify (salt persisted).
	if !(&PasswordVerifier{File: path}).Verify("persist-me") {
		t.Error("verification must survive process restart via file salt+hash")
	}
	// ensure file is not empty
	st, _ := os.Stat(path)
	if st.Size() == 0 {
		t.Error("verifier file must contain salt+hash")
	}
}

// TestPasswordVerifierRejectsCraftedFile proves Verify refuses attacker-
// controlled KDF parameters / versions in the verifier file (panic/OOM/DoS
// family, same defense as Decrypt's header checks) instead of feeding them
// to argon2.
func TestPasswordVerifierRejectsCraftedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".asscor-pw")
	if err := (&PasswordVerifier{File: path}).Set("pw"); err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) < 1+1+16+16+32 {
		t.Fatalf("unexpected verifier file size: %d", len(base))
	}
	// Layout: version(1) + saltLen(1) + salt(16) + N(4) + r(4) + p(4) + keyLen(4) + hash.
	saltLen := int(base[1])
	nOff := 2 + saltLen
	pOff := nOff + 8
	klOff := pOff + 4
	writeU32 := func(d []byte, off int, v uint32) {
		binary.BigEndian.PutUint32(d[off:off+4], v)
	}

	cases := []struct {
		name string
		mut  func(d []byte) []byte
	}{
		{"keyLen=0", func(d []byte) []byte { writeU32(d, klOff, 0); return d }},
		{"N=0", func(d []byte) []byte { writeU32(d, nOff, 0); return d }},
		{"p=256 (uint8 truncates to 0)", func(d []byte) []byte { writeU32(d, pOff, 256); return d }},
		{"truncated below minimum", func(d []byte) []byte { return d[:10] }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			crafted := tc.mut(append([]byte(nil), base...))
			if err := os.WriteFile(path, crafted, 0o600); err != nil {
				t.Fatal(err)
			}
			if (&PasswordVerifier{File: path}).Verify("pw") {
				t.Error("crafted verifier file must not verify")
			}
		})
	}
	// Control: restore the valid file, must still verify.
	if err := os.WriteFile(path, base, 0o600); err != nil {
		t.Fatal(err)
	}
	if !(&PasswordVerifier{File: path}).Verify("pw") {
		t.Error("valid verifier file must verify")
	}
}
