package securemode

import (
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
