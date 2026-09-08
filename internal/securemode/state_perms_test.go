//go:build unix

package securemode

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestWriteFile0600IgnoresPermissiveUmask (audit RC-L2): os.WriteFile's mode
// is masked by the process umask, so under umask 0000 a naive 0600 write
// lands as 0666 — world-readable. writeFile0600 must explicitly chmod after
// writing so the verifier/payload never exceeds 0600.
func TestWriteFile0600IgnoresPermissiveUmask(t *testing.T) {
	old := syscall.Umask(0) // permissive: would turn 0600 into 0666
	defer syscall.Umask(old)

	path := filepath.Join(t.TempDir(), "secret.bin")
	if err := writeFile0600(path, []byte("sensitive")); err != nil {
		t.Fatalf("writeFile0600: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %04o, want 0600 under umask 0000 (audit RC-L2)", perm)
	}
}

// TestPasswordVerifierSetIgnoresPermissiveUmask: the verifier path (the
// audit's named location) must also stay 0600 under umask 0000.
func TestPasswordVerifierSetIgnoresPermissiveUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	pv := &PasswordVerifier{File: filepath.Join(t.TempDir(), ".asscor-pw")}
	if err := pv.Set("some-strong-password-123"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	info, err := os.Stat(pv.File)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("verifier mode = %04o, want 0600 under umask 0000 (audit RC-L2)", perm)
	}
}
