package securemode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	content := "[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[weights]\nattack_surface = 35\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Vault{DataDir: dir, ConfigPath: path, BootstrapHeader: "[bootstrap]"}
}

func TestVaultEncryptFileAtomic(t *testing.T) {
	v := newTestVault(t)
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	if !v.State().hasEnc {
		t.Error(".enc should exist after encrypt")
	}
	if v.State().hasPlain {
		t.Error("plaintext must be removed after successful encrypt")
	}
	// .enc.tmp must not linger.
	if _, err := os.Stat(v.encPath() + ".tmp"); !os.IsNotExist(err) {
		t.Errorf(".enc.tmp should be cleaned up, stat err=%v", err)
	}
}

func TestVaultRoundTrip(t *testing.T) {
	v := newTestVault(t)
	orig, _ := os.ReadFile(v.ConfigPath)
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	if err := v.DecryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(v.ConfigPath)
	if string(got) != string(orig) {
		t.Errorf("round trip mismatch:\ngot  %q\nwant %q", got, orig)
	}
	if v.State().hasEnc {
		t.Error(".enc should be removed after decrypt")
	}
}

func TestVaultBootstrapStaysPlaintext(t *testing.T) {
	v := newTestVault(t)
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	enc, _ := os.ReadFile(v.encPath())
	s := string(enc)
	if !strings.Contains(s, "kernel_addr = 127.0.0.1:50051") {
		t.Error("bootstrap section must remain readable plaintext in .enc")
	}
	dec, err := v.LoadCiphertext("pw")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dec, "attack_surface = 35") {
		t.Error("protected section must decrypt back")
	}
	if !strings.Contains(dec, "kernel_addr") {
		t.Error("bootstrap must be present in decrypted view too")
	}
}

func TestVaultEncryptWrongPasswordVerify(t *testing.T) {
	v := newTestVault(t)
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	// Decrypt with wrong password must fail and leave files untouched.
	if err := v.DecryptFile("wrong"); err == nil {
		t.Fatal("wrong password decrypt must fail")
	}
	if !v.State().hasEnc || v.State().hasPlain {
		t.Error("failed decrypt must not modify file state")
	}
}

func TestVaultRecoveryStateDetection(t *testing.T) {
	v := newTestVault(t)
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	// Simulate crash residue: re-create plaintext alongside .enc.
	os.WriteFile(v.ConfigPath, []byte("stale plaintext"), 0o600)
	st := v.State()
	if !st.hasPlain || !st.hasEnc {
		t.Errorf("crash residue should show both files, got %+v", st)
	}
}

// TestVaultBootstrapSymmetry verifies that splitBootstrap/reassemble are
// inverse operations and that encrypt+load reproduces the original bytes —
// i.e. splitBootstrap (plaintext side) and decryptPayload (payload side) split
// at exactly the same point.
func TestVaultBootstrapSymmetry(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"standard", "[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[weights]\nattack_surface = 35\n"},
		{"multi-line bootstrap", "[bootstrap]\naddr = a\ncert = /etc/x.pem\n\n[weights]\nw = 1\n"},
		{"no trailing newline", "[bootstrap]\naddr = a\n\n[weights]\nw = 1"},
		{"bootstrap only ends with blank line", "[bootstrap]\naddr = a\n\n"},
		{"section before header", "[pre]\nk = v\n\n[bootstrap]\naddr = a\n\n[weights]\nw = 1\n"},
		{"no header", "[weights]\nattack_surface = 35\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.ini")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			v := &Vault{DataDir: dir, ConfigPath: path, BootstrapHeader: "[bootstrap]"}

			// split -> reassemble must reproduce the original exactly.
			bootstrap, rest, _ := v.splitBootstrap(tc.content)
			if got := v.reassemble(bootstrap, rest); got != tc.content {
				t.Errorf("reassemble(splitBootstrap) mismatch:\ngot  %q\nwant %q", got, tc.content)
			}

			// Full encrypt + decrypt round trip must also reproduce it.
			if err := v.EncryptFile("pw"); err != nil {
				t.Fatalf("EncryptFile: %v", err)
			}
			dec, err := v.LoadCiphertext("pw")
			if err != nil {
				t.Fatalf("LoadCiphertext: %v", err)
			}
			if dec != tc.content {
				t.Errorf("encrypt/load mismatch:\ngot  %q\nwant %q", dec, tc.content)
			}
		})
	}
}

// TestVaultNoBootstrapHeaderRoundTrip covers the pure-encryption layout
// (BootstrapHeader == "" or no header line in the content).
func TestVaultNoBootstrapHeaderRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	content := "[weights]\nattack_surface = 35\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &Vault{DataDir: dir, ConfigPath: path}
	if b, rest, ok := v.splitBootstrap(content); ok || b != "" || rest != content {
		t.Errorf("empty BootstrapHeader must not split, got (b=%q, rest=%q, ok=%v)", b, rest, ok)
	}
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	// No bootstrap header means the whole payload is encrypted: the plaintext
	// must NOT be visible in the .enc.
	enc, _ := os.ReadFile(v.encPath())
	if strings.Contains(string(enc), "attack_surface") {
		t.Error("without bootstrap header nothing may stay plaintext in .enc")
	}
	dec, err := v.LoadCiphertext("pw")
	if err != nil {
		t.Fatal(err)
	}
	if dec != content {
		t.Errorf("round trip mismatch: got %q want %q", dec, content)
	}
}

// TestVaultEncryptNoProtectedSectionFailsSafe: a config whose bootstrap block
// has no blank line afterwards cannot be byte-exactly round-tripped through
// the "[bootstrap][\n\n][encrypted rest]" layout, so EncryptFile must fail
// BEFORE touching the plaintext (fail-safe, no partial state).
func TestVaultEncryptNoProtectedSectionFailsSafe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	content := "[bootstrap]\naddr = a\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &Vault{DataDir: dir, ConfigPath: path, BootstrapHeader: "[bootstrap]"}
	if err := v.EncryptFile("pw"); err == nil {
		t.Fatal("encrypting a bootstrap-only file without a blank line must fail")
	}
	if !v.State().hasPlain || v.State().hasEnc {
		t.Error("failed encrypt must leave plaintext in place and no .enc")
	}
	got, _ := os.ReadFile(v.ConfigPath)
	if string(got) != content {
		t.Errorf("plaintext modified by failed encrypt: %q", got)
	}
}

// TestVaultReadBootstrap verifies the run-mode restart path: connectivity
// essentials stay readable from the .enc payload WITHOUT the password (the
// agent reads them before the kernel issues the registered unlock secret).
func TestVaultReadBootstrap(t *testing.T) {
	v := newTestVault(t)
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	boot, err := v.ReadBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(boot, "[bootstrap]") || !strings.Contains(boot, "kernel_addr = 127.0.0.1:50051") {
		t.Errorf("ReadBootstrap = %q, want readable bootstrap section", boot)
	}
	if strings.Contains(boot, "attack_surface") {
		t.Errorf("ReadBootstrap must not leak the protected section, got %q", boot)
	}
}

// TestVaultReadBootstrapNoHeader: without a configured bootstrap header the
// whole payload is encrypted, so nothing can be read back — a safe empty
// result, never an error.
func TestVaultReadBootstrapNoHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	if err := os.WriteFile(path, []byte("[weights]\na = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &Vault{DataDir: dir, ConfigPath: path} // no BootstrapHeader
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	boot, err := v.ReadBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if boot != "" {
		t.Errorf("ReadBootstrap without header = %q, want empty", boot)
	}
}

// TestVaultRotatePassword: re-encrypt the .enc with a new password, decrypting
// with the old one purely in memory (agent securemode_rotate instruction). The
// old password stops working, the new one round-trips, and no plaintext file
// ever appears on disk.
func TestVaultRotatePassword(t *testing.T) {
	v := newTestVault(t)
	if err := v.EncryptFile("old-pw"); err != nil {
		t.Fatal(err)
	}
	if err := v.RotatePassword("old-pw", "new-pw"); err != nil {
		t.Fatal(err)
	}
	if st := v.State(); st.hasPlain || !st.hasEnc {
		t.Fatalf("after rotate state = %+v, want enc-only", st)
	}
	if _, err := v.LoadCiphertext("old-pw"); err == nil {
		t.Error("old password must not decrypt after rotation")
	}
	plain, err := v.LoadCiphertext("new-pw")
	if err != nil {
		t.Fatalf("new password must decrypt after rotation: %v", err)
	}
	if !strings.Contains(plain, "attack_surface = 35") {
		t.Errorf("rotated config lost protected content: %q", plain)
	}
}

// TestVaultRotatePasswordWrongOld: rotating with a wrong old password must
// fail WITHOUT touching the .enc (the old password keeps working).
func TestVaultRotatePasswordWrongOld(t *testing.T) {
	v := newTestVault(t)
	if err := v.EncryptFile("old-pw"); err != nil {
		t.Fatal(err)
	}
	encBefore, _ := os.ReadFile(v.encPath())
	if err := v.RotatePassword("wrong-pw", "new-pw"); err == nil {
		t.Fatal("rotate with wrong old password must fail")
	}
	encAfter, _ := os.ReadFile(v.encPath())
	if string(encBefore) != string(encAfter) {
		t.Error(".enc must be untouched after failed rotate")
	}
	if _, err := v.LoadCiphertext("old-pw"); err != nil {
		t.Errorf("old password must keep working after failed rotate: %v", err)
	}
}
