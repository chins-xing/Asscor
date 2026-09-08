package securemode

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAgentSecretFlow verifies the agent-side bootstrap: self-generated
// password, encrypt, and registry registration (mock fingerprint).
func TestAgentSecretFlow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.ini")
	content := "[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[agent]\nheartbeat_sec = 30\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &Vault{DataDir: dir, ConfigPath: path, BootstrapHeader: "[bootstrap]"}

	// Agent generates its own ephemeral password (never persisted).
	pw, err := randomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	agentPW := hex.EncodeToString(pw)

	if err := v.EncryptFile(agentPW); err != nil {
		t.Fatal(err)
	}
	if !v.State().hasEnc || v.State().hasPlain {
		t.Fatalf("after agent encrypt: state = %+v", v.State())
	}

	// Report to kernel: fingerprint-keyed registry.
	reg := NewSecretRegistry()
	if err := reg.Register("cert-fp-001", "host-1", agentPW); err != nil {
		t.Fatal(err)
	}
	if s, ok := reg.Lookup("cert-fp-001"); !ok || s.Password != agentPW {
		t.Fatalf("registry lookup = %+v ok=%v", s, ok)
	}

	// Agent restart: decrypt with kernel-issued password.
	plain, err := v.LoadCiphertext(agentPW)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain, "heartbeat_sec") {
		t.Errorf("decrypted config missing protected section: %q", plain)
	}
}

// TestAgentSecretFlowRestartUnlock simulates the run-mode restart path (spec
// §8.2 / Ruling 2): the plaintext agent.ini is gone, only the .enc remains;
// the kernel issues the registered password and the agent decrypts and reloads
// the protected configuration.
func TestAgentSecretFlowRestartUnlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.ini")
	content := "[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[agent]\nheartbeat_sec = 30\nuser_check.mysql.id = CU-MYSQL-001\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &Vault{DataDir: dir, ConfigPath: path, BootstrapHeader: "[bootstrap]"}

	// Previous run: self-generated password, encrypted, reported to kernel.
	prevPW := "previous-ephemeral-password"
	if err := v.EncryptFile(prevPW); err != nil {
		t.Fatal(err)
	}
	reg := NewSecretRegistry()
	if err := reg.Register("cert-fp-001", "host-1", prevPW); err != nil {
		t.Fatal(err)
	}

	// Restart: no plaintext, only .enc (state locked). Connectivity
	// essentials are still recoverable from the .enc bootstrap section.
	st := v.State()
	if st.hasPlain || !st.hasEnc {
		t.Fatalf("restart state = %+v, want enc-only", st)
	}
	boot, err := v.ReadBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(boot, "kernel_addr") {
		t.Errorf("bootstrap must stay readable without the password, got %q", boot)
	}

	// Kernel issues the registered password; agent decrypts the protected
	// section and re-derives its config (Ruling 2: heartbeats must carry the
	// correct configuration after unlock).
	issued, ok := reg.Lookup("cert-fp-001")
	if !ok {
		t.Fatal("kernel must have the agent's registered password")
	}
	plain, err := v.LoadCiphertext(issued.Password)
	if err != nil {
		t.Fatalf("restart unlock with kernel-issued password failed: %v", err)
	}
	if !strings.Contains(plain, "heartbeat_sec") || !strings.Contains(plain, "user_check.mysql.id") {
		t.Errorf("decrypted config missing protected sections: %q", plain)
	}
}

// TestAgentSecretFlowRotate verifies the kernel-issued rotate instruction:
// the .enc is re-encrypted with a fresh self-generated password while the old
// password still decrypts the original content (rotate never loses data).
func TestAgentSecretFlowRotate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.ini")
	content := "[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[agent]\nheartbeat_sec = 30\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &Vault{DataDir: dir, ConfigPath: path, BootstrapHeader: "[bootstrap]"}

	oldPW := "old-ephemeral-password"
	if err := v.EncryptFile(oldPW); err != nil {
		t.Fatal(err)
	}
	newPW := "new-ephemeral-password"
	if err := v.RotatePassword(oldPW, newPW); err != nil {
		t.Fatal(err)
	}
	// Old password no longer works; new password decrypts the same content.
	if _, err := v.LoadCiphertext(oldPW); err == nil {
		t.Error("old password must fail after rotation")
	}
	plain, err := v.LoadCiphertext(newPW)
	if err != nil {
		t.Fatalf("new password must decrypt after rotation: %v", err)
	}
	if !strings.Contains(plain, "heartbeat_sec") {
		t.Errorf("rotated config lost protected section: %q", plain)
	}
	// No plaintext may appear on disk during rotation.
	if st := v.State(); st.hasPlain || !st.hasEnc {
		t.Errorf("rotate state = %+v, want enc-only", st)
	}
}

// TestNewEphemeralPassword verifies the exported ephemeral-password generator:
// hex-encoded, 64 chars (32 random bytes), and unique per call.
func TestNewEphemeralPassword(t *testing.T) {
	p1, err := NewEphemeralPassword()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := NewEphemeralPassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(p1) != 64 {
		t.Errorf("ephemeral password length = %d, want 64", len(p1))
	}
	if p1 == p2 {
		t.Error("two generated passwords must differ")
	}
	if _, err := hex.DecodeString(p1); err != nil {
		t.Errorf("ephemeral password is not hex: %v", err)
	}
}
