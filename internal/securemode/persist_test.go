package securemode

import (
	"os"
	"path/filepath"
	"testing"
)

// newPersistTestController builds a run-mode-capable controller over a single
// kernel config vault in a fresh temp dir.
func newPersistTestController(t *testing.T) *Controller {
	t.Helper()
	dir := t.TempDir()
	v := &Vault{
		DataDir:         dir,
		ConfigPath:      filepath.Join(dir, "config.ini"),
		BootstrapHeader: "[bootstrap]",
	}
	if err := os.WriteFile(v.ConfigPath, []byte("[bootstrap]\naddr = x\n\n[weights]\na = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return NewController(dir, []*Vault{v})
}

// TestPersistSecretsDefaultModeNoop: in default mode there is no run-mode
// registry to persist, so PersistSecrets is a no-op and never writes a file.
func TestPersistSecretsDefaultModeNoop(t *testing.T) {
	c := newPersistTestController(t)
	if err := c.PersistSecrets(); err != nil {
		t.Fatalf("PersistSecrets in default mode must be a no-op, got %v", err)
	}
	if _, err := os.Stat(SecretsFilePath(c.DataDir)); !os.IsNotExist(err) {
		t.Error("no registry file may be written in default mode")
	}
}

// TestPersistSecretsRunModeWithoutRetainedPassword: a run-mode controller with
// no retained password (defensive, unreachable through the normal
// EnterRun/Unlock flow) must fail loudly instead of writing an undecryptable
// file.
func TestPersistSecretsRunModeWithoutRetainedPassword(t *testing.T) {
	dir := t.TempDir()
	c := &Controller{DataDir: dir, Mode: ModeRun, Secrets: NewSecretRegistry()}
	if err := c.PersistSecrets(); err == nil {
		t.Fatal("PersistSecrets without a retained run-mode password must fail")
	}
	if _, err := os.Stat(SecretsFilePath(dir)); !os.IsNotExist(err) {
		t.Error("no registry file may be written without a password")
	}
}

// TestRegistryPersistenceRoundTrip: register -> persist -> kernel restart
// (fresh controller) -> Startup + Unlock must auto-recover the registry
// (spec §10.1 P0-1 recovery flow: unlock then restore the 3-tuples).
func TestRegistryPersistenceRoundTrip(t *testing.T) {
	c := newPersistTestController(t)
	if err := c.EnterRun("kernel-pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.Secrets.Register("fp-a", "host-a", "agent-pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.PersistSecrets(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(SecretsFilePath(c.DataDir)); err != nil {
		t.Fatalf("registry file must exist after persist: %v", err)
	}

	// Restart: fresh controller, Startup sees the run marker, Unlock must
	// restore the registry before serving.
	c2 := NewController(c.DataDir, c.Vaults)
	if err := c2.Startup(); err != nil {
		t.Fatal(err)
	}
	if c2.Mode != ModeRun {
		t.Fatalf("restart mode = %q, want run", c2.Mode)
	}
	if err := c2.Unlock("kernel-pw"); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	s, ok := c2.Secrets.Lookup("fp-a")
	if !ok || s.Password != "agent-pw" || s.AgentID != "host-a" {
		t.Fatalf("registry not recovered after restart: %+v ok=%v", s, ok)
	}
}

// TestLoadSecretsMissingFile: no persisted registry (fresh kernel, no agent
// ever registered) -> unlock succeeds with an empty registry.
func TestLoadSecretsMissingFile(t *testing.T) {
	c := newPersistTestController(t)
	if err := c.EnterRun("kernel-pw"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(SecretsFilePath(c.DataDir)); err != nil {
		t.Fatal(err)
	}
	c2 := NewController(c.DataDir, c.Vaults)
	if err := c2.Startup(); err != nil {
		t.Fatal(err)
	}
	if err := c2.Unlock("kernel-pw"); err != nil {
		t.Fatalf("unlock without a persisted registry must succeed: %v", err)
	}
	if c2.Secrets.Size() != 0 {
		t.Errorf("registry size = %d, want 0 (fresh start)", c2.Secrets.Size())
	}
}

// TestLoadSecretsWrongPasswordFailClosed: a registry file that cannot be
// decrypted (wrong password / tampered ciphertext) must fail closed — the
// file is preserved and the registry is not half-loaded.
func TestLoadSecretsWrongPasswordFailClosed(t *testing.T) {
	c := newPersistTestController(t)
	if err := c.EnterRun("kernel-pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.Secrets.Register("fp-a", "host-a", "agent-pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.PersistSecrets(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(SecretsFilePath(c.DataDir))
	if err != nil {
		t.Fatal(err)
	}

	c2 := NewController(c.DataDir, c.Vaults)
	if err := c2.Startup(); err != nil {
		t.Fatal(err)
	}
	err = c2.Unlock("wrong-pw")
	if err == nil {
		t.Fatal("wrong password must fail unlock (verifier rejects it before the registry is touched)")
	}
	after, err := os.ReadFile(SecretsFilePath(c.DataDir))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("registry file must be preserved byte-for-byte on failed unlock")
	}
	if c2.Guard != nil {
		t.Error("guard must not be populated when unlock fails")
	}
}

// TestLoadSecretsCorruptFileFailClosed: a corrupt (bit-flipped) registry file
// with the CORRECT password must also fail closed — the GCM tag catches the
// tampering, the file is preserved for manual recovery, and the registry stays
// empty.
func TestLoadSecretsCorruptFileFailClosed(t *testing.T) {
	c := newPersistTestController(t)
	if err := c.EnterRun("kernel-pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.Secrets.Register("fp-a", "host-a", "agent-pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.PersistSecrets(); err != nil {
		t.Fatal(err)
	}
	path := SecretsFilePath(c.DataDir)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0xFF // flip a ciphertext bit
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	c2 := NewController(c.DataDir, c.Vaults)
	if err := c2.Startup(); err != nil {
		t.Fatal(err)
	}
	err = c2.Unlock("kernel-pw")
	if err == nil {
		t.Fatal("corrupt registry must fail unlock (fail-closed)")
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Error("corrupt registry file must NOT be deleted (manual recovery path)")
	}
	if c2.Secrets.Size() != 0 {
		t.Errorf("registry must stay empty after failed unlock, got %d entries", c2.Secrets.Size())
	}
	// Direct LoadSecrets must fail the same way.
	if err := c2.LoadSecrets("kernel-pw"); err == nil {
		t.Error("direct LoadSecrets on the corrupt file must fail")
	}
}

// TestSetPasswordReencryptsRegistry: rotating the kernel password must also
// re-encrypt the persisted registry under the new password, otherwise a later
// kernel restart could never recover the registry (unlock would fail closed).
func TestSetPasswordReencryptsRegistry(t *testing.T) {
	c := newPersistTestController(t)
	if err := c.EnterRun("old"); err != nil {
		t.Fatal(err)
	}
	if err := c.Secrets.Register("fp-a", "host-a", "agent-pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.PersistSecrets(); err != nil {
		t.Fatal(err)
	}
	if err := c.SetPassword("old", "new"); err != nil {
		t.Fatal(err)
	}

	c2 := NewController(c.DataDir, c.Vaults)
	if err := c2.Startup(); err != nil {
		t.Fatal(err)
	}
	// Old password is dead (verifier rotated AND registry re-encrypted).
	if err := c2.Unlock("old"); err == nil {
		t.Fatal("old password must not unlock after rotation")
	}
	if err := c2.Unlock("new"); err != nil {
		t.Fatalf("new password must unlock after rotation: %v", err)
	}
	s, ok := c2.Secrets.Lookup("fp-a")
	if !ok || s.Password != "agent-pw" {
		t.Fatalf("registry must survive kernel password rotation: %+v ok=%v", s, ok)
	}
}

// TestExitRunRemovesRegistryFile: leaving run mode removes the persisted
// registry (kernel in default mode => no agents in run mode, spec §10.1), and
// the retained password is dropped.
func TestExitRunRemovesRegistryFile(t *testing.T) {
	c := newPersistTestController(t)
	if err := c.EnterRun("kernel-pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.Secrets.Register("fp-a", "host-a", "agent-pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.PersistSecrets(); err != nil {
		t.Fatal(err)
	}
	if err := c.ExitRun("kernel-pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(SecretsFilePath(c.DataDir)); !os.IsNotExist(err) {
		t.Error("registry file must be removed when the kernel exits run mode")
	}
	if c.runPassword != "" {
		t.Error("retained run-mode password must be dropped on exit")
	}
}

// TestLoadSecretsDirectAPI: the exported LoadSecrets(password) recovery
// primitive restores the registry on a fresh controller and fails closed on a
// wrong password.
func TestLoadSecretsDirectAPI(t *testing.T) {
	c := newPersistTestController(t)
	if err := c.EnterRun("kernel-pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.Secrets.Register("fp-a", "host-a", "agent-pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.PersistSecrets(); err != nil {
		t.Fatal(err)
	}

	c2 := NewController(c.DataDir, c.Vaults)
	if err := c2.LoadSecrets("kernel-pw"); err != nil {
		t.Fatalf("LoadSecrets: %v", err)
	}
	s, ok := c2.Secrets.Lookup("fp-a")
	if !ok || s.Password != "agent-pw" {
		t.Fatalf("LoadSecrets must restore the registry: %+v ok=%v", s, ok)
	}
	// Wrong password must fail closed (no partial state).
	if err := c2.LoadSecrets("wrong"); err == nil {
		t.Error("wrong password must fail LoadSecrets")
	}
	if s, ok := c2.Secrets.Lookup("fp-a"); !ok || s.Password != "agent-pw" {
		t.Error("failed LoadSecrets must not clobber the loaded registry")
	}
}
