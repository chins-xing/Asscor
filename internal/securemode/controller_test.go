package securemode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asscor/asscor/internal/config"
)

// parseConfigForTest is the I-1 kernel feed path: the run-mode guard content
// (decrypted .enc) is re-parsed with config.Parse and pushed into the kernel
// runtime (SetConfigObj + assessor.ReloadConfig). The controller-level tests
// verify the guard content is ALWAYS parseable so the kernel wiring stays a
// thin glue layer.
func parseConfigForTest(plain string) (*config.Config, error) {
	return config.Parse(plain)
}

func newTestController(t *testing.T) *Controller {
	t.Helper()
	dir := t.TempDir()
	v := &Vault{
		DataDir:         dir,
		ConfigPath:      filepath.Join(dir, "config.ini"),
		BootstrapHeader: "[bootstrap]",
	}
	os.WriteFile(v.ConfigPath, []byte("[bootstrap]\naddr = x\n\n[weights]\na = 1\n"), 0o600)
	return NewController(dir, []*Vault{v})
}

func TestControllerEnterExitRun(t *testing.T) {
	c := newTestController(t)
	if c.Mode != ModeDefault {
		t.Fatalf("initial mode = %q, want default", c.Mode)
	}
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeRun {
		t.Errorf("mode = %q after enter, want run", c.Mode)
	}
	if c.Guard == nil || !c.Guard.IntegrityOK() {
		t.Error("guard must be initialized after enter")
	}
	if err := c.ExitRun("pw"); err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeDefault {
		t.Errorf("mode = %q after exit, want default", c.Mode)
	}
	// plaintext must be restored
	if _, err := os.Stat(c.Vaults[0].ConfigPath); err != nil {
		t.Error("plaintext config must be restored after exit")
	}
}

func TestControllerExitRunWrongPassword(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("right"); err != nil {
		t.Fatal(err)
	}
	if err := c.ExitRun("wrong"); err == nil {
		t.Fatal("exit with wrong password must fail")
	}
	if c.Mode != ModeRun {
		t.Errorf("mode must stay run after failed exit, got %q", c.Mode)
	}
}

func TestControllerStartupMarkerRunNeedsUnlock(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	// Simulate restart: fresh controller over same dir.
	c2 := NewController(c.DataDir, c.Vaults)
	if err := c2.Startup(); err != nil {
		t.Fatalf("Startup (run marker) should succeed but require unlock, got %v", err)
	}
	if c2.Mode != ModeRun {
		t.Errorf("restarted mode = %q, want run", c2.Mode)
	}
	if c2.Guard != nil {
		t.Error("guard must not be populated before unlock")
	}
	if err := c2.Unlock("pw"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if c2.Guard == nil || !c2.Guard.IntegrityOK() {
		t.Error("guard must be populated after unlock")
	}
}

func TestControllerStartupCorruptMarkerFailClosed(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	p := MarkerPath(c.DataDir)
	data, _ := os.ReadFile(p)
	data[0] = 'Z'
	os.WriteFile(p, data, 0o600)

	c2 := NewController(c.DataDir, c.Vaults)
	err := c2.Startup()
	if err == nil {
		t.Fatal("corrupt marker must fail closed on startup")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("error = %v, want corrupt mention", err)
	}
}

func TestControllerStartupResidue(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	// Re-create plaintext alongside .enc -> crash residue.
	os.WriteFile(c.Vaults[0].ConfigPath, []byte("stale"), 0o600)
	c2 := NewController(c.DataDir, c.Vaults)
	err := c2.Startup()
	if err == nil {
		t.Fatal("residue must surface an error on startup")
	}
	if !strings.Contains(err.Error(), "residue") && !strings.Contains(err.Error(), "both") {
		t.Errorf("error = %v, want residue mention", err)
	}
}

func TestControllerSetPassword(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("old"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetPassword("old", "new"); err != nil {
		t.Fatal(err)
	}
	// Old password must no longer decrypt; new one must.
	if err := c.ExitRun("old"); err == nil {
		t.Fatal("old password must fail after rotate")
	}
	if err := c.ExitRun("new"); err != nil {
		t.Fatalf("new password must work after rotate: %v", err)
	}
}

func TestControllerSetPasswordWrongOld(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetPassword("wrong", "new"); err == nil {
		t.Fatal("wrong old password must fail rotation")
	}
}

// TestControllerSetPasswordRollback: a re-encryption failure mid-loop (after
// some vaults were already switched to the new password) must roll back every
// vault to the old password — never leave a mix where part of the vaults are
// encrypted under the new password while the verifier is gone/stale.
func TestControllerSetPasswordRollback(t *testing.T) {
	dir := t.TempDir()
	configA := filepath.Join(dir, "config-a.ini")
	configB := filepath.Join(dir, "config-b.ini")
	vaults := []*Vault{
		{DataDir: dir, ConfigPath: configA, BootstrapHeader: "[bootstrap]"},
		{DataDir: dir, ConfigPath: configB, BootstrapHeader: "[bootstrap]"},
	}
	for _, p := range []string{configA, configB} {
		os.WriteFile(p, []byte("[bootstrap]\naddr = x\n\n[weights]\na = 1\n"), 0o600)
	}
	c := NewController(dir, vaults)
	if err := c.EnterRun("old"); err != nil {
		t.Fatal(err)
	}
	// Block vault B's re-encryption: a directory at its .enc.tmp path makes
	// the atomic write fail AFTER vault A was already re-encrypted.
	os.MkdirAll(configB+".enc.tmp", 0o700)
	if err := c.SetPassword("old", "new"); err == nil {
		t.Fatal("SetPassword must fail when re-encryption fails mid-loop")
	}
	// Rollback must have restored old-password encryption on every vault.
	if _, err := c.Vaults[0].LoadCiphertext("old"); err != nil {
		t.Errorf("vault A must still decrypt with old password after rollback: %v", err)
	}
	if _, err := c.Vaults[1].LoadCiphertext("old"); err != nil {
		t.Errorf("vault B must still decrypt with old password after rollback: %v", err)
	}
	// Old password must work for a full exit; new must not (verifier rolled back).
	if err := c.ExitRun("new"); err == nil {
		t.Error("exit with new password must fail after rollback")
	}
	if err := c.ExitRun("old"); err != nil {
		t.Errorf("exit with old password must work after rollback: %v", err)
	}
}

// TestControllerSetPasswordVerifierFailure: if writing the NEW verifier fails,
// no vault may have been touched — the old password keeps working.
func TestControllerSetPasswordVerifierFailure(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("old"); err != nil {
		t.Fatal(err)
	}
	// A directory at the verifier's tmp path makes Password.Set fail before
	// any vault is re-encrypted.
	os.MkdirAll(PasswordVerifierPath(c.DataDir)+".tmp", 0o700)
	if err := c.SetPassword("old", "new"); err == nil {
		t.Fatal("SetPassword must fail when writing the new verifier fails")
	}
	if _, err := c.Vaults[0].LoadCiphertext("old"); err != nil {
		t.Errorf("vault must still decrypt with old password: %v", err)
	}
	if err := c.ExitRun("old"); err != nil {
		t.Errorf("old password must still exit run mode: %v", err)
	}
}

// TestControllerStartupInterruptedEnterRun: EnterRun crashes between its
// stages leave half-states (enc-only vaults with a mismatched marker/verifier)
// that Startup must fail closed on instead of silently starting in default
// mode and orphaning the encrypted config.
func TestControllerStartupInterruptedEnterRun(t *testing.T) {
	t.Run("default marker enc-only with verifier", func(t *testing.T) {
		c := newTestController(t)
		if err := c.EnterRun("pw"); err != nil {
			t.Fatal(err)
		}
		// Simulate the crash window between Password.Set and WriteMarker(run):
		// marker back to default, vault stays enc-only, verifier stays present.
		if err := WriteMarker(MarkerPath(c.DataDir), ModeDefault); err != nil {
			t.Fatal(err)
		}
		c2 := NewController(c.DataDir, c.Vaults)
		err := c2.Startup()
		if err == nil {
			t.Fatal("default marker + enc-only vault + verifier must fail closed on startup")
		}
		if !strings.Contains(err.Error(), "verifier") {
			t.Errorf("error = %v, want verifier mention", err)
		}
	})
	t.Run("run marker enc-only without verifier", func(t *testing.T) {
		c := newTestController(t)
		if err := c.EnterRun("pw"); err != nil {
			t.Fatal(err)
		}
		// Simulate the crash window before Password.Set: marker=run, vault
		// enc-only, verifier never written.
		if err := os.Remove(PasswordVerifierPath(c.DataDir)); err != nil {
			t.Fatal(err)
		}
		c2 := NewController(c.DataDir, c.Vaults)
		err := c2.Startup()
		if err == nil {
			t.Fatal("run marker + enc-only vault without verifier must fail closed on startup")
		}
		if !strings.Contains(err.Error(), "verifier") {
			t.Errorf("error = %v, want verifier mention", err)
		}
	})
	t.Run("default marker enc-only without verifier", func(t *testing.T) {
		c := newTestController(t)
		if err := c.EnterRun("pw"); err != nil {
			t.Fatal(err)
		}
		// Simulate the crash window between EncryptFile (plaintext deleted) and
		// Password.Set (verifier written): marker back to default, vault
		// enc-only, verifier never written (M1 — review: this combination is
		// the same interrupted-EnterRun half-state as the other two and must
		// fail closed, not silently start in default mode).
		if err := os.Remove(PasswordVerifierPath(c.DataDir)); err != nil {
			t.Fatal(err)
		}
		if err := WriteMarker(MarkerPath(c.DataDir), ModeDefault); err != nil {
			t.Fatal(err)
		}
		c2 := NewController(c.DataDir, c.Vaults)
		err := c2.Startup()
		if err == nil {
			t.Fatal("default marker + enc-only vault without verifier must fail closed on startup")
		}
		if !strings.Contains(err.Error(), "verifier") {
			t.Errorf("error = %v, want verifier mention", err)
		}
	})
}

// TestControllerUnlockGuardContentParsesAsConfig (I-1): after a run-mode
// restart + unlock, the guard content — the decrypted .enc — must parse with
// config.Parse so the kernel wiring can feed it back into the kernel runtime
// (SetConfigObj + assessor.ReloadConfig, mirroring the agent-side
// reloadProtectedConfig). A kernel restart in run mode currently starts on
// config.Default(); unlock is what restores the real protected config.
func TestControllerUnlockGuardContentParsesAsConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.ini")
	content := "[bootstrap]\nlisten = :50051\n\n[acceptability]\nthreshold = 70\n\n[integrity]\nanti_debug = true\n\n[topology]\nexclude_cidrs = 10.0.0.0/8,172.16.0.0/12\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewController(dir, []*Vault{{DataDir: dir, ConfigPath: configPath, BootstrapHeader: "[bootstrap]"}})
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	c2 := NewController(c.DataDir, c.Vaults)
	if err := c2.Startup(); err != nil {
		t.Fatal(err)
	}
	if c2.Guard != nil {
		t.Fatal("guard must be nil before unlock (kernel runs on defaults)")
	}
	if err := c2.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	if c2.Guard == nil {
		t.Fatal("guard must be populated after unlock")
	}
	cfg, err := config.Parse(string(c2.Guard.Snapshot()))
	if err != nil {
		t.Fatalf("guard content must parse as a kernel config: %v", err)
	}
	// The protected settings (threshold, integrity keys, topology exclusions)
	// are exactly what was lost on a run-mode restart — they must round-trip
	// after unlock. (Weights are renormalized by config.Parse, so they are not
	// asserted here.)
	if cfg.Threshold != 70 {
		t.Errorf("parsed threshold = %v, want 70 (protected content lost?)", cfg.Threshold)
	}
	if cfg.AdapterConfig["integrity.anti_debug"] != "true" {
		t.Errorf("parsed integrity.anti_debug = %q, want true", cfg.AdapterConfig["integrity.anti_debug"])
	}
	if len(cfg.TopologyExcludeCIDRs) != 2 || cfg.TopologyExcludeCIDRs[0] != "10.0.0.0/8" {
		t.Errorf("parsed exclude_cidrs = %v, want [10.0.0.0/8 172.16.0.0/12]", cfg.TopologyExcludeCIDRs)
	}
	// Integrity baseline must hold on the guard (hardening, spec §7).
	if !c2.Guard.IntegrityOK() {
		t.Error("guard integrity check must pass right after unlock")
	}
}

// TestControllerEmptyVaults: EnterRun/Unlock must fail cleanly (no panic) when
// no vault is configured — a controller constructed with an empty vault list
// (e.g. a mis-wired kernel) must not index Vaults[0].
func TestControllerEmptyVaults(t *testing.T) {
	dir := t.TempDir()
	c := NewController(dir, nil) // no vaults

	if err := c.EnterRun("pw"); err == nil {
		t.Error("EnterRun with no vaults must fail")
	}
	if err := c.Unlock("pw"); err == nil {
		t.Error("Unlock with no vaults must fail")
	}
	if c.Mode != ModeDefault {
		t.Errorf("mode after failed EnterRun = %q, want default", c.Mode)
	}
	if c.Guard != nil {
		t.Error("guard must remain nil with no vaults")
	}
}

// TestControllerRefusesSensitiveOpsUnderDebugger (spec §7.3 hardening): mode
// transitions that touch the plaintext/password must be refused while a
// debugger/tracer is attached. The probe is injected so the refusal path is
// exercised without a real tracer.
func TestControllerRefusesSensitiveOpsUnderDebugger(t *testing.T) {
	orig := debuggerDetected
	debuggerDetected = func() bool { return true }
	defer func() { debuggerDetected = orig }()

	c := newTestController(t)
	// default -> run refused under debugger
	if err := c.EnterRun("pw"); err == nil {
		t.Fatal("EnterRun under debugger must be refused")
	} else if !strings.Contains(err.Error(), "debugger/tracer") {
		t.Errorf("refusal message should mention debugger, got: %v", err)
	}
	if c.Mode != ModeDefault {
		t.Error("mode must stay default after refused EnterRun")
	}

	// Get into run mode with the probe off, then each sensitive op refused.
	debuggerDetected = func() bool { return false }
	if err := c.EnterRun("pw"); err != nil {
		t.Fatalf("EnterRun (no debugger) failed: %v", err)
	}
	debuggerDetected = func() bool { return true }
	if err := c.ExitRun("pw"); err == nil {
		t.Fatal("ExitRun under debugger must be refused")
	}
	if err := c.Unlock("pw"); err == nil {
		t.Fatal("Unlock under debugger must be refused")
	}
	if err := c.SetPassword("pw", "newpw"); err == nil {
		t.Fatal("SetPassword under debugger must be refused")
	}
	if c.Mode != ModeRun {
		t.Error("mode must stay run after refused ops")
	}
	// The guard must still be intact (refusals happen before any mutation).
	if !c.Guard.IntegrityOK() {
		t.Error("guard integrity must hold after refused ops")
	}
}

// TestControllerGuardReleasedOnExit: leaving run mode must release the guard's
// backing allocation (mmap on Linux) so repeated enter/exit cycles do not leak
// mappings; the guard pointer is nil after exit and a fresh guard is created on
// re-entry.
func TestControllerGuardReleasedOnExit(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	if c.Guard == nil {
		t.Fatal("guard must exist in run mode")
	}
	// Hold a reference to the pre-exit guard; after ExitRun it must be released
	// (data nil) and the controller's pointer cleared.
	old := c.Guard
	if err := c.ExitRun("pw"); err != nil {
		t.Fatal(err)
	}
	if c.Guard != nil {
		t.Error("controller must drop the guard on exit")
	}
	if old.data != nil {
		t.Error("guard backing must be released (data nil) after exit")
	}
	// Re-enter creates a fresh guard that is usable.
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	if c.Guard == nil || !c.Guard.IntegrityOK() {
		t.Error("re-entered guard must be usable")
	}
}
