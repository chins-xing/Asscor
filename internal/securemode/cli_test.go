package securemode

import (
	"strings"
	"testing"
)

func newModeCLI(t *testing.T) *ModeCLI {
	c := newTestController(t)
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	return &ModeCLI{Ctrl: c}
}

func TestModeCLIStatus(t *testing.T) {
	m := newModeCLI(t)
	out, err := m.HandleMode("status", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "run") {
		t.Errorf("status output should mention run mode, got %q", out)
	}
}

func TestModeCLIExitWrongPassword(t *testing.T) {
	m := newModeCLI(t)
	_, err := m.HandleMode("exit", nil, map[string]string{"password": "wrong"})
	if err == nil {
		t.Fatal("exit with wrong password must fail")
	}
	if m.Ctrl.Mode != ModeRun {
		t.Error("mode must stay run after failed exit")
	}
}

func TestModeCLIExitOK(t *testing.T) {
	m := newModeCLI(t)
	out, err := m.HandleMode("exit", nil, map[string]string{"password": "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "default") {
		t.Errorf("exit output should mention default mode, got %q", out)
	}
}

func TestModeCLISetPassword(t *testing.T) {
	m := newModeCLI(t)
	if _, err := m.HandleMode("set-password", nil, map[string]string{"old": "pw", "new": "newpw"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.HandleMode("exit", nil, map[string]string{"password": "newpw"}); err != nil {
		t.Fatalf("new password should work: %v", err)
	}
}

func TestModeCLIConfigSetTemp(t *testing.T) {
	m := newModeCLI(t)
	out, err := m.HandleConfigSet([]string{"addr", "85"}, map[string]string{"password": "pw", "temp": "true"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "85") {
		t.Errorf("set output should echo value, got %q", out)
	}
}

func TestModeCLIConfigSetWrongPassword(t *testing.T) {
	m := newModeCLI(t)
	if _, err := m.HandleConfigSet([]string{"addr", "85"}, map[string]string{"password": "nope"}); err == nil {
		t.Fatal("config set in run mode without correct password must fail")
	}
}

func TestModeCLIConfigSetPersist(t *testing.T) {
	m := newModeCLI(t)
	out, err := m.HandleConfigSet([]string{"addr", "77"}, map[string]string{"password": "pw", "persist": "true"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "reload") {
		t.Errorf("persist output should mention reload, got %q", out)
	}
}

// TestModeCLIConfigSetPersistDefaultMode: spec §9 — --persist in default mode
// (no guard, no password) rewrites the plaintext config on disk.
func TestModeCLIConfigSetPersistDefaultMode(t *testing.T) {
	c := newTestController(t) // default mode: no guard
	m := &ModeCLI{Ctrl: c}
	out, err := m.HandleConfigSet([]string{"addr", "66"}, map[string]string{"persist": "true"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "plaintext") {
		t.Errorf("persist output should mention plaintext, got %q", out)
	}
	content, err := c.Vaults[0].LoadPlaintext()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "addr = 66") {
		t.Errorf("plaintext config must contain the new value, got %q", content)
	}
}

// TestModeCLIConfigSetUnlockedRunFails: mode=run without a guard (run marker
// present but not yet unlocked) must fail closed before any mutation.
func TestModeCLIConfigSetUnlockedRunFails(t *testing.T) {
	m := newModeCLI(t)
	// Simulate the run-marker-not-yet-unlocked state: mode=run, no guard.
	m.Ctrl.Guard = nil
	_, err := m.HandleConfigSet([]string{"addr", "66"}, map[string]string{"password": "pw"})
	if err == nil {
		t.Fatal("config set with mode=run but no guard must fail (unlock required)")
	}
	if !strings.Contains(err.Error(), "unlock") {
		t.Errorf("error should mention unlock, got %v", err)
	}
	if m.Ctrl.Guard != nil {
		t.Error("guard must stay nil after the failed config set")
	}
	// Nothing may have been written: the .enc still decrypts to the original.
	content, err := m.Ctrl.Vaults[0].LoadCiphertext("pw")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(content, "addr = 66") {
		t.Errorf("config must not have been modified, got %q", content)
	}
}

// TestModeCLIUnlock: after a kernel restart with a run marker, the controller
// is in run mode with no guard (not yet unlocked); `mode unlock --password`
// loads the protected config into memory (Ruling 3).
func TestModeCLIUnlock(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	// Simulate kernel restart: a fresh controller on the same data dir starts
	// in run mode (marker) but without the config in memory.
	c2 := NewController(c.DataDir, c.Vaults)
	if err := c2.Startup(); err != nil {
		t.Fatal(err)
	}
	if c2.Mode != ModeRun {
		t.Fatalf("restart mode = %q, want run", c2.Mode)
	}
	if c2.Guard != nil {
		t.Fatal("restarted controller must not have the config in memory yet")
	}
	m := &ModeCLI{Ctrl: c2}
	out, err := m.HandleMode("unlock", nil, map[string]string{"password": "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(out), "unlock") {
		t.Errorf("unlock output should mention unlock, got %q", out)
	}
	if c2.Guard == nil || !c2.Guard.IntegrityOK() {
		t.Error("unlock must load the protected config into the guard")
	}
}

// TestModeCLIUnlockWrongPassword: a wrong password must fail without loading
// the config (guard stays nil).
func TestModeCLIUnlockWrongPassword(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	c2 := NewController(c.DataDir, c.Vaults)
	if err := c2.Startup(); err != nil {
		t.Fatal(err)
	}
	m := &ModeCLI{Ctrl: c2}
	_, err := m.HandleMode("unlock", nil, map[string]string{"password": "wrong"})
	if err == nil {
		t.Fatal("unlock with wrong password must fail")
	}
	if c2.Guard != nil {
		t.Error("guard must stay nil after a failed unlock")
	}
}

// TestModeCLIUnlockDefaultMode: unlock is only meaningful in run mode.
func TestModeCLIUnlockDefaultMode(t *testing.T) {
	c := newTestController(t) // default mode
	m := &ModeCLI{Ctrl: c}
	if _, err := m.HandleMode("unlock", nil, map[string]string{"password": "pw"}); err == nil {
		t.Fatal("unlock in default mode must be rejected")
	}
}
