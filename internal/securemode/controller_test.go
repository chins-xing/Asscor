package securemode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
