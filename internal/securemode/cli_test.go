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
