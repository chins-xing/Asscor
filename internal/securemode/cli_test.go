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

// fakeAgentCommander records enqueued instructions (AgentCommander contract,
// review I-1 — the kernel CLI dispatches agent mode actions via the
// commander instead of the old placeholder text).
type fakeAgentCommander struct {
	enqueued []fakeCommand
}

type fakeCommand struct {
	hostID string
	action string
	params map[string]string
}

func (f *fakeAgentCommander) EnqueueCommand(hostID, action string, params map[string]string) string {
	f.enqueued = append(f.enqueued, fakeCommand{hostID: hostID, action: action, params: params})
	return "cmd-" + action
}

func newAgentModeCLI(t *testing.T) (*ModeCLI, *fakeAgentCommander) {
	t.Helper()
	c := newTestController(t)
	if err := c.Secrets.Register("fp-a", "host-a", "registered-pw"); err != nil {
		t.Fatal(err)
	}
	commander := &fakeAgentCommander{}
	return &ModeCLI{Ctrl: c, Commander: commander}, commander
}

// TestModeCLIAgentExitEnqueues (review I-1): `mode agent <id> exit` must
// enqueue a real securemode_exit command carrying the registered password.
func TestModeCLIAgentExitEnqueues(t *testing.T) {
	m, commander := newAgentModeCLI(t)
	out, err := m.HandleMode("agent", []string{"host-a", "exit"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "securemode_exit") {
		t.Errorf("output should name the command, got %q", out)
	}
	if len(commander.enqueued) != 1 {
		t.Fatalf("exactly one command must be enqueued, got %d", len(commander.enqueued))
	}
	cmd := commander.enqueued[0]
	if cmd.hostID != "host-a" || cmd.action != "securemode_exit" {
		t.Errorf("enqueued = %+v, want host-a securemode_exit", cmd)
	}
	if cmd.params["password"] != "registered-pw" {
		t.Errorf("exit must carry the registered password, got %v", cmd.params)
	}
}

// TestModeCLIAgentRotateEnqueues: rotate-password enqueues securemode_rotate
// with the registered password.
func TestModeCLIAgentRotateEnqueues(t *testing.T) {
	m, commander := newAgentModeCLI(t)
	out, err := m.HandleMode("agent", []string{"host-a", "rotate-password"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "securemode_rotate") {
		t.Errorf("output should name the command, got %q", out)
	}
	if len(commander.enqueued) != 1 {
		t.Fatalf("exactly one command must be enqueued, got %d", len(commander.enqueued))
	}
	cmd := commander.enqueued[0]
	if cmd.action != "securemode_rotate" || cmd.params["password"] != "registered-pw" {
		t.Errorf("rotate enqueue = %+v, want securemode_rotate with registered-pw", cmd)
	}
}

// TestModeCLIAgentEnterEnqueues: enter enqueues securemode_enter WITHOUT a
// password (the agent self-generates its ephemeral password on entry).
func TestModeCLIAgentEnterEnqueues(t *testing.T) {
	m, commander := newAgentModeCLI(t)
	out, err := m.HandleMode("agent", []string{"host-a", "enter"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "securemode_enter") {
		t.Errorf("output should name the command, got %q", out)
	}
	if len(commander.enqueued) != 1 {
		t.Fatalf("exactly one command must be enqueued, got %d", len(commander.enqueued))
	}
	cmd := commander.enqueued[0]
	if cmd.hostID != "host-a" || cmd.action != "securemode_enter" {
		t.Errorf("enqueued = %+v, want host-a securemode_enter", cmd)
	}
	if len(cmd.params) != 0 {
		t.Errorf("enter must not carry params (agent generates its own password), got %v", cmd.params)
	}
}

// TestModeCLIAgentActionUnregistered: exit/rotate on an agent without a
// registered secret must fail — the kernel has no password to hand the agent.
func TestModeCLIAgentActionUnregistered(t *testing.T) {
	c := newTestController(t) // no registered secret
	m := &ModeCLI{Ctrl: c, Commander: &fakeAgentCommander{}}
	if _, err := m.HandleMode("agent", []string{"ghost", "exit"}, nil); err == nil {
		t.Fatal("exit for an unregistered agent must fail")
	}
}

// TestModeCLIAgentNoCommander: without a wired commander (commander build tag
// off) the CLI must fail loudly instead of printing a fake success.
func TestModeCLIAgentNoCommander(t *testing.T) {
	c := newTestController(t)
	if err := c.Secrets.Register("fp-a", "host-a", "pw"); err != nil {
		t.Fatal(err)
	}
	m := &ModeCLI{Ctrl: c} // Commander nil
	if _, err := m.HandleMode("agent", []string{"host-a", "exit"}, nil); err == nil {
		t.Fatal("agent action without a commander must fail")
	}
}
