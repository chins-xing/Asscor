//go:build commander

package commander

import (
	"testing"
	"time"

	apiv1 "github.com/asscor/asscor/api/v1"
)

func TestCommanderEnqueueDequeue(t *testing.T) {
	m := &Module{
		pendingCmds: make(map[string]map[string]*pendingCommand),
	}

	cmdID := m.enqueueTest("host-01", "restart", nil)
	if cmdID == "" {
		t.Fatal("expected non-empty command ID")
	}

	cmds := m.DequeueCommands("host-01")
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	if cmds[0].CommandId != cmdID {
		t.Errorf("CommandId = %s, want %s", cmds[0].CommandId, cmdID)
	}
	if cmds[0].Command != "restart" {
		t.Errorf("Command = %s, want restart", cmds[0].Command)
	}
}

func TestCommanderDequeueEmpty(t *testing.T) {
	m := &Module{
		pendingCmds: make(map[string]map[string]*pendingCommand),
	}

	cmds := m.DequeueCommands("nonexistent")
	if cmds != nil {
		t.Fatalf("expected nil, got %d commands", len(cmds))
	}
}

func TestCommanderEnqueueMultipleHosts(t *testing.T) {
	m := &Module{
		pendingCmds: make(map[string]map[string]*pendingCommand),
	}

	m.enqueueTest("h1", "cmd1", nil)
	m.enqueueTest("h2", "cmd2", nil)

	if len(m.pendingCmds) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(m.pendingCmds))
	}

	cmds1 := m.DequeueCommands("h1")
	if len(cmds1) != 1 {
		t.Errorf("expected 1 command for h1, got %d", len(cmds1))
	}

	cmds2 := m.DequeueCommands("h2")
	if len(cmds2) != 1 {
		t.Errorf("expected 1 command for h2, got %d", len(cmds2))
	}
}

func TestCommanderAckCommand(t *testing.T) {
	m := &Module{
		pendingCmds: make(map[string]map[string]*pendingCommand),
	}

	cmdID := m.enqueueTest("host-01", "status", nil)

	m.AckCommand("host-01", cmdID, true, "OK")

	if cmds := m.pendingCmds["host-01"]; len(cmds) > 0 {
		for id := range cmds {
			t.Errorf("expected command %s to be removed after ack", id)
		}
	}
}

func TestCommanderAckNonexistent(t *testing.T) {
	m := &Module{
		pendingCmds: make(map[string]map[string]*pendingCommand),
	}

	m.AckCommand("host-01", "nonexistent", true, "OK")

	if cmds := m.pendingCmds["host-01"]; len(cmds) != 0 {
		t.Error("expected no commands for unknown host")
	}
}

func (m *Module) enqueueTest(hostID, action string, params map[string]string) string {
	id := hostID + "-" + action

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pendingCmds[hostID] == nil {
		m.pendingCmds[hostID] = make(map[string]*pendingCommand)
	}
	m.pendingCmds[hostID][id] = &pendingCommand{
		Cmd:        &apiv1.Command{CommandId: id, Command: action, Params: params},
		EnqueuedAt: time.Now(),
	}
	return id
}

func TestCommander_CommandExpiry(t *testing.T) {
	m := &Module{
		pendingCmds: make(map[string]map[string]*pendingCommand),
		cmdTTL:      30 * time.Minute,
	}

	m.pendingCmds["host-1"] = map[string]*pendingCommand{
		"cmd-fresh":   {Cmd: &apiv1.Command{CommandId: "cmd-fresh"}, EnqueuedAt: time.Now()},
		"cmd-expired": {Cmd: &apiv1.Command{CommandId: "cmd-expired"}, EnqueuedAt: time.Now().Add(-1 * time.Hour)},
	}
	m.pendingCmds["host-2"] = map[string]*pendingCommand{
		"cmd-old": {Cmd: &apiv1.Command{CommandId: "cmd-old"}, EnqueuedAt: time.Now().Add(-2 * time.Hour)},
	}

	m.expireStaleCommands()

	if cmds, ok := m.pendingCmds["host-1"]; !ok {
		t.Error("host-1 should still exist")
	} else if len(cmds) != 1 {
		t.Errorf("host-1 should have 1 command, got %d", len(cmds))
	}
	if _, ok := m.pendingCmds["host-2"]; ok {
		t.Error("host-2 should be removed (all commands expired)")
	}
}

func TestCommander_EnqueueDequeue(t *testing.T) {
	m := &Module{
		pendingCmds: make(map[string]map[string]*pendingCommand),
		cmdTTL:      30 * time.Minute,
	}

	id := m.EnqueueCommand("host-1", "restart", map[string]string{"service": "nginx"})
	if id == "" {
		t.Error("expected non-empty command ID")
	}

	cmds := m.DequeueCommands("host-1")
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	if cmds[0].Command != "restart" {
		t.Errorf("command = %s, want restart", cmds[0].Command)
	}

	cmds2 := m.DequeueCommands("host-1")
	if len(cmds2) != 0 {
		t.Error("second dequeue should return empty")
	}
}
