package kernel

import (
	"context"
	"testing"

	apiv1 "github.com/asscor/asscor/api/v1"
)

// mockCommander implements CommanderInterface for blocker tests.
type mockCommander struct {
	hostID string
	action string
}

func (m *mockCommander) EnqueueCommand(hostID string, action string, params map[string]string) string {
	m.hostID = hostID
	m.action = action
	return "cmd-1"
}
func (m *mockCommander) DequeueCommands(hostID string) []*apiv1.Command { return nil }
func (m *mockCommander) AckCommand(hostID string, cmdID string, success bool, output string) {}

func TestKernelBlockerBlock(t *testing.T) {
	// Nil kernel → no commander → Block returns not-blocked.
	b := NewKernelBlocker(nil)
	res, err := b.Block(context.Background(), &AttackerLocation{FootholdHost: "h"})
	if err != nil {
		t.Fatalf("Block error: %v", err)
	}
	if res.Blocked {
		t.Error("expected not-blocked with nil kernel")
	}
}

func TestKernelBlockerNilLocation(t *testing.T) {
	b := NewKernelBlocker(nil)
	res, err := b.Block(context.Background(), nil)
	if err != nil {
		t.Fatalf("Block error: %v", err)
	}
	if res == nil || res.Blocked {
		t.Error("expected not-blocked for nil location")
	}
}
