//go:build heartbeat

package heartbeat

import (
	"testing"
	"time"

	"github.com/asscor/asscor/internal/kernel"
)

func TestHeartbeatRecordAndGet(t *testing.T) {
	m := &Module{
		agents:  make(map[string]*kernel.AgentRecord),
		timeout: 60 * time.Second,
	}

	m.RegisterAgent("host-01", "test-host", "1.0")

	agent := m.GetAgent("host-01")
	if agent == nil {
		t.Fatal("expected agent to be registered")
	}
	if agent.HostID != "host-01" {
		t.Errorf("HostID = %s, want host-01", agent.HostID)
	}
	if agent.Hostname != "test-host" {
		t.Errorf("Hostname = %s, want test-host", agent.Hostname)
	}
	if !agent.Active {
		t.Error("expected agent to be active")
	}
}

func TestHeartbeatRegisterAgent(t *testing.T) {
	m := &Module{
		agents: make(map[string]*kernel.AgentRecord),
	}

	m.RegisterAgent("host-02", "web-server", "1.0.0")

	agent := m.GetAgent("host-02")
	if agent == nil {
		t.Fatal("expected agent to be registered")
	}
	if agent.Hostname != "web-server" {
		t.Errorf("Hostname = %s, want web-server", agent.Hostname)
	}
	if agent.Version != "1.0.0" {
		t.Errorf("Version = %s, want 1.0.0", agent.Version)
	}
}

func TestHeartbeatMultipleAgents(t *testing.T) {
	m := &Module{
		agents: make(map[string]*kernel.AgentRecord),
	}

	m.RegisterAgent("h1", "host1", "1.0")
	m.RegisterAgent("h2", "host2", "2.0")
	m.RegisterAgent("h3", "host3", "3.0")

	agents := m.ListAgents()
	if len(agents) != 3 {
		t.Fatalf("expected 3 agents, got %d", len(agents))
	}

	ids := make(map[string]bool)
	for _, a := range agents {
		ids[a.HostID] = true
	}
	if !ids["h1"] || !ids["h2"] || !ids["h3"] {
		t.Error("expected all 3 agents in list")
	}
}

func TestHeartbeatIsAlive(t *testing.T) {
	m := &Module{
		agents:  make(map[string]*kernel.AgentRecord),
		timeout: 60 * time.Second,
	}

	if m.IsAlive("nonexistent") {
		t.Error("IsAlive should be false for unregistered agent")
	}

	m.RegisterAgent("alive", "alive-host", "1.0")
	if !m.IsAlive("alive") {
		t.Error("IsAlive should be true for registered agent")
	}
}

func TestHeartbeat_PruneDeadAgents(t *testing.T) {
	m := &Module{
		agents:  make(map[string]*kernel.AgentRecord),
		timeout: 60 * time.Second,
	}

	now := time.Now()
	m.agents["host-a"] = &kernel.AgentRecord{HostID: "host-a", Active: true, LastSeen: now}
	m.agents["host-b"] = &kernel.AgentRecord{HostID: "host-b", Active: false, LastSeen: now.Add(-30 * time.Minute)}
	m.agents["host-c"] = &kernel.AgentRecord{HostID: "host-c", Active: false, LastSeen: now.Add(-2 * time.Hour)}

	m.pruneDeadAgents()

	if _, ok := m.agents["host-a"]; !ok {
		t.Error("active host-a should not be pruned")
	}
	if _, ok := m.agents["host-b"]; !ok {
		t.Error("inactive host-b (30min) should not be pruned (<1h cutoff)")
	}
	if _, ok := m.agents["host-c"]; ok {
		t.Error("inactive host-c (2h) should be pruned (>1h cutoff)")
	}
	if len(m.agents) != 2 {
		t.Errorf("expected 2 agents remaining, got %d", len(m.agents))
	}
}
