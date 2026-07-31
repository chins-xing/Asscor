package kernel

import (
	"testing"
	"time"
)

func TestHeartbeatRecordAndGet(t *testing.T) {
	m := &HeartbeatModule{
		agents:  make(map[string]*AgentRecord),
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
	m := &HeartbeatModule{
		agents: make(map[string]*AgentRecord),
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
	m := &HeartbeatModule{
		agents: make(map[string]*AgentRecord),
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
	m := &HeartbeatModule{
		agents:  make(map[string]*AgentRecord),
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
