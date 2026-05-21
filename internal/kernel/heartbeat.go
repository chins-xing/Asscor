package kernel

import (
	"context"
	"sync"
	"time"

	"github.com/argus-security/argus/internal/logger"
)

type AgentRecord struct {
	HostID      string
	Hostname    string
	Version     string
	LastSeen    time.Time
	Registered  time.Time
	Connections int64
	Active      bool
}

type HeartbeatModule struct {
	kernel *Kernel

	mu      sync.RWMutex
	agents  map[string]*AgentRecord
	state   PluginState

	timeout time.Duration
}

func (m *HeartbeatModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "heartbeat",
		Version:     "1.2.0",
		Description: "Heartbeat monitor — tracks Agent liveness, triggers alerts on timeout (default 60s)",
		Author:      "ARGUS Core Team",
	}
}

func (m *HeartbeatModule) Dependencies() []PluginDependency {
	return nil
}

func (m *HeartbeatModule) Priority() int {
	return 5
}

func (m *HeartbeatModule) Init(ctx context.Context, k *Kernel) error {
	m.kernel = k
	m.agents = make(map[string]*AgentRecord)
	m.timeout = 60 * time.Second
	m.state = PluginInitialized

	k.Container().Bind((*HeartbeatInterface)(nil), m)
	return nil
}

func (m *HeartbeatModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	go m.monitorLoop()
	logger.With("component", "heartbeat").Info("started", "timeout", m.timeout)
	return nil
}

func (m *HeartbeatModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.state = PluginStopped
	logger.With("component", "heartbeat").Info("stopped")
	return nil
}

func (m *HeartbeatModule) State() PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *HeartbeatModule) RecordHeartbeat(hostID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	agent, ok := m.agents[hostID]
	if !ok {
		agent = &AgentRecord{
			HostID:     hostID,
			Registered: time.Now(),
			Active:     true,
		}
		m.agents[hostID] = agent
	}

	agent.LastSeen = time.Now()
	agent.Connections++
	agent.Active = true

	m.kernel.Bus().Publish(m.kernel.Context(), Message{
		Topic:   "agent.heartbeat",
		Payload: hostID,
		Source:  "heartbeat",
	})
}

func (m *HeartbeatModule) RegisterAgent(hostID, hostname, version string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.agents == nil {
		m.agents = make(map[string]*AgentRecord)
	}

	m.agents[hostID] = &AgentRecord{
		HostID:     hostID,
		Hostname:   hostname,
		Version:    version,
		LastSeen:   time.Now(),
		Registered: time.Now(),
		Active:     true,
	}

	if m.kernel != nil {
		m.kernel.Bus().Publish(m.kernel.Context(), Message{
			Topic:   "agent.registered",
			Payload: hostID,
			Source:  "heartbeat",
		})
	}

	logger.With("component", "heartbeat").Info("agent registered", "host_id", hostID, "hostname", hostname)
}

func (m *HeartbeatModule) GetAgent(hostID string) *AgentRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.agents[hostID]
}

func (m *HeartbeatModule) ListAgents() []*AgentRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	agents := make([]*AgentRecord, 0, len(m.agents))
	for _, a := range m.agents {
		agents = append(agents, a)
	}
	return agents
}

func (m *HeartbeatModule) IsAlive(hostID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	agent, ok := m.agents[hostID]
	if !ok {
		return false
	}
	return agent.Active && time.Since(agent.LastSeen) < m.timeout
}

func (m *HeartbeatModule) monitorLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.kernel.Context().Done():
			return
		case <-ticker.C:
			m.checkTimeouts()
		}
	}
}

func (m *HeartbeatModule) checkTimeouts() {
	m.mu.RLock()
	now := time.Now()
	var timedOut []string
	for id, agent := range m.agents {
		if now.Sub(agent.LastSeen) > m.timeout {
			timedOut = append(timedOut, id)
		}
	}
	m.mu.RUnlock()

	for _, id := range timedOut {
		m.kernel.Bus().Publish(m.kernel.Context(), Message{
			Topic:   "agent.timeout",
			Payload: id,
			Source:  "heartbeat",
		})
		logger.With("component", "heartbeat").Warn("agent timed out", "host_id", id)

		m.mu.Lock()
		if agent, ok := m.agents[id]; ok {
			agent.Active = false
		}
		m.mu.Unlock()
	}
}

type HeartbeatInterface interface {
	RecordHeartbeat(hostID string)
	RegisterAgent(hostID, hostname, version string)
	GetAgent(hostID string) *AgentRecord
	ListAgents() []*AgentRecord
	IsAlive(hostID string) bool
}