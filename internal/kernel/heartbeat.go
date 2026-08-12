package kernel

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

type HeartbeatModule struct {
	kernel KernelContext

	mu      sync.RWMutex
	agents  map[string]*AgentRecord
	state   PluginState

	timeout  time.Duration
	stopCh   chan struct{}
	stopped  bool
}

func (m *HeartbeatModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "heartbeat",
		Version:     "1.2.0",
		Description: "Heartbeat monitor — tracks Agent liveness, triggers alerts on timeout (default 60s)",
		Author:      "ASSCOR Core Team",
	}
}

func (m *HeartbeatModule) Dependencies() []PluginDependency {
	return nil
}

func (m *HeartbeatModule) Priority() int {
	return 5
}

func (m *HeartbeatModule) Init(ctx context.Context, kc KernelContext) error {
	m.kernel = kc
	m.agents = make(map[string]*AgentRecord)
	m.timeout = 60 * time.Second
	if cfg := kc.GetConfigObj(); cfg != nil && cfg.HeartbeatTimeoutSec > 0 {
		m.timeout = time.Duration(cfg.HeartbeatTimeoutSec) * time.Second
	}
	m.stopCh = make(chan struct{})
	m.state = PluginInitialized

	kc.Container().Bind((*HeartbeatInterface)(nil), m)
	return nil
}

func (m *HeartbeatModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	go m.monitorLoop()
	logger.WithComponent("heartbeat").Info("started", "timeout", m.timeout)
	return nil
}

func (m *HeartbeatModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.mu.Lock()
	if !m.stopped {
		m.stopped = true
		close(m.stopCh)
	}
	m.mu.Unlock()
	m.state = PluginStopped
	logger.WithComponent("heartbeat").Info("stopped")
	return nil
}

func (m *HeartbeatModule) State() PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *HeartbeatModule) HealthCheck(ctx context.Context) error {
	m.mu.RLock()
	state := m.state
	m.mu.RUnlock()
	if state != PluginStarted {
		return fmt.Errorf("heartbeat not started (state=%s)", state)
	}
	m.mu.RLock()
	agentCount := len(m.agents)
	m.mu.RUnlock()
	if agentCount > 1000 {
		return fmt.Errorf("heartbeat agent count abnormally high: %d", agentCount)
	}
	return nil
}

func (m *HeartbeatModule) RecordHeartbeat(hostID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	agent, ok := m.agents[hostID]
	wasInactive := ok && !agent.Active
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
	if wasInactive && m.kernel != nil && m.kernel.Extensions() != nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "heartbeat.agent_reconnected", map[string]interface{}{
			"host_id":      hostID,
			"connections":  agent.Connections,
		})
	}

	if m.kernel != nil {
		m.kernel.Bus().Publish(m.kernel.Context(), Message{
			Topic:   TopicAgentHeartbeat,
			Payload: hostID,
			Source:  "heartbeat",
		})
	}
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
			Topic:   TopicAgentRegistered,
			Payload: hostID,
			Source:  "heartbeat",
		})
	}

	logger.WithComponent("heartbeat").Info("agent registered", "host_id", hostID, "hostname", hostname)
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
	defer func() {
		if r := recover(); r != nil {
			logger.WithComponent("heartbeat").Error("monitorLoop panic recovered", "panic", r)
		}
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.kernel.Context().Done():
			return
		case <-m.stopCh:
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
		if m.kernel != nil {
			m.kernel.Bus().Publish(m.kernel.Context(), Message{
			Topic:   TopicAgentTimeout,
			Payload: id,
			Source:  "heartbeat",
		})
		if m.kernel.Extensions() != nil {
			m.kernel.Extensions().Execute(m.kernel.Context(), "heartbeat.agent_timeout", map[string]interface{}{
				"host_id": id,
			})
		}
		}
		logger.WithComponent("heartbeat").Warn("agent timed out", "host_id", id)

		m.mu.Lock()
		if agent, ok := m.agents[id]; ok {
			agent.Active = false
		}
		m.mu.Unlock()
	}

	m.pruneDeadAgents()
}

func (m *HeartbeatModule) pruneDeadAgents() {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	for id, agent := range m.agents {
		if !agent.Active && agent.LastSeen.Before(cutoff) {
			delete(m.agents, id)
			if m.kernel != nil && m.kernel.Extensions() != nil {
				m.kernel.Extensions().Execute(m.kernel.Context(), "heartbeat.agent_pruned", map[string]interface{}{
					"host_id":   id,
					"last_seen": agent.LastSeen.Format(time.RFC3339),
				})
			}
			logger.WithComponent("heartbeat").Info("pruned dead agent", "host_id", id, "last_seen", agent.LastSeen.Format(time.RFC3339))
		}
	}
}