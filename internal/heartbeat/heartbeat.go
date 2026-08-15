//go:build heartbeat

package heartbeat

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/logger"
)

// Module tracks Agent liveness and triggers alerts on timeout.
// It is a build-tag optional module (//go:build heartbeat): the kernel keeps
// only the HeartbeatInterface contract, this package provides the
// Module tracks agent liveness and identity. CertFingerprint binds each
// host_id to the mTLS certificate it registered with (identity hardening).
// Bindings are persisted to <data_dir>/heartbeat_identity.json so they survive
// kernel restarts (a restarted kernel must not lose the identity anchor).
type Module struct {
	kc kernel.KernelContext

	mu     sync.RWMutex
	agents map[string]*kernel.AgentRecord
	state  kernel.PluginState

	timeout time.Duration
	stopCh  chan struct{}
	stopped bool

	// identityPath persists host_id ↔ cert-fingerprint bindings.
	identityPath string
}

// New creates a heartbeat module instance.
func New() *Module {
	return &Module{}
}

func (m *Module) Info() kernel.PluginInfo {
	return kernel.PluginInfo{
		Name:        "heartbeat",
		Version:     "1.2.0",
		Description: "Heartbeat monitor — tracks Agent liveness, triggers alerts on timeout (default 60s)",
		Author:      "ASSCOR Core Team",
	}
}

func (m *Module) Dependencies() []kernel.PluginDependency {
	return nil
}

func (m *Module) Priority() int {
	return 5
}

func (m *Module) Init(ctx context.Context, kc kernel.KernelContext) error {
	m.kc = kc
	m.agents = make(map[string]*kernel.AgentRecord)
	m.timeout = 60 * time.Second
	if cfg := kc.GetConfigObj(); cfg != nil && cfg.HeartbeatTimeoutSec > 0 {
		m.timeout = time.Duration(cfg.HeartbeatTimeoutSec) * time.Second
	}
	if cfg := kc.GetConfigObj(); cfg != nil && cfg.DataDir != "" {
		m.identityPath = filepath.Join(cfg.DataDir, "heartbeat_identity.json")
		m.loadIdentityLocked()
	}
	m.stopCh = make(chan struct{})
	m.state = kernel.PluginInitialized

	kc.Container().Bind((*kernel.HeartbeatInterface)(nil), m)
	return nil
}

// loadIdentityLocked restores persisted host_id ↔ cert-fingerprint bindings
// so identity anchors survive kernel restarts. Call with m.mu held (Init runs
// single-threaded).
func (m *Module) loadIdentityLocked() {
	if m.identityPath == "" {
		return
	}
	data, err := os.ReadFile(m.identityPath)
	if err != nil {
		return // no bindings yet
	}
	var fpMap map[string]string
	if err := json.Unmarshal(data, &fpMap); err != nil {
		logger.WithComponent("heartbeat").Warn("cannot parse identity bindings, ignoring", "path", m.identityPath, "error", err)
		return
	}
	for host, fp := range fpMap {
		if fp == "" {
			continue
		}
		rec := m.agents[host]
		if rec == nil {
			rec = &kernel.AgentRecord{HostID: host}
			m.agents[host] = rec
		}
		rec.CertFingerprint = fp
	}
	logger.WithComponent("heartbeat").Info("loaded identity bindings", "count", len(fpMap), "path", m.identityPath)
}

// saveIdentityLocked atomically persists all bindings. Call with m.mu held.
func (m *Module) saveIdentityLocked() {
	if m.identityPath == "" {
		return
	}
	fpMap := make(map[string]string)
	for host, rec := range m.agents {
		if rec.CertFingerprint != "" {
			fpMap[host] = rec.CertFingerprint
		}
	}
	data, err := json.Marshal(fpMap)
	if err != nil {
		return
	}
	tmp := m.identityPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		logger.WithComponent("heartbeat").Warn("cannot persist identity bindings", "error", err)
		return
	}
	if err := os.Rename(tmp, m.identityPath); err != nil {
		logger.WithComponent("heartbeat").Warn("cannot persist identity bindings (rename)", "error", err)
	}
}

func (m *Module) Start(ctx context.Context) error {
	m.state = kernel.PluginStarted
	go m.monitorLoop()
	logger.WithComponent("heartbeat").Info("started", "timeout", m.timeout)
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	m.state = kernel.PluginStopping
	m.mu.Lock()
	if !m.stopped {
		m.stopped = true
		close(m.stopCh)
	}
	m.mu.Unlock()
	m.state = kernel.PluginStopped
	logger.WithComponent("heartbeat").Info("stopped")
	return nil
}

func (m *Module) State() kernel.PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *Module) HealthCheck(ctx context.Context) error {
	m.mu.RLock()
	state := m.state
	m.mu.RUnlock()
	if state != kernel.PluginStarted {
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

func (m *Module) RecordHeartbeat(hostID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	agent, ok := m.agents[hostID]
	wasInactive := ok && !agent.Active
	if !ok {
		agent = &kernel.AgentRecord{
			HostID:     hostID,
			Registered: time.Now(),
			Active:     true,
		}
		m.agents[hostID] = agent
	}

	agent.LastSeen = time.Now()
	agent.Connections++
	agent.Active = true
	if wasInactive && m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "heartbeat.agent_reconnected", map[string]interface{}{
			"host_id":     hostID,
			"connections": agent.Connections,
		})
	}

	if m.kc != nil {
		m.kc.Bus().Publish(m.kc.Context(), kernel.Message{
			Topic:   kernel.TopicAgentHeartbeat,
			Payload: hostID,
			Source:  "heartbeat",
		})
	}
}

func (m *Module) RegisterAgent(hostID, hostname, version string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.agents == nil {
		m.agents = make(map[string]*kernel.AgentRecord)
	}

	rec := m.agents[hostID]
	if rec == nil {
		rec = &kernel.AgentRecord{}
		m.agents[hostID] = rec
	}
	rec.HostID = hostID
	rec.Hostname = hostname
	rec.Version = version
	rec.LastSeen = time.Now()
	if rec.Registered.IsZero() {
		rec.Registered = time.Now()
	}
	rec.Active = true

	if m.kc != nil {
		m.kc.Bus().Publish(m.kc.Context(), kernel.Message{
			Topic:   kernel.TopicAgentRegistered,
			Payload: hostID,
			Source:  "heartbeat",
		})
	}

	logger.WithComponent("heartbeat").Info("agent registered", "host_id", hostID, "hostname", hostname)
}

// BindAgentCert binds hostID to the presented mTLS certificate fingerprint on
// first registration (one certificate, one identity). An empty fingerprint
// (mTLS disabled, development only) always succeeds and stores nothing.
func (m *Module) BindAgentCert(hostID, fingerprint string) bool {
	if fingerprint == "" {
		return true // mTLS disabled — no binding (development mode)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.agents == nil {
		m.agents = make(map[string]*kernel.AgentRecord)
	}

	// The fingerprint must not already belong to another host.
	for id, rec := range m.agents {
		if id != hostID && rec.CertFingerprint == fingerprint {
			logger.WithComponent("heartbeat").Warn("cert fingerprint already bound to another host",
				"host_id", hostID, "other_host", id, "fingerprint", shortFP(fingerprint))
			return false
		}
	}

	rec := m.agents[hostID]
	if rec == nil {
		rec = &kernel.AgentRecord{HostID: hostID}
		m.agents[hostID] = rec
	}
	if rec.CertFingerprint != "" && rec.CertFingerprint != fingerprint {
		logger.WithComponent("heartbeat").Warn("host already bound to a different certificate",
			"host_id", hostID, "old_fingerprint", shortFP(rec.CertFingerprint), "new_fingerprint", shortFP(fingerprint))
		return false
	}
	rec.CertFingerprint = fingerprint
	m.saveIdentityLocked()
	return true
}

// shortFP shortens a certificate fingerprint for log output without panicking
// on short test values.
func shortFP(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12] + "..."
}

// VerifyAgentCert checks the connecting certificate fingerprint matches the
// one bound to hostID. Returns true when hostID has no binding yet (first
// contact, BindAgentCert will establish it) or the fingerprints match. An
// empty fingerprint (no mTLS) always verifies.
func (m *Module) VerifyAgentCert(hostID, fingerprint string) bool {
	if fingerprint == "" {
		return true // mTLS disabled — no verification (development mode)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec := m.agents[hostID]
	if rec == nil || rec.CertFingerprint == "" {
		return true // not bound yet
	}
	return rec.CertFingerprint == fingerprint
}

func (m *Module) GetAgent(hostID string) *kernel.AgentRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.agents[hostID]
}

func (m *Module) ListAgents() []*kernel.AgentRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	agents := make([]*kernel.AgentRecord, 0, len(m.agents))
	for _, a := range m.agents {
		agents = append(agents, a)
	}
	return agents
}

func (m *Module) IsAlive(hostID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	agent, ok := m.agents[hostID]
	if !ok {
		return false
	}
	return agent.Active && time.Since(agent.LastSeen) < m.timeout
}

func (m *Module) monitorLoop() {
	defer func() {
		if r := recover(); r != nil {
			logger.WithComponent("heartbeat").Error("monitorLoop panic recovered", "panic", r)
		}
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.kc.Context().Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.checkTimeouts()
		}
	}
}

func (m *Module) checkTimeouts() {
	m.mu.RLock()
	now := time.Now()
	var timedOut []string
	for id, agent := range m.agents {
		// Records restored from the persisted identity file have a zero
		// LastSeen until the agent actually connects. They are anchors, not
		// live agents: do not mark them timed out on kernel start.
		if agent.LastSeen.IsZero() {
			continue
		}
		if now.Sub(agent.LastSeen) > m.timeout {
			timedOut = append(timedOut, id)
		}
	}
	m.mu.RUnlock()

	for _, id := range timedOut {
		if m.kc != nil {
			m.kc.Bus().Publish(m.kc.Context(), kernel.Message{
				Topic:   kernel.TopicAgentTimeout,
				Payload: id,
				Source:  "heartbeat",
			})
			if m.kc.Extensions() != nil {
				m.kc.Extensions().Execute(m.kc.Context(), "heartbeat.agent_timeout", map[string]interface{}{
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

func (m *Module) pruneDeadAgents() {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	for id, agent := range m.agents {
		// Identity anchors (host_id ↔ cert-fingerprint bindings) must never be
		// pruned by liveness tracking: they are permanent until explicitly
		// revoked. Deleting the record here would drop the CertFingerprint from
		// memory, letting any certificate re-bind the host on next registration
		// (the persisted file would then be silently overwritten — the very
		// impersonation the binding exists to stop).
		if agent.CertFingerprint != "" {
			continue
		}
		if !agent.Active && agent.LastSeen.Before(cutoff) {
			delete(m.agents, id)
			if m.kc != nil && m.kc.Extensions() != nil {
				m.kc.Extensions().Execute(m.kc.Context(), "heartbeat.agent_pruned", map[string]interface{}{
					"host_id":   id,
					"last_seen": agent.LastSeen.Format(time.RFC3339),
				})
			}
			logger.WithComponent("heartbeat").Info("pruned dead agent", "host_id", id, "last_seen", agent.LastSeen.Format(time.RFC3339))
		}
	}
}
