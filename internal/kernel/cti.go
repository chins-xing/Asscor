package kernel

import (
	"context"
	"log"
	"math"
	"sync"
	"time"
)

type CTIModule struct {
	kernel *Kernel

	mu            sync.RWMutex
	coefficient   float64
	lastUpdate    time.Time
	activeThreats int
	state         PluginState

	updateInterval time.Duration
}

func (m *CTIModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "cti",
		Version:     "1.2.0",
		Description: "Cyber Threat Intelligence manager — computes global threat coefficient μ from OTX/MISP feeds",
		Author:      "ARGUS Core Team",
	}
}

func (m *CTIModule) Dependencies() []PluginDependency {
	return nil
}

func (m *CTIModule) Priority() int {
	return 10
}

func (m *CTIModule) Init(ctx context.Context, k *Kernel) error {
	m.kernel = k
	m.coefficient = 1.0
	m.updateInterval = 15 * time.Minute
	m.state = PluginInitialized

	k.Container().Bind((*CTIInterface)(nil), m)
	return nil
}

func (m *CTIModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	go m.updateLoop()
	log.Printf("cti: started (μ=%.2f)", m.coefficient)
	return nil
}

func (m *CTIModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.state = PluginStopped
	log.Println("cti: stopped")
	return nil
}

func (m *CTIModule) State() PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *CTIModule) updateLoop() {
	ticker := time.NewTicker(m.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.kernel.Context().Done():
			return
		case <-ticker.C:
			m.updateCoefficient()
		}
	}
}

func (m *CTIModule) updateCoefficient() {
	m.mu.Lock()
	defer m.mu.Unlock()

	base := 1.0
	threatPenalty := float64(m.activeThreats) * 0.02
	m.coefficient = math.Max(0.60, base-threatPenalty)

	m.lastUpdate = time.Now()
	log.Printf("cti: coefficient updated to μ=%.4f (active threats: %d)", m.coefficient, m.activeThreats)
}

func (m *CTIModule) GetCoefficient() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.coefficient
}

func (m *CTIModule) ReportThreat(severity string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeThreats++

	m.kernel.Bus().Publish(m.kernel.Context(), Message{
		Topic:   "cti.threat_detected",
		Payload: map[string]interface{}{"severity": severity, "active_count": m.activeThreats},
		Source:  "cti",
	})
}

func (m *CTIModule) ClearThreat() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeThreats > 0 {
		m.activeThreats--
	}
}

func (m *CTIModule) HealthCheck(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if time.Since(m.lastUpdate) > m.updateInterval*3 {
		return context.DeadlineExceeded
	}
	return nil
}

type CTIInterface interface {
	GetCoefficient() float64
	ReportThreat(severity string)
	ClearThreat()
}