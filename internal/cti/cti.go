//go:build cti

package cti

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/logger"
)

// Module fetches OTX pulses and MISP events and computes the global threat
// coefficient μ. It is a build-tag optional plugin (//go:build cti); the kernel
// keeps only the CTIInterface contract.
type Module struct {
	kc kernel.KernelContext

	mu            sync.RWMutex
	coefficient   float64
	lastUpdate    time.Time
	activeThreats int
	state         kernel.PluginState

	updateInterval time.Duration
	stopCh         chan struct{}
	stopped        bool

	otxAPIKey        string
	mispURL          string
	mispAPIKey       string
	sourcesLastPulse time.Time
}

// New creates a CTI module instance.
func New() *Module {
	return &Module{
		coefficient:    1.0,
		updateInterval: 15 * time.Minute,
	}
}

func (m *Module) Info() kernel.PluginInfo {
	return kernel.PluginInfo{
		Name:        "cti",
		Version:     "1.3.0",
		Description: "Cyber Threat Intelligence manager — fetches OTX pulses and MISP events, computes global threat coefficient μ",
		Author:      "ASSCOR Core Team",
	}
}

func (m *Module) Dependencies() []kernel.PluginDependency {
	return nil
}

func (m *Module) Priority() int {
	return 10
}

func (m *Module) Init(ctx context.Context, kc kernel.KernelContext) error {
	m.kc = kc
	m.coefficient = 1.0
	m.updateInterval = 15 * time.Minute
	m.stopCh = make(chan struct{})
	m.state = kernel.PluginInitialized

	m.otxAPIKey = os.Getenv("OTX_API_KEY")
	m.mispURL = os.Getenv("MISP_URL")
	m.mispAPIKey = os.Getenv("MISP_API_KEY")

	if cfg := kc.GetConfigObj(); cfg != nil {
		if m.otxAPIKey == "" {
			m.otxAPIKey = cfg.AdapterConfig["otx_api_key"]
		}
		if m.mispURL == "" {
			m.mispURL = cfg.AdapterConfig["misp_url"]
		}
		if m.mispAPIKey == "" {
			m.mispAPIKey = cfg.AdapterConfig["misp_api_key"]
		}
	}

	kc.Container().Bind((*kernel.CTIInterface)(nil), m)
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.state = kernel.PluginStarted
	go m.updateLoop()
	logger.WithComponent("cti").Info("started", "coefficient", m.coefficient, "otx_configured", m.otxAPIKey != "", "misp_configured", m.mispURL != "")
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
	logger.WithComponent("cti").Info("stopped")
	return nil
}

func (m *Module) State() kernel.PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *Module) updateLoop() {
	defer func() {
		if r := recover(); r != nil {
			logger.WithComponent("cti").Error("updateLoop panic recovered", "panic", r)
		}
	}()

	ticker := time.NewTicker(m.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.kc.Context().Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.updateFromFeeds()
			m.updateCoefficient()
		}
	}
}

func (m *Module) updateFromFeeds() {
	if m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "cti.pre_update", nil)
	}

	var totalWeight int

	if m.otxAPIKey != "" {
		weight := m.fetchOTXPulses()
		totalWeight += weight
	}

	if m.mispURL != "" && m.mispAPIKey != "" {
		weight := m.fetchMISPEvents()
		totalWeight += weight
	}

	m.mu.Lock()
	if totalWeight > 0 {
		m.activeThreats += totalWeight
	}
	m.mu.Unlock()

	if m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "cti.post_update", map[string]interface{}{
			"weight":     totalWeight,
			"active_ctx": m.activeThreats,
		})
	}
}

func (m *Module) fetchOTXPulses() int {
	type otxPulseIndicator struct {
		Type string `json:"type"`
	}

	type otxPulse struct {
		ID          string              `json:"id"`
		Name        string              `json:"name"`
		Description string              `json:"description"`
		TLP         string              `json:"tlp"`
		Adversary   string              `json:"adversary"`
		Created     string              `json:"created"`
		Modified    string              `json:"modified"`
		Indicators  []otxPulseIndicator `json:"indicators"`
		Tags        []string            `json:"tags"`
	}

	type otxResponse struct {
		Count   int        `json:"count"`
		Next    string     `json:"next"`
		Results []otxPulse `json:"results"`
	}

	url := "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50"
	if !m.sourcesLastPulse.IsZero() {
		modified := m.sourcesLastPulse.Format(time.RFC3339)
		url += "&modified_since=" + modified
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logger.WithComponent("cti").Warn("OTX request build failed", "error", err)
		return 0
	}
	req.Header.Set("X-OTX-API-KEY", m.otxAPIKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.WithComponent("cti").Warn("OTX fetch failed", "error", err)
		return 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0
	}

	var otxResp otxResponse
	if err := json.Unmarshal(body, &otxResp); err != nil {
		logger.WithComponent("cti").Warn("OTX parse failed", "error", err)
		return 0
	}

	var weight int
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, pulse := range otxResp.Results {
		created, err := time.Parse(time.RFC3339, pulse.Created)
		if err != nil {
			continue
		}
		if created.Before(cutoff) {
			continue
		}
		pulseWeight := 1
		if stringsContainAny(pulse.Tags, "apt", "malware", "ransomware", "exploit") {
			pulseWeight = 4
		} else if stringsContainAny(pulse.Tags, "phishing", "c2", "botnet") {
			pulseWeight = 3
		} else if stringsContainAny(pulse.Tags, "trojan", "backdoor", "rat") {
			pulseWeight = 2
		}
		weight += pulseWeight * (1 + len(pulse.Indicators)/10)
	}

	m.sourcesLastPulse = time.Now()
	logger.WithComponent("cti").Info("OTX pulses fetched",
		"pulses", otxResp.Count, "recent_weight", weight)
	return weight
}

func stringsContainAny(tags []string, needles ...string) bool {
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		for _, n := range needles {
			if strings.Contains(lower, n) {
				return true
			}
		}
	}
	return false
}

func (m *Module) fetchMISPEvents() int {
	if m.mispURL == "" || m.mispAPIKey == "" {
		return 0
	}

	type mispEvent struct {
		Event struct {
			ID   string `json:"id"`
			Info string `json:"info"`
			Tag  []struct {
				Name string `json:"name"`
			} `json:"Tag"`
		} `json:"Event"`
	}

	url := strings.TrimRight(m.mispURL, "/") + "/events/index"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logger.WithComponent("cti").Warn("MISP request build failed", "error", err)
		return 0
	}
	req.Header.Set("Authorization", m.mispAPIKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.WithComponent("cti").Warn("MISP fetch failed", "error", err)
		return 0
	}
	defer resp.Body.Close()

	var events []mispEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return 0
	}

	var weight int
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, e := range events {
		for _, tag := range e.Event.Tag {
			lower := strings.ToLower(tag.Name)
			if strings.Contains(lower, "tlp:red") || strings.Contains(lower, "apt") {
				weight += 4
				break
			} else if strings.Contains(lower, "tlp:amber") {
				weight += 3
				break
			} else if strings.Contains(lower, "tlp:green") {
				weight += 1
				break
			}
		}
	}
	_ = cutoff

	logger.WithComponent("cti").Info("MISP events fetched",
		"events", len(events), "weight", weight)
	return weight
}

func (m *Module) updateCoefficient() {
	m.mu.Lock()
	defer m.mu.Unlock()

	prevCoeff := m.coefficient

	base := 1.0
	threatPenalty := float64(m.activeThreats) * 0.02
	m.coefficient = math.Max(0.60, base-threatPenalty)

	m.lastUpdate = time.Now()

	if m.coefficient != prevCoeff && m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "cti.coefficient_changed", map[string]interface{}{
			"prev_coeff": prevCoeff,
			"new_coeff":  m.coefficient,
			"threats":    m.activeThreats,
		})
	}

	logger.WithComponent("cti").Info("coefficient updated", "coefficient", m.coefficient, "active_threats", m.activeThreats)
}

func (m *Module) GetCoefficient() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.coefficient
}

func severityWeight(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 2
	}
}

func (m *Module) ReportThreat(severity string) {
	weight := severityWeight(severity)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeThreats += weight

	if m.kc != nil {
		m.kc.Bus().Publish(m.kc.Context(), kernel.Message{
			Topic:   kernel.TopicCTIThreatDetected,
			Payload: map[string]interface{}{"severity": severity, "weight": weight, "active_count": m.activeThreats},
			Source:  "cti",
		})
	}
}

func (m *Module) ClearThreat() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeThreats > 0 {
		m.activeThreats--
	}
}

func (m *Module) HealthCheck(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if time.Since(m.lastUpdate) > m.updateInterval*3 {
		return fmt.Errorf("cti: last update %v ago, expected within %v", time.Since(m.lastUpdate), m.updateInterval*3)
	}
	return nil
}
