//go:build engine

package srd

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/common"
	"github.com/asscor/asscor/internal/logger"
)

// TopicSRDResult is the Bus topic published when an external tool report is processed.
const TopicSRDResult = "srd.external_result"

// --- Plugin types (local copy to avoid coupling with kernel package) ---

type PluginState int

const (
	PluginUnregistered PluginState = iota
	PluginRegistered
	PluginInitialized
	PluginStarted
	PluginStopping
	PluginStopped
	PluginFailed
)

type PluginInfo struct {
	Name        string
	Version     string
	Description string
	Author      string
}

type PluginDependency struct {
	Interface interface{}
	Name      string
}

// Manager is the Plugin that integrates external assessment tools with the SRD engine.
// It wraps the Pipeline and exposes SRD results to the ASSCOR event bus.
type Manager struct {
	kernel   KernelContext
	cfg      Config
	pipeline *Pipeline
	state    PluginState

	mu       sync.RWMutex
	history  map[string][]*SRDResult // hostID -> results
	scanDirs []string
	stopCh   chan struct{}
}

type KernelContext interface {
	Context() context.Context
	Bus() BusAccess
	GetConfigObj() ConfigGetter
}

type BusAccess interface {
	Publish(ctx context.Context, topic string, payload interface{})
}

type ConfigGetter interface {
	GetConfigObj() interface{}
}

// NewManager creates a new SRD Manager plugin.
func NewManager() *Manager {
	cfg := DefaultConfig()
	return &Manager{
		cfg:     cfg,
		state:   PluginUnregistered,
		history: make(map[string][]*SRDResult),
		scanDirs: []string{
			"/var/log/assessor/",
			"/opt/security-reports/",
			"/tmp/assessor/",
		},
	}
}

// Plugin interface.

func (m *Manager) Info() PluginInfo {
	return PluginInfo{
		Name:        "srd_adapters",
		Version:    "1.0.0",
		Description: "SRD external adapters — normalizes OpenSCAP, Lynis and generic JSON reports into Prism/SRD input",
		Author:     "ASSCOR Core Team",
	}
}

func (m *Manager) Dependencies() []PluginDependency {
	return nil
}

func (m *Manager) Priority() int {
	return 110 // runs after assessor (P=40) and adapter_integration (P=45)
}

func (m *Manager) Init(ctx context.Context, kc KernelContext) error {
	m.kernel = kc
	m.state = PluginInitialized

	// Load config from kernel config object.
	if cfgObj := kc.GetConfigObj(); cfgObj != nil {
		m.loadConfig(cfgObj)
	}

	// Create pipeline.
	m.pipeline = NewPipeline(m.cfg)

	// Register all built-in adapters.
	m.registerAdapters()

	logger.WithComponent("srd_adapters").Info("initialized",
		"adapters", len(List()),
		"scan_dirs", len(m.scanDirs),
	)
	return nil
}

func (m *Manager) Start(ctx context.Context) error {
	m.state = PluginStarted
	m.stopCh = make(chan struct{})

	go m.scanLoop()

	logger.WithComponent("srd_adapters").Info("started")
	return nil
}

func (m *Manager) Stop(ctx context.Context) error {
	m.state = PluginStopping
	if m.stopCh != nil {
		select {
		case <-m.stopCh:
		default:
			close(m.stopCh)
		}
	}
	m.state = PluginStopped
	logger.WithComponent("srd_adapters").Info("stopped")
	return nil
}

func (m *Manager) State() PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// Business methods.

func (m *Manager) RegisterAdapter(ad Adapter) {
	Register(ad)
}

func (m *Manager) ProcessReport(ctx context.Context, toolID string, data []byte) (*SRDResult, error) {
	result, err := m.pipeline.ProcessFromBytes(ctx, toolID, data)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}

	m.storeResult(result)
	m.publishResult(ctx, result)
	return result, nil
}

// SetTopology records a host's network position (subnets/zone) for real-edge
// construction in the SRD pipeline.
func (m *Manager) SetTopology(hostID string, subnets []string, zone string) {
	m.pipeline.SetTopology(hostID, subnets, zone)
}

// GetReachableHosts returns hosts sharing a subnet with hostID (lateral-movement scope).
func (m *Manager) GetReachableHosts(hostID string) []string {
	return m.pipeline.GetReachableHosts(hostID)
}

func (m *Manager) ProcessFile(ctx context.Context, path string) (*SRDResult, error) {
	result, err := m.pipeline.ProcessFromFile(ctx, path)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}

	m.storeResult(result)
	m.publishResult(ctx, result)
	return result, nil
}

func (m *Manager) GetHistory(hostID string) []*SRDResult {
	m.mu.RLock()
	defer m.mu.RUnlock()
	hist, ok := m.history[hostID]
	if !ok {
		return nil
	}
	out := make([]*SRDResult, len(hist))
	copy(out, hist)
	return out
}

func (m *Manager) LatestResult(hostID string) *SRDResult {
	hist := m.GetHistory(hostID)
	if len(hist) == 0 {
		return nil
	}
	return hist[len(hist)-1]
}

func (m *Manager) AllResults() map[string]*SRDResult {
	m.mu.RLock()
	defer m.mu.RUnlock()
	latest := make(map[string]*SRDResult)
	for hostID, hist := range m.history {
		if len(hist) > 0 {
			latest[hostID] = hist[len(hist)-1]
		}
	}
	return latest
}

func (m *Manager) SetScanDirectory(dir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanDirs = append(m.scanDirs, dir)
}

func (m *Manager) SetEnabled(toolID string, enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg.EnabledAdapters == nil {
		m.cfg.EnabledAdapters = make(map[string]bool)
	}
	m.cfg.EnabledAdapters[toolID] = enabled
}

// Internal methods.

func (m *Manager) registerAdapters() {
	Register(newOpenSCAPAdapter())
	Register(newLynisAdapter())
	Register(newGenericAdapter())
	Register(newAtomicRedAdapter())
}

func (m *Manager) loadConfig(cfgObj interface{}) {
	if cfg, ok := cfgObj.(interface {
		Get(string) string
	}); ok {
		if v := cfg.Get("srd.sync_interval_sec"); v != "" {
			if n, err := parseInt(v); err == nil && n > 0 {
				m.cfg.SyncIntervalSec = n
			}
		}
	}
}

func (m *Manager) storeResult(result *SRDResult) {
	if result == nil || result.Report == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	hostID := result.Report.HostID
	if hostID == "" {
		hostID = "unknown"
	}

	m.history[hostID] = append(m.history[hostID], result)

	// Keep last 100 results per host.
	if len(m.history[hostID]) > 100 {
		m.history[hostID] = m.history[hostID][len(m.history[hostID])-100:]
	}
}

func (m *Manager) publishResult(ctx context.Context, result *SRDResult) {
	if m.kernel == nil || m.kernel.Bus() == nil {
		return
	}

	pr := result.PrismResult
	payload := map[string]interface{}{
		"tool":       result.Report.Tool,
		"host_id":    result.Report.HostID,
		"hostname":   result.Report.Hostname,
		"scan_time":  result.Report.ScanTime,
		"item_count": len(result.Report.Items),
		"raw_score":  result.Report.RawScore,
		"ssam_score": pr.SsamScore,
		"prism_score": pr.PrismScore,
		"external_risk": pr.ExternalRisk,
		"prop_penalty": pr.PropPenalty,
		"debt_penalty": pr.DebtPenalty,
		"propagated_risk": pr.PropagatedRisk,
		"debt_raw": pr.DebtRaw,
		"collapse_modifier": pr.CollapseModifier,
		"risk_velocity": pr.RiskVelocity,
	}

	if result.SemanticResult != nil {
		payload["semantic_state"] = result.SemanticResult.CurrentState
		payload["semantic_state_vector"] = result.SemanticResult.StateVector
		payload["semantic_stable"] = result.SemanticResult.StableMembership
		payload["semantic_degraded"] = result.SemanticResult.DegradedMembership
		payload["semantic_untrusted"] = result.SemanticResult.UntrustedMembership
		payload["semantic_collapse"] = result.SemanticResult.CollapseMembership
	}

	if result.InferenceResult != nil {
		payload["inference_trend"] = result.InferenceResult.Trend
		payload["inference_confidence"] = result.InferenceResult.Confidence
		payload["inference_collapse_risk"] = result.InferenceResult.CollapseRisk
		payload["inference_horizon_days"] = result.InferenceResult.HorizonDays
		payload["inference_model"] = "MarkovChain"
	}

	m.kernel.Bus().Publish(ctx, TopicSRDResult, payload)
}

func (m *Manager) scanLoop() {
	defer func() {
		if r := recover(); r != nil {
			logger.WithComponent("srd_adapters").Error("scanLoop panic recovered", "panic", r)
		}
	}()

	// Perform initial scan.
	m.performScan(m.kernel.Context())

	ticker := time.NewTicker(time.Duration(m.cfg.SyncIntervalSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.kernel.Context().Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.performScan(m.kernel.Context())
		}
	}
}

func (m *Manager) performScan(ctx context.Context) {
	m.mu.RLock()
	dirs := make([]string, len(m.scanDirs))
	copy(dirs, m.scanDirs)
	m.mu.RUnlock()

	var processed, failed int
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())

			// Try each adapter.
			found := false
			for _, ad := range List() {
				if !ad.IsEnabled(m.cfg) {
					continue
				}
				if !ad.SupportsFormat(path) {
					continue
				}

				result, err := m.pipeline.ProcessFromFile(ctx, path)
				if err != nil || result == nil {
					continue
				}

				m.storeResult(result)
				m.publishResult(ctx, result)
				found = true
				processed++

				// Move processed file to avoid re-processing.
				processedDir := filepath.Join(dir, ".processed")
				os.MkdirAll(processedDir, 0755)
				os.Rename(path, filepath.Join(processedDir, entry.Name()))
				break
			}

			if !found {
				failed++
			}
		}
	}

	if processed > 0 || failed > 0 {
		logger.WithComponent("srd_adapters").Info("scan completed",
			"processed", processed, "skipped", failed)
	}
}

// SRDManagerInterface is the public interface exposed by the SRD Manager.
type SRDManagerInterface interface {
	ProcessReport(ctx context.Context, toolID string, data []byte) (*SRDResult, error)
	ProcessFile(ctx context.Context, path string) (*SRDResult, error)
	LatestResult(hostID string) *SRDResult
	GetHistory(hostID string) []*SRDResult
	AllResults() map[string]*SRDResult
}

// --- config helper ---

func parseInt(s string) (int, error) { return common.ParseInt(s) }
