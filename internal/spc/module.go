
package spc

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/logger"
)

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

func (s PluginState) String() string {
	switch s {
	case PluginUnregistered:
		return "unregistered"
	case PluginRegistered:
		return "registered"
	case PluginInitialized:
		return "initialized"
	case PluginStarted:
		return "started"
	case PluginStopping:
		return "stopping"
	case PluginStopped:
		return "stopped"
	case PluginFailed:
		return "failed"
	default:
		return "unknown"
	}
}

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

type Container interface {
	ResolveNamed(name string) (interface{}, bool)
}

type ExtensionRegistry interface {
	RegisterPoint(point ExtensionPoint)
	Execute(ctx context.Context, name string, payload interface{})
}

type ExtensionPoint struct {
	Name        string
	Description string
	Version     string
}

type Message interface{}

type Bus interface {
	PublishSync(ctx context.Context, msg Message) []error
}

type KernelContext interface {
	Container() Container
	Bus() Bus
	Extensions() ExtensionRegistry
	Context() context.Context
	GetConfigObj() *config.Config
}

type Plugin interface {
	Info() PluginInfo
	Dependencies() []PluginDependency
	Init(ctx context.Context, kc KernelContext) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	State() PluginState
}

type PriorityPlugin interface {
	Plugin
	Priority() int
}

type HealthCheckable interface {
	HealthCheck(ctx context.Context) error
}

type SPCInterface interface {
	Calculate(hostID string, assetPackages []string) SPCCorrection
	AddCVE(score SPCCVEScore)
	AddCVEs(scores []SPCCVEScore)
	MergeCVEs(cves []SPCCVEScore) (added int, updated int)
	GetCVEs() []SPCCVEScore
	GetCVECount() int
	GetKEVCount() int
	ClearCache()
	UpsertAsset(asset LocalAsset)
	GetAsset(hostID string) *LocalAsset
	FetchFromAllSources() []SPCFetchResult
	FetchFromEPSS() SPCFetchResult
	FetchFromCISAKEV() SPCFetchResult
	ImportOSCAL(data []byte, format string) (int, error)
	ConfigureMISP(baseURL, apiKey string) error
	Enabled() bool
	SetEnabled(v bool)
	LastUpdate() time.Time
}

type SPCModule struct {
	kernel KernelContext

	mu            sync.RWMutex
	cveCache      []SPCCVEScore
	cveIndex      map[string]int
	assetCache    map[string]*LocalAsset
	lastNVDFetch  time.Time
	lastUpdate    time.Time
	fetchResults  []SPCFetchResult
	state         PluginState

	fetchInterval time.Duration
	mispConfig    SPCMISPConfig
	nvdConfig     SPCNVDConfig
	epssConfig    SPCEPSSConfig
	kevConfig     SPCKEVConfig
	cnnvdConfig   SPCCNNVDConfig
	cnvdConfig    SPCCNVDConfig
	oscalConfig   SPCOSCALConfig
	mispClient    *SPCMISPClient
	enabled       bool
	minPScore     float64
	maxCacheSize  int
	kevCatalog    map[string]bool
	nvdLimiter    chan struct{}
	nvdTimers     []*time.Timer
	done          chan struct{}
	cancelFunc    context.CancelFunc
}

func NewSPCModule() *SPCModule {
	return &SPCModule{
		cveCache:      make([]SPCCVEScore, 0),
		cveIndex:      make(map[string]int),
		assetCache:    make(map[string]*LocalAsset),
		kevCatalog:    make(map[string]bool),
		fetchInterval: 1 * time.Hour,
		minPScore:     0.60,
		maxCacheSize:  100000,
		enabled:       false,
		nvdLimiter:    make(chan struct{}, 1),
		done:          make(chan struct{}),
		mispConfig: SPCMISPConfig{
			SyncHours: 1,
			TLPFilter: "white",
			VerifyTLS: true,
		},
		nvdConfig: SPCNVDConfig{
			BaseURL:   DefaultNVDBaseURL,
			SyncHours: 6,
		},
		epssConfig: SPCEPSSConfig{
			Enabled:       true,
			DataURL:       DefaultEPSSDataURL,
			SyncIntervalH: 24,
		},
		kevConfig: SPCKEVConfig{
			Enabled:       true,
			CatalogURL:    DefaultKEVCatalogURL,
			SyncIntervalH: 24,
		},
		oscalConfig: SPCOSCALConfig{
			InputFormat: "json",
		},
	}
}

func (m *SPCModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "spc",
		Version:     "1.2.0",
		Description: "Security Posture Calculator – computes individualized risk posture from global CVE data, MISP, ATT&CK, and local asset inventory",
		Author:      "ASSCOR Core Team",
	}
}

func (m *SPCModule) Dependencies() []PluginDependency {
	return nil
}

func (m *SPCModule) Priority() int {
	return 20
}

func (m *SPCModule) Init(ctx context.Context, kc KernelContext) error {
	if kc == nil {
		return fmt.Errorf("kernel context must not be nil")
	}
	m.kernel = kc
	m.state = PluginInitialized

	cfg := kc.GetConfigObj()
	if cfg == nil {
		m.enabled = false
		m.minPScore = 0.60
		m.fetchInterval = 24 * time.Hour
		m.nvdConfig.BaseURL = DefaultNVDBaseURL
		m.nvdConfig.APIKey = os.Getenv("NVD_API_KEY")
		m.nvdConfig.SyncHours = 24
		m.epssConfig.Enabled = true
		m.epssConfig.DataURL = DefaultEPSSDataURL
		m.epssConfig.SyncIntervalH = 24
		m.kevConfig.Enabled = true
		m.kevConfig.CatalogURL = DefaultKEVCatalogURL
		m.kevConfig.SyncIntervalH = 24
		m.mispConfig.BaseURL = ""
		m.mispConfig.APIKey = os.Getenv("MISP_API_KEY")
		m.mispConfig.VerifyTLS = true
		m.mispConfig.SyncHours = 24
		m.mispConfig.TLPFilter = "white,green"
	} else {
		m.ConfigureFromConfig(cfg)
	}

	if m.enabled && m.nvdConfig.APIKey == "" {
		logger.WithComponent("spc").Warn("NVD API key not configured, SPC may be rate limited")
	}

	kc.Container().ResolveNamed("spc")
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "spc.pre_calculate",
		Description: "Called before SPC calculation",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "spc.post_calculate",
		Description: "Called after SPC calculation completes",
		Version:     "1.0",
	})
	kc.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "spc.cve_updated",
		Description: "Called when CVE cache is refreshed",
		Version:     "1.0",
	})

	return nil
}

func (m *SPCModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	if m.enabled {
		if m.mispConfig.BaseURL != "" && m.mispConfig.APIKey != "" {
			if err := m.ConfigureMISP(m.mispConfig.BaseURL, m.mispConfig.APIKey); err != nil {
				logger.WithComponent("spc").Warn("MISP configuration invalid, continuing without MISP", "error", err)
			}
		}
		m.loadCacheFromDisk()
		m.mu.RLock()
		cacheSize := len(m.cveCache)
		m.mu.RUnlock()
		if cacheSize == 0 {
			logger.WithComponent("spc").Info("CVE cache empty, will perform initial sync in background")
		}
		go m.fetchLoop()
	}
	logger.WithComponent("spc").Info("started", "enabled", m.enabled)
	return nil
}

func (m *SPCModule) Stop(ctx context.Context) error {
	m.state = PluginStopping

	m.mu.Lock()
	for _, t := range m.nvdTimers {
		t.Stop()
	}
	m.nvdTimers = nil
	m.mu.Unlock()

	if m.cancelFunc != nil {
		m.cancelFunc()
	}

	select {
	case <-m.done:
	case <-ctx.Done():
	}
	m.saveCacheToDisk()
	m.state = PluginStopped
	logger.WithComponent("spc").Info("stopped")
	return nil
}

func (m *SPCModule) State() PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *SPCModule) HealthCheck(ctx context.Context) error {
	if m.state != PluginStarted {
		return fmt.Errorf("spc not started (state=%s)", m.state)
	}
	return nil
}

func (m *SPCModule) Enabled() bool {
	return m.enabled
}

func (m *SPCModule) SetEnabled(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = v
}

func (m *SPCModule) ConfigureFromConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	spcCfg := cfg.SPC
	m.enabled = spcCfg.Enabled
	m.minPScore = spcCfg.MinPScore
	if m.minPScore == 0 {
		m.minPScore = 0.60
	}
	m.fetchInterval = time.Duration(spcCfg.FetchIntervalH) * time.Hour
	if m.fetchInterval == 0 {
		m.fetchInterval = 1 * time.Hour
	}

	m.nvdConfig.BaseURL = spcCfg.NVD.BaseURL
	if m.nvdConfig.BaseURL == "" {
		m.nvdConfig.BaseURL = DefaultNVDBaseURL
	}
	m.nvdConfig.APIKey = spcCfg.NVD.APIKey
	if m.nvdConfig.APIKey == "" {
		m.nvdConfig.APIKey = os.Getenv("NVD_API_KEY")
	}
	m.nvdConfig.SyncHours = spcCfg.NVD.SyncIntervalH
	if m.nvdConfig.SyncHours == 0 {
		m.nvdConfig.SyncHours = 6
	}
	m.nvdConfig.UseLastMod = spcCfg.NVD.UseLastMod
	m.nvdConfig.NoRejected = spcCfg.NVD.NoRejected

	m.epssConfig.Enabled = spcCfg.EPSS.Enabled
	m.epssConfig.DataURL = spcCfg.EPSS.DataURL
	if m.epssConfig.DataURL == "" {
		m.epssConfig.DataURL = DefaultEPSSDataURL
	}
	m.epssConfig.SyncIntervalH = spcCfg.EPSS.SyncIntervalH
	if m.epssConfig.SyncIntervalH == 0 {
		m.epssConfig.SyncIntervalH = 24
	}

	m.kevConfig.Enabled = spcCfg.CISAKEV.Enabled
	m.kevConfig.CatalogURL = spcCfg.CISAKEV.CatalogURL
	if m.kevConfig.CatalogURL == "" {
		m.kevConfig.CatalogURL = DefaultKEVCatalogURL
	}
	m.kevConfig.SyncIntervalH = spcCfg.CISAKEV.SyncIntervalH
	if m.kevConfig.SyncIntervalH == 0 {
		m.kevConfig.SyncIntervalH = 24
	}

	m.mispConfig.BaseURL = spcCfg.MISP.BaseURL
	m.mispConfig.APIKey = spcCfg.MISP.APIKey
	if m.mispConfig.APIKey == "" {
		m.mispConfig.APIKey = os.Getenv("MISP_API_KEY")
	}
	m.mispConfig.VerifyTLS = spcCfg.MISP.VerifyTLS
	m.mispConfig.SyncHours = spcCfg.MISP.SyncIntervalH
	if m.mispConfig.SyncHours == 0 {
		m.mispConfig.SyncHours = 1
	}
	m.mispConfig.TLPFilter = spcCfg.MISP.TLPFilter
	if m.mispConfig.TLPFilter == "" {
		m.mispConfig.TLPFilter = "white"
	}

	m.cnnvdConfig.Enabled = spcCfg.CNNVD.Enabled
	m.cnnvdConfig.BaseURL = spcCfg.CNNVD.BaseURL
	m.cnnvdConfig.APIKey = spcCfg.CNNVD.APIKey
	m.cnnvdConfig.SyncIntervalH = spcCfg.CNNVD.SyncIntervalH
	if m.cnnvdConfig.BaseURL == "" {
		m.cnnvdConfig.BaseURL = "https://www.cnnvd.org.cn/home/data"
	}
	if m.cnnvdConfig.APIKey == "" {
		m.cnnvdConfig.APIKey = os.Getenv("CNNVD_API_KEY")
	}

	m.cnvdConfig.Enabled = spcCfg.CNVD.Enabled
	m.cnvdConfig.BaseURL = spcCfg.CNVD.BaseURL
	m.cnvdConfig.SyncIntervalH = spcCfg.CNVD.SyncIntervalH
	if m.cnvdConfig.BaseURL == "" {
		m.cnvdConfig.BaseURL = "https://www.cnvd.org.cn/shareData"
	}

	if spcCfg.MaxCacheSize > 0 {
		m.maxCacheSize = spcCfg.MaxCacheSize
	}
}

func (m *SPCModule) fetchLoop() {
	defer close(m.done)

	fetchCtx, fetchCancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.cancelFunc = fetchCancel
	m.mu.Unlock()

	m.FetchFromAllSources()

	ticker := time.NewTicker(m.fetchInterval)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(24 * time.Hour)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-fetchCtx.Done():
			m.saveCacheToDisk()
			return
		case <-m.kernel.Context().Done():
			m.saveCacheToDisk()
			return
		case <-ticker.C:
			m.FetchFromAllSources()
		case <-cleanupTicker.C:
			m.cleanupOldCVEs()
		}
	}
}

func (m *SPCModule) cleanupOldCVEs() {
	cutoff := time.Now().AddDate(0, 0, -365)

	m.mu.RLock()
	cacheCopy := make([]SPCCVEScore, len(m.cveCache))
	copy(cacheCopy, m.cveCache)
	m.mu.RUnlock()

	kept := make([]SPCCVEScore, 0, len(cacheCopy))
	removedInBatch := 0
	for _, cve := range cacheCopy {
		if cve.DateModified.After(cutoff) || cve.InKEV {
			kept = append(kept, cve)
		} else {
			removedInBatch++
		}
	}

	if removedInBatch == 0 {
		return
	}

	m.mu.Lock()
	newIndex := make(map[string]int, len(kept))
	for i, cve := range kept {
		newIndex[cve.CVEID] = i
	}
	m.cveCache = kept
	m.cveIndex = newIndex
	m.mu.Unlock()

	logger.WithComponent("spc").Info("cleaned old CVE records", "removed", removedInBatch, "kept", len(kept))
}

func (m *SPCModule) UpsertAsset(asset LocalAsset) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assetCache[asset.HostID] = &asset
}

func (m *SPCModule) GetAsset(hostID string) *LocalAsset {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.assetCache[hostID]
}

