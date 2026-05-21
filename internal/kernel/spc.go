package kernel

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/argus-security/argus/internal/logger"
	"github.com/argus-security/argus/internal/model"
)

type MatchType int

const (
	MatchNone       MatchType = iota
	MatchCPEVendor            = 1
	MatchCPEProduct           = 2
	MatchVersionRange         = 3
	MatchExactVersion         = 4
)

func (m MatchType) Factor() float64 {
	switch m {
	case MatchExactVersion:
		return 1.0
	case MatchVersionRange:
		return 0.7
	case MatchCPEProduct:
		return 0.3
	default:
		return 0.0
	}
}

type ExposureLevel int

const (
	ExposureLocalhost ExposureLevel = iota
	ExposureInternal
	ExposureDMZ
	ExposurePublic
)

func (e ExposureLevel) Factor() float64 {
	switch e {
	case ExposurePublic:
		return 1.0
	case ExposureDMZ:
		return 0.7
	case ExposureInternal:
		return 0.4
	case ExposureLocalhost:
		return 0.1
	default:
		return 0.4
	}
}

func (e ExposureLevel) String() string {
	switch e {
	case ExposurePublic:
		return "public"
	case ExposureDMZ:
		return "dmz"
	case ExposureInternal:
		return "internal"
	case ExposureLocalhost:
		return "localhost"
	default:
		return "unknown"
	}
}

type ControlLevel int

const (
	ControlNone       ControlLevel = 0
	ControlPartial                 = 1
	ControlEffective               = 2
)

func (c ControlLevel) Factor() float64 {
	switch c {
	case ControlNone:
		return 1.0
	case ControlPartial:
		return 0.5
	case ControlEffective:
		return 0.2
	default:
		return 1.0
	}
}

type SPCAction int

const (
	ActionNone     SPCAction = iota
	ActionWarn
	ActionPatch
	ActionPriority
	ActionIsolate
)

func (a SPCAction) String() string {
	switch a {
	case ActionNone:
		return "none"
	case ActionWarn:
		return "notify_admin"
	case ActionPatch:
		return "patch_recommended"
	case ActionPriority:
		return "priority_fix"
	case ActionIsolate:
		return "isolate_host"
	default:
		return "none"
	}
}

func classifyAction(pscore float64) SPCAction {
	switch {
	case pscore >= 0.95:
		return ActionNone
	case pscore >= 0.85:
		return ActionWarn
	case pscore >= 0.75:
		return ActionPatch
	case pscore >= 0.65:
		return ActionPriority
	default:
		return ActionIsolate
	}
}

type SPCCVEScore struct {
	CVEID        string    `json:"cve_id"`
	Description  string    `json:"description"`
	CVSS         float64   `json:"cvss_score"`
	CVSSVector   string    `json:"cvss_vector"`
	EPSS         float64   `json:"epss_score"`
	EPSSPercent  float64   `json:"epss_percentile"`
	InKEV        bool      `json:"in_kev"`
	HasPublicPoC bool      `json:"has_public_poc"`
	DatePublished time.Time `json:"date_published"`
	DateModified time.Time  `json:"date_modified"`
	AffectedCPEs []string  `json:"affected_cpes"`
	AttckTechniques []string `json:"attck_techniques"`
	MISPGalaxyTags  []string `json:"misp_galaxy_tags"`
	OSCALFindingUUID string  `json:"oscal_finding_uuid,omitempty"`
	APTGroupAssoc    []string `json:"apt_group_assoc,omitempty"`
	Matched       bool      `json:"matched"`
	MatchType     MatchType `json:"match_type"`
	Exposure      ExposureLevel `json:"exposure"`
	ControlLevel  ControlLevel `json:"control_level"`
}

type SPCVulnerabilityRecord struct {
	CVEID        string   `json:"cve_id"`
	Description  string   `json:"description"`
	CVSSScore    float64  `json:"cvss_score"`
	CVSSVector   string   `json:"cvss_vector"`
	EPSSScore    float64  `json:"epss_score"`
	EPSSPercent  float64  `json:"epss_percentile"`
	InKEV        bool     `json:"in_kev"`
	DatePublished string  `json:"date_published"`
	DateModified  string  `json:"date_modified"`
	AffectedCPEs []string `json:"affected_cpes"`
	AttckTechniques []string `json:"attck_techniques"`
	MISPGalaxyTags  []string `json:"misp_galaxy_tags"`
	OSCALFindingUUID string `json:"oscal_finding_uuid,omitempty"`
	APTGroupAssoc   []string `json:"apt_group_assoc,omitempty"`
}

type SPCCorrection struct {
	Score           float64            `json:"p_score"`
	Weights         map[string]float64 `json:"p_weight"`
	Action          string             `json:"p_action"`
	AffectedCVE     []string           `json:"affected_cve"`
	TopCVEImpact    string             `json:"top_cve_impact"`
	TotalPenalty    float64            `json:"total_penalty"`
	PenaltyBreakdown []CVEPenalty      `json:"penalty_breakdown,omitempty"`
	KillChainScore  float64            `json:"kill_chain_score,omitempty"`
}

type CVEPenalty struct {
	CVEID        string  `json:"cve_id"`
	Impact       float64 `json:"impact"`
	CVSSFactor   float64 `json:"cvss_factor"`
	EPSSFactor   float64 `json:"epss_factor"`
	KEVFactor    float64 `json:"kev_factor"`
	LocalFactor  float64 `json:"local_factor"`
	TimeFactor   float64 `json:"time_factor"`
	Penalty      float64 `json:"penalty"`
}

type LocalAsset struct {
	HostID        string   `json:"host_id"`
	Hostname      string   `json:"hostname"`
	Role          string   `json:"role"`
	Packages      []string `json:"packages"`
	InstalledCPEs []string `json:"installed_cpes"`
	Services      []string `json:"services"`
	Ports         []int    `json:"ports"`
	NetworkZone   string   `json:"network_zone"`
	Compensations struct {
		WAFRules      bool `json:"waf_rules"`
		IPSRules      bool `json:"ips_rules"`
		AppWhitelist  bool `json:"app_whitelist"`
		VirtualPatch  bool `json:"virtual_patch"`
	} `json:"compensations"`
}

type SPCFetchResult struct {
	Source       string    `json:"source"`
	CVEAdded     int       `json:"cve_added"`
	CVEUpdated   int       `json:"cve_updated"`
	Duration     time.Duration `json:"duration_ms"`
	Error        string    `json:"error,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

type SPCMISPConfig struct {
	BaseURL    string `json:"base_url"`
	APIKey     string `json:"api_key"`
	VerifyTLS  bool   `json:"verify_tls"`
	SyncHours  int    `json:"sync_interval_h"`
	TLPFilter  string `json:"tlp_filter"`
}

type SPCMISPClient struct {
	config   SPCMISPConfig
	client   *http.Client
	lastSync time.Time
}

type SPCNVDConfig struct {
	BaseURL    string `json:"base_url"`
	APIKey     string `json:"api_key"`
	SyncHours  int    `json:"sync_interval_h"`
}

type SPCOscalConfig struct {
	Enabled      bool   `json:"enabled"`
	InputFormat  string `json:"input_format"`
	ResultsPath  string `json:"results_path"`
	PlanPath     string `json:"plan_path"`
}

type SPCEPSSConfig struct {
	Enabled       bool   `json:"enabled"`
	DataURL       string `json:"data_url"`
	SyncIntervalH int    `json:"sync_interval_h"`
}

type SPCKEVConfig struct {
	Enabled       bool   `json:"enabled"`
	CatalogURL    string `json:"catalog_url"`
	SyncIntervalH int    `json:"sync_interval_h"`
}

type SPCModule struct {
	kernel *Kernel

	mu          sync.RWMutex
	cveCache    []SPCCVEScore
	cveIndex    map[string]int
	assetCache  map[string]*LocalAsset
	lastFetch   time.Time
	lastUpdate  time.Time
	fetchResults []SPCFetchResult
	state       PluginState

	fetchInterval  time.Duration
	mispConfig     SPCMISPConfig
	nvdConfig      SPCNVDConfig
	epssConfig     SPCEPSSConfig
	kevConfig      SPCKEVConfig
	oscalConfig    SPCOscalConfig
	mispClient     *SPCMISPClient
	enabled        bool
	minPScore      float64
	maxCacheSize   int
	kevCatalog     map[string]bool
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
		mispConfig: SPCMISPConfig{
			SyncHours: 1,
			TLPFilter: "white",
			VerifyTLS: true,
		},
		nvdConfig: SPCNVDConfig{
			BaseURL:   "https://services.nvd.nist.gov/rest/json/cves/2.0",
			SyncHours: 6,
		},
		epssConfig: SPCEPSSConfig{
			Enabled:       true,
			DataURL:       "https://epss.cyentia.com/epss_scores-current.csv.gz",
			SyncIntervalH: 24,
		},
		kevConfig: SPCKEVConfig{
			Enabled:       true,
			CatalogURL:    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			SyncIntervalH: 24,
		},
		oscalConfig: SPCOscalConfig{
			InputFormat: "json",
		},
	}
}

func (m *SPCModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "spc",
		Version:     "1.2.0",
		Description: "Security Posture Calculator — computes individualized risk posture from global CVE data, MISP, ATT&CK, and local asset inventory",
		Author:      "ARGUS Core Team",
	}
}

func (m *SPCModule) Dependencies() []PluginDependency {
	return nil
}

func (m *SPCModule) Priority() int {
	return 20
}

func (m *SPCModule) Init(ctx context.Context, k *Kernel) error {
	if k == nil {
		return fmt.Errorf("kernel instance must not be nil")
	}
	m.kernel = k
	m.state = PluginInitialized

	if k.cfg == nil {
		m.enabled = false
		m.minPScore = 0.60
		m.fetchInterval = 24 * time.Hour
		m.nvdConfig.BaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
		m.nvdConfig.APIKey = os.Getenv("NVD_API_KEY")
		m.nvdConfig.SyncHours = 24
		m.epssConfig.Enabled = true
		m.epssConfig.DataURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
		m.epssConfig.SyncIntervalH = 24
		m.kevConfig.Enabled = true
		m.kevConfig.CatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
		m.kevConfig.SyncIntervalH = 24
		m.mispConfig.BaseURL = ""
		m.mispConfig.APIKey = os.Getenv("MISP_API_KEY")
		m.mispConfig.VerifyTLS = true
		m.mispConfig.SyncHours = 24
		m.mispConfig.TLPFilter = "white,green"
	} else {
		spcCfg := k.cfg.SPC
		m.enabled = spcCfg.Enabled
		m.minPScore = spcCfg.MinPScore
		m.fetchInterval = time.Duration(spcCfg.FetchIntervalH) * time.Hour

		m.nvdConfig.BaseURL = spcCfg.NVD.BaseURL
		m.nvdConfig.APIKey = spcCfg.NVD.APIKey
		m.nvdConfig.SyncHours = spcCfg.NVD.SyncIntervalH

		if m.nvdConfig.APIKey == "" {
			m.nvdConfig.APIKey = os.Getenv("NVD_API_KEY")
		}

		m.epssConfig.Enabled = spcCfg.EPSS.Enabled
		m.epssConfig.DataURL = spcCfg.EPSS.DataURL
		m.epssConfig.SyncIntervalH = spcCfg.EPSS.SyncIntervalH
		if m.epssConfig.DataURL == "" {
			m.epssConfig.DataURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
		}

		m.kevConfig.Enabled = spcCfg.CISAKEV.Enabled
		m.kevConfig.CatalogURL = spcCfg.CISAKEV.CatalogURL
		m.kevConfig.SyncIntervalH = spcCfg.CISAKEV.SyncIntervalH
		if m.kevConfig.CatalogURL == "" {
			m.kevConfig.CatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
		}

		m.mispConfig.BaseURL = spcCfg.MISP.BaseURL
		m.mispConfig.APIKey = spcCfg.MISP.APIKey
		m.mispConfig.VerifyTLS = spcCfg.MISP.VerifyTLS
		m.mispConfig.SyncHours = spcCfg.MISP.SyncIntervalH
		m.mispConfig.TLPFilter = spcCfg.MISP.TLPFilter

		if m.mispConfig.APIKey == "" {
			m.mispConfig.APIKey = os.Getenv("MISP_API_KEY")
		}
	}

	if m.enabled && m.nvdConfig.APIKey == "" {
		logger.With("component", "spc").Warn("NVD API key not configured, SPC may be rate limited")
	}

	k.Container().Bind((*SPCInterface)(nil), m)

	k.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "spc.pre_calculate",
		Description: "Called before SPC calculation",
		Version:     "1.0",
	})
	k.Extensions().RegisterPoint(ExtensionPoint{
		Name:        "spc.post_calculate",
		Description: "Called after SPC calculation completes",
		Version:     "1.0",
	})
	k.Extensions().RegisterPoint(ExtensionPoint{
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
				logger.With("component", "spc").Warn("MISP configuration invalid, continuing without MISP", "error", err)
			}
		}
		go m.fetchLoop()
	}
	logger.With("component", "spc").Info("started", "enabled", m.enabled)
	return nil
}

func (m *SPCModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.state = PluginStopped
	logger.With("component", "spc").Info("stopped")
	return nil
}

func (m *SPCModule) State() PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *SPCModule) Enabled() bool {
	return m.enabled
}

func (m *SPCModule) SetEnabled(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = v
}

func (m *SPCModule) fetchLoop() {
	ticker := time.NewTicker(m.fetchInterval)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(24 * time.Hour)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-m.kernel.Context().Done():
			return
		case <-ticker.C:
			m.FetchFromAllSources()
		case <-cleanupTicker.C:
			m.cleanupOldCVEs()
		}
	}
}

func (m *SPCModule) cleanupOldCVEs() {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().AddDate(0, 0, -365)
	before := len(m.cveCache)
	kept := make([]SPCCVEScore, 0, before)
	for _, cve := range m.cveCache {
		if cve.DateModified.After(cutoff) || cve.InKEV {
			kept = append(kept, cve)
		}
	}
	m.cveCache = kept
	m.cveIndex = make(map[string]int, len(kept))
	for i, cve := range kept {
		m.cveIndex[cve.CVEID] = i
	}
	removed := before - len(m.cveCache)
	if removed > 0 {
		logger.With("component", "spc").Info("cleaned old CVE records", "removed", removed, "kept", len(m.cveCache))
	}
}

func (m *SPCModule) FetchFromAllSources() []SPCFetchResult {
	results := make([]SPCFetchResult, 0)

	result := m.FetchFromNVD()
	results = append(results, result)

	if m.epssConfig.Enabled {
		resultEPSS := m.FetchFromEPSS()
		results = append(results, resultEPSS)
	}

	if m.kevConfig.Enabled {
		resultKEV := m.FetchFromCISAKEV()
		results = append(results, resultKEV)
	}

	result2 := m.FetchFromMISP()
	results = append(results, result2)

	m.mu.Lock()
	m.lastUpdate = time.Now()
	m.fetchResults = append(m.fetchResults, results...)
	if len(m.fetchResults) > 100 {
		m.fetchResults = m.fetchResults[len(m.fetchResults)-100:]
	}
	m.mu.Unlock()

	m.kernel.Extensions().Execute(m.kernel.Context(), "spc.cve_updated", results)

	if persister, ok := m.kernel.Container().ResolveNamed("persistence"); ok {
		if pi, ok2 := persister.(PersistenceInterface); ok2 {
			topCVEs := make([]string, 0, 10)
			m.mu.RLock()
			sorted := make([]SPCCVEScore, len(m.cveCache))
			copy(sorted, m.cveCache)
			sort.Slice(sorted, func(i, j int) bool {
				return sorted[i].CVSS > sorted[j].CVSS
			})
			for i := 0; i < len(sorted) && i < 10; i++ {
				topCVEs = append(topCVEs, sorted[i].CVEID)
			}
			kevCount := 0
			highCount := 0
			for _, cve := range m.cveCache {
				if cve.InKEV {
					kevCount++
				}
				if cve.CVSS >= 7.0 {
					highCount++
				}
			}
			m.mu.RUnlock()

			pi.WriteCVECache(CVECacheRecord{
				Timestamp:  time.Now(),
				TotalCount: len(m.cveCache),
				HighCount:  highCount,
				KEVCount:   kevCount,
				TopCVEs:    topCVEs,
				Sources: map[string]interface{}{
					"nvd":  result,
					"misp": result2,
				},
			})
		}
	}

	return results
}

func (m *SPCModule) FetchFromNVD() SPCFetchResult {
	start := time.Now()
	result := SPCFetchResult{
		Source:    "nvd",
		Timestamp: time.Now(),
	}

	m.mu.Lock()
	m.lastFetch = time.Now()
	baseURL := m.nvdConfig.BaseURL
	apiKey := m.nvdConfig.APIKey
	m.mu.Unlock()

	if baseURL == "" {
		baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}

	since := m.lastUpdate
	if since.IsZero() {
		since = time.Now().AddDate(0, 0, -7)
	}

	cves, err := m.fetchNVDAPI(baseURL, apiKey, since)
	if err != nil {
		result.Error = err.Error()
		logger.With("component", "spc").Warn("NVD API fetch failed, falling back to sample data", "error", err)
		cves = m.generateSampleCVEs()
	}

	m.mu.Lock()
	for _, cve := range cves {
		if _, exists := m.cveIndex[cve.CVEID]; !exists {
			if len(m.cveCache) >= m.maxCacheSize {
				logger.With("component", "spc").Warn("CVE cache reached max size", "max", m.maxCacheSize)
				break
			}
			m.cveIndex[cve.CVEID] = len(m.cveCache)
			m.cveCache = append(m.cveCache, cve)
			result.CVEAdded++
		}
	}
	m.mu.Unlock()

	result.Duration = time.Since(start)
	logger.With("component", "spc").Info("NVD fetch completed", "duration", result.Duration, "added", result.CVEAdded)
	return result
}

type nvdAPIResponse struct {
	TotalResults int              `json:"totalResults"`
	ResultsPerPage int            `json:"resultsPerPage"`
	StartIndex int                `json:"startIndex"`
	Vulnerabilities []nvdVulnItem `json:"vulnerabilities"`
}

type nvdVulnItem struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID             string          `json:"id"`
	SourceIdentifier string        `json:"sourceIdentifier"`
	Published      string          `json:"published"`
	LastModified   string          `json:"lastModified"`
	Descriptions   []nvdLangStr   `json:"descriptions"`
	Metrics        nvdMetrics      `json:"metrics"`
	Weaknesses     []nvdWeakness   `json:"weaknesses"`
	Configurations []nvdConfig     `json:"configurations"`
	References     []nvdReference  `json:"references"`
}

type nvdLangStr struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetricV2 `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	Source   string     `json:"source"`
	Type     string     `json:"type"`
	CVSSData nvdCVSSData `json:"cvssData"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

type nvdCVSSData struct {
	Version                       string  `json:"version"`
	VectorString                  string  `json:"vectorString"`
	BaseScore                     float64 `json:"baseScore"`
	BaseSeverity                  string  `json:"baseSeverity"`
}

type nvdCVSSMetricV2 struct {
	Source       string       `json:"source"`
	Type         string       `json:"type"`
	CVSSData     nvdCVSSDataV2 `json:"cvssData"`
	BaseSeverity string       `json:"baseSeverity"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

type nvdCVSSDataV2 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
}

type nvdWeakness struct {
	Source          string        `json:"source"`
	Type            string        `json:"type"`
	Description     []nvdLangStr  `json:"description"`
}

type nvdConfig struct {
	Operator string      `json:"operator"`
	Nodes    []nvdNode   `json:"nodes"`
}

type nvdNode struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdReference struct {
	Source string `json:"source"`
	URL    string `json:"url"`
	Tags   []string `json:"tags"`
}

func (m *SPCModule) fetchNVDAPI(baseURL, apiKey string, since time.Time) ([]SPCCVEScore, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	var allCVEs []SPCCVEScore
	startIdx := 0
	pageSize := 100
	maxRetries := 5
	retryCount := 0

	for {
		dateStr := since.UTC().Format("2006-01-02T15:04:05") + ".000Z"
		reqURL := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d&pubStartDate=%s",
			baseURL, pageSize, startIdx, dateStr)

		req, err := http.NewRequest("GET", reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("NVD request creation: %w", err)
		}

		req.Header.Set("Accept", "application/json")
		if apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}

		resp, err := client.Do(req)
		if err != nil {
			return allCVEs, fmt.Errorf("NVD API call: %w", err)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			retryCount++
			if retryCount > maxRetries {
				logger.With("component", "spc").Error("NVD rate limit exceeded max retries",
					"max_retries", maxRetries,
					"cves_fetched", len(allCVEs))
				return allCVEs, fmt.Errorf("NVD rate limit: exceeded %d retries", maxRetries)
			}
			waitTime := 30 * time.Second
			if apiKey != "" {
				waitTime = 6 * time.Second
			}
			logger.With("component", "spc").Warn("NVD rate limited, waiting before retry",
				"retry", retryCount,
				"max_retries", maxRetries,
				"wait", waitTime)
			time.Sleep(waitTime)
			continue
		}

		retryCount = 0

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return allCVEs, fmt.Errorf("NVD API returned HTTP %d", resp.StatusCode)
		}

		var apiResp nvdAPIResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			resp.Body.Close()
			return allCVEs, fmt.Errorf("NVD response decode: %w", err)
		}
		resp.Body.Close()

		for _, vuln := range apiResp.Vulnerabilities {
			cve := m.parseNVDCVE(vuln.CVE)
			allCVEs = append(allCVEs, cve)
		}

		if apiResp.StartIndex+apiResp.ResultsPerPage >= apiResp.TotalResults {
			break
		}
		startIdx += apiResp.ResultsPerPage

		if apiKey == "" {
			time.Sleep(6 * time.Second)
		} else {
			time.Sleep(300 * time.Millisecond)
		}
	}

	logger.With("component", "spc").Info("NVD API fetched CVEs", "count", len(allCVEs), "since", since.Format("2006-01-02"))
	return allCVEs, nil
}

func (m *SPCModule) parseNVDCVE(cve nvdCVE) SPCCVEScore {
	desc := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	if desc == "" && len(cve.Descriptions) > 0 {
		desc = cve.Descriptions[0].Value
	}

	var cvssScore float64
	var cvssVector string
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		cvssScore = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
		cvssVector = cve.Metrics.CVSSMetricV31[0].CVSSData.VectorString
	} else if len(cve.Metrics.CVSSMetricV30) > 0 {
		cvssScore = cve.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
		cvssVector = cve.Metrics.CVSSMetricV30[0].CVSSData.VectorString
	} else if len(cve.Metrics.CVSSMetricV2) > 0 {
		cvssScore = cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
		cvssVector = cve.Metrics.CVSSMetricV2[0].CVSSData.VectorString
	}

	var affectedCPEs []string
	for _, cfg := range cve.Configurations {
		for _, node := range cfg.Nodes {
			for _, match := range node.CPEMatch {
				if match.Vulnerable && match.Criteria != "" {
					affectedCPEs = append(affectedCPEs, match.Criteria)
				}
			}
		}
	}

	pubDate, _ := time.Parse("2006-01-02T15:04:05.000", cve.Published)
	modDate, _ := time.Parse("2006-01-02T15:04:05.000", cve.LastModified)
	if pubDate.IsZero() {
		pubDate, _ = time.Parse(time.RFC3339, cve.Published)
	}
	if modDate.IsZero() {
		modDate, _ = time.Parse(time.RFC3339, cve.LastModified)
	}

	var attckTechs []string
	for _, ref := range cve.References {
		for _, tag := range ref.Tags {
			if strings.HasPrefix(tag, "ATT&CK:") {
				tech := strings.TrimPrefix(tag, "ATT&CK:")
				attckTechs = append(attckTechs, tech)
			} else if strings.HasPrefix(tag, "MITRE ATT&CK:") {
				tech := strings.TrimPrefix(tag, "MITRE ATT&CK:")
				attckTechs = append(attckTechs, tech)
			}
		}
	}

	return SPCCVEScore{
		CVEID:          cve.ID,
		Description:    desc,
		CVSS:           cvssScore,
		CVSSVector:     cvssVector,
		AffectedCPEs:   affectedCPEs,
		AttckTechniques: attckTechs,
		DatePublished:  pubDate,
		DateModified:   modDate,
	}
}

func (m *SPCModule) FetchFromEPSS() SPCFetchResult {
	start := time.Now()
	result := SPCFetchResult{
		Source:    "epss",
		Timestamp: start,
	}

	if !m.epssConfig.Enabled {
		result.Error = "EPSS data source disabled"
		return result
	}

	dataURL := m.epssConfig.DataURL
	if dataURL == "" {
		dataURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(dataURL)
	if err != nil {
		result.Error = fmt.Sprintf("EPSS fetch failed: %v", err)
		result.Duration = time.Since(start)
		logger.With("component", "spc").Error("EPSS fetch failed", "error", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("EPSS returned HTTP %d", resp.StatusCode)
		result.Duration = time.Since(start)
		return result
	}

	var reader io.Reader = resp.Body
	if strings.HasSuffix(dataURL, ".gz") {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			result.Error = fmt.Sprintf("EPSS gzip decompress failed: %v", err)
			result.Duration = time.Since(start)
			return result
		}
		defer gzReader.Close()
		reader = gzReader
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	parsed := 0
	updated := 0
	created := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "model") || strings.HasPrefix(line, "cve") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			continue
		}

		cveID := strings.TrimSpace(fields[0])
		epssStr := strings.TrimSpace(fields[1])
		percentileStr := strings.TrimSpace(fields[2])

		if !strings.HasPrefix(strings.ToUpper(cveID), "CVE-") {
			continue
		}

		epssVal, _ := strconv.ParseFloat(epssStr, 64)
		percentileVal, _ := strconv.ParseFloat(percentileStr, 64)
		parsed++

		m.mu.Lock()
		if idx, exists := m.cveIndex[cveID]; exists && idx < len(m.cveCache) {
			m.cveCache[idx].EPSS = epssVal
			m.cveCache[idx].EPSSPercent = percentileVal
			updated++
		} else if len(m.cveCache) < m.maxCacheSize {
			m.cveIndex[cveID] = len(m.cveCache)
			m.cveCache = append(m.cveCache, SPCCVEScore{
				CVEID:       cveID,
				EPSS:        epssVal,
				EPSSPercent: percentileVal,
			})
			created++
		}
		m.mu.Unlock()
	}

	if err := scanner.Err(); err != nil {
		result.Error = fmt.Sprintf("EPSS parse error: %v", err)
	}

	result.CVEAdded = created
	result.CVEUpdated = updated
	result.Duration = time.Since(start)

	logger.With("component", "spc").Info("EPSS data fetched",
		"parsed", parsed,
		"created", created,
		"updated", updated,
		"duration_ms", result.Duration.Milliseconds())

	return result
}

func (m *SPCModule) FetchFromCISAKEV() SPCFetchResult {
	start := time.Now()
	result := SPCFetchResult{
		Source:    "cisa_kev",
		Timestamp: start,
	}

	if !m.kevConfig.Enabled {
		result.Error = "CISA KEV data source disabled"
		return result
	}

	catalogURL := m.kevConfig.CatalogURL
	if catalogURL == "" {
		catalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(catalogURL)
	if err != nil {
		result.Error = fmt.Sprintf("CISA KEV fetch failed: %v", err)
		result.Duration = time.Since(start)
		logger.With("component", "spc").Error("CISA KEV fetch failed", "error", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("CISA KEV returned HTTP %d", resp.StatusCode)
		result.Duration = time.Since(start)
		return result
	}

	var kevCatalog struct {
		Title           string `json:"title"`
		CatalogVersion  string `json:"catalogVersion"`
		DateReleased    string `json:"dateReleased"`
		Count           int    `json:"count"`
		Vulnerabilities []struct {
			CVEID                       string `json:"cveID"`
			VendorProject               string `json:"vendorProject"`
			Product                     string `json:"product"`
			VulnerabilityName           string `json:"vulnerabilityName"`
			DateAdded                   string `json:"dateAdded"`
			ShortDescription            string `json:"shortDescription"`
			RequiredAction              string `json:"requiredAction"`
			DueDate                     string `json:"dueDate"`
			KnownRansomwareCampaignUse  string `json:"knownRansomwareCampaignUse"`
			Notes                       string `json:"notes"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&kevCatalog); err != nil {
		result.Error = fmt.Sprintf("CISA KEV decode failed: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	newKEV := make(map[string]bool)
	kevUpdated := 0
	kevCreated := 0
	for _, vuln := range kevCatalog.Vulnerabilities {
		cveID := strings.TrimSpace(vuln.CVEID)
		if cveID == "" {
			continue
		}
		newKEV[cveID] = true

		m.mu.Lock()
		if idx, exists := m.cveIndex[cveID]; exists && idx < len(m.cveCache) {
			m.cveCache[idx].InKEV = true
			if strings.EqualFold(vuln.KnownRansomwareCampaignUse, "known") {
				m.cveCache[idx].APTGroupAssoc = appendUnique(m.cveCache[idx].APTGroupAssoc, "ransomware")
			}
			kevUpdated++
		} else if len(m.cveCache) < m.maxCacheSize {
			m.cveIndex[cveID] = len(m.cveCache)
			aptAssoc := []string{}
			if strings.EqualFold(vuln.KnownRansomwareCampaignUse, "known") {
				aptAssoc = []string{"ransomware"}
			}
			m.cveCache = append(m.cveCache, SPCCVEScore{
				CVEID:        cveID,
				InKEV:        true,
				APTGroupAssoc: aptAssoc,
			})
			kevCreated++
		}
		m.mu.Unlock()
	}

	m.mu.Lock()
	m.kevCatalog = newKEV
	m.mu.Unlock()

	result.CVEAdded = kevCreated
	result.CVEUpdated = kevUpdated
	result.Duration = time.Since(start)

	logger.With("component", "spc").Info("CISA KEV catalog fetched",
		"total_kev", len(newKEV),
		"created", kevCreated,
		"updated", kevUpdated,
		"catalog_version", kevCatalog.CatalogVersion,
		"duration_ms", result.Duration.Milliseconds())

	return result
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

func (m *SPCModule) isInKEVCatalog(cveID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.kevCatalog[cveID]
}

func (m *SPCModule) FetchFromMISP() SPCFetchResult {
	start := time.Now()
	result := SPCFetchResult{
		Source:    "misp",
		Timestamp: time.Now(),
	}

	m.mu.RLock()
	client := m.mispClient
	m.mu.RUnlock()

	if client == nil || client.config.BaseURL == "" {
		result.Duration = time.Since(start)
		return result
	}

	cves := m.fetchMISPEvents(client)

	m.mu.Lock()
	for _, cve := range cves {
		if _, exists := m.cveIndex[cve.CVEID]; !exists {
			if len(m.cveCache) >= m.maxCacheSize {
				break
			}
			m.cveIndex[cve.CVEID] = len(m.cveCache)
			m.cveCache = append(m.cveCache, cve)
			result.CVEAdded++
		}
	}
	m.mu.Unlock()

	m.mu.Lock()
	if client != nil {
		client.lastSync = time.Now()
	}
	m.mu.Unlock()

	result.Duration = time.Since(start)
	logger.With("component", "spc").Info("MISP fetch completed", "duration", result.Duration, "added", result.CVEAdded)
	return result
}

type mispEventSearchRequest struct {
	ReturnFormat  string   `json:"returnFormat"`
	Type         []string `json:"type"`
	Category     []string `json:"category"`
	Tags         []string `json:"tags,omitempty"`
	DateFrom     string   `json:"date,omitempty"`
	Published    bool     `json:"published"`
	EnforceWarninglist bool `json:"enforceWarninglist"`
	Limit        int      `json:"limit"`
	Page         int      `json:"page"`
}

type mispEventResponse struct {
	Response []mispEventItem `json:"response"`
}

type mispEventItem struct {
	Event mispEvent `json:"Event"`
}

type mispEvent struct {
	ID          string          `json:"id"`
	Info        string          `json:"info"`
	ThreatLevel string          `json:"threat_level_id"`
	Published   bool            `json:"published"`
	Date        string          `json:"date"`
	Tags        []mispTag       `json:"Tag"`
	Galaxy      []mispGalaxy    `json:"Galaxy"`
	Attribute   []mispAttribute `json:"Attribute"`
}

type mispTag struct {
	Name  string `json:"name"`
	Color string `json:"colour"`
}

type mispGalaxy struct {
	Name     string           `json:"name"`
	Type     string           `json:"type"`
	Cluster  []mispGalaxyCluster `json:"GalaxyCluster"`
}

type mispGalaxyCluster struct {
	Value   string   `json:"value"`
	TagName string   `json:"tag_name"`
	Meta    struct {
		Synonyms []string `json:"synonyms"`
	} `json:"meta"`
}

type mispAttribute struct {
	Type       string `json:"type"`
	Category   string `json:"category"`
	Value      string `json:"value"`
	ToIDS      bool   `json:"to_ids"`
	Comment    string `json:"comment"`
}

func (m *SPCModule) fetchMISPEvents(client *SPCMISPClient) []SPCCVEScore {
	searchReq := mispEventSearchRequest{
		ReturnFormat: "json",
		Type:        []string{"vulnerability"},
		Category:    []string{"External analysis"},
		Published:   true,
		EnforceWarninglist: true,
		Limit:       100,
		Page:        1,
	}

	if client.config.TLPFilter != "" {
		tlps := strings.Split(client.config.TLPFilter, ",")
		for _, tlp := range tlps {
			searchReq.Tags = append(searchReq.Tags, "tlp:"+strings.TrimSpace(tlp))
		}
	}

	since := m.lastUpdate
	if since.IsZero() {
		since = time.Now().AddDate(0, 0, -7)
	}
	searchReq.DateFrom = since.Format("2006-01-02")

	body, err := json.Marshal(searchReq)
	if err != nil {
		logger.With("component", "spc").Error("MISP request marshal failed", "error", err)
		return nil
	}

	req, err := http.NewRequest("POST", client.config.BaseURL+"/events/restSearch",
		strings.NewReader(string(body)))
	if err != nil {
		logger.With("component", "spc").Error("MISP request creation failed", "error", err)
		return nil
	}

	req.Header.Set("Authorization", client.config.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	if !client.config.VerifyTLS {
		client.client.Transport = &http.Transport{
			TLSClientConfig: nil,
		}
	}

	resp, err := client.client.Do(req)
	if err != nil {
		logger.With("component", "spc").Error("MISP API call failed", "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.With("component", "spc").Error("MISP API returned error status", "status", resp.StatusCode)
		return nil
	}

	var eventResp mispEventResponse
	if err := json.NewDecoder(resp.Body).Decode(&eventResp); err != nil {
		logger.With("component", "spc").Error("MISP response decode failed", "error", err)
		return nil
	}

	var cves []SPCCVEScore
	for _, item := range eventResp.Response {
		parsed := m.parseMISPEvent(item.Event)
		cves = append(cves, parsed...)
	}

	logger.With("component", "spc").Info("MISP fetched events", "events", len(eventResp.Response), "cves", len(cves))
	return cves
}

func (m *SPCModule) parseMISPEvent(event mispEvent) []SPCCVEScore {
	var cveIDs []string
	var descriptions []string

	for _, attr := range event.Attribute {
		if attr.Type == "vulnerability" {
			if strings.HasPrefix(strings.ToUpper(attr.Value), "CVE-") {
				cveIDs = append(cveIDs, attr.Value)
			}
		}
		if attr.Category == "External analysis" && attr.Comment != "" {
			descriptions = append(descriptions, attr.Comment)
		}
	}

	var galaxyTags []string
	var attckTechs []string
	var aptGroups []string

	for _, g := range event.Galaxy {
		for _, cluster := range g.Cluster {
			galaxyTags = append(galaxyTags, cluster.TagName)
			if strings.HasPrefix(g.Type, "mitre-attack-pattern") {
				tech := extractATTCKTechnique(cluster.TagName)
				if tech != "" {
					attckTechs = append(attckTechs, tech)
				}
			}
			if strings.HasPrefix(g.Type, "threat-actor") || strings.HasPrefix(g.Type, "microsoft-activity-group") {
				aptGroups = append(aptGroups, cluster.Value)
			}
		}
	}

	for _, tag := range event.Tags {
		if strings.HasPrefix(tag.Name, "misp-galaxy:mitre-attack-pattern") {
			tech := extractATTCKTechnique(tag.Name)
			if tech != "" {
				attckTechs = append(attckTechs, tech)
			}
		}
		if strings.HasPrefix(tag.Name, "misp-galaxy:threat-actor") {
			parts := strings.Split(tag.Name, "=\"")
			if len(parts) >= 2 {
				name := strings.TrimSuffix(parts[1], "\"")
				aptGroups = append(aptGroups, name)
			}
		}
	}

	desc := event.Info
	if len(descriptions) > 0 {
		desc = descriptions[0]
	}

	pubDate, _ := time.Parse("2006-01-02", event.Date)

	var results []SPCCVEScore
	for _, cveID := range cveIDs {
		results = append(results, SPCCVEScore{
			CVEID:          cveID,
			Description:    desc,
			DatePublished:  pubDate,
			DateModified:   time.Now(),
			AttckTechniques: attckTechs,
			MISPGalaxyTags:  galaxyTags,
			APTGroupAssoc:   aptGroups,
		})
	}

	return results
}

func extractATTCKTechnique(tagName string) string {
	upper := strings.ToUpper(tagName)
	idx := strings.Index(upper, "T1")
	if idx < 0 {
		return ""
	}
	tech := tagName[idx:]
	var result strings.Builder
	for _, ch := range tech {
		if (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
			result.WriteRune(ch)
		} else {
			break
		}
	}
	s := result.String()
	if len(s) < 4 {
		return ""
	}
	return s
}

func (m *SPCModule) ConfigureMISP(baseURL, apiKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if baseURL == "" || apiKey == "" {
		return fmt.Errorf("MISP base URL and API key are required")
	}

	m.mispConfig.BaseURL = baseURL
	m.mispConfig.APIKey = apiKey

	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", baseURL+"/users/view/me", nil)
	if err != nil {
		return fmt.Errorf("MISP test request: %w", err)
	}
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("MISP connection test failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("MISP authentication failed: HTTP %d (expected 200)", resp.StatusCode)
	}

	m.mispClient = &SPCMISPClient{
		config:   m.mispConfig,
		client:   client,
		lastSync: time.Now(),
	}

	logger.With("component", "spc").Info("MISP connection verified", "url", baseURL)
	return nil
}

func (m *SPCModule) ImportOSCAL(data []byte, format string) (int, error) {
	var records []SPCVulnerabilityRecord

	switch strings.ToLower(format) {
	case "json":
		if err := json.Unmarshal(data, &records); err != nil {
			var wrapper struct {
				Findings []SPCVulnerabilityRecord `json:"findings"`
			}
			if err2 := json.Unmarshal(data, &wrapper); err2 != nil {
				return 0, err
			}
			records = wrapper.Findings
		}
	case "yaml", "yml":
		parsed, err := parseOSCALYAML(data)
		if err != nil {
			return 0, fmt.Errorf("OSCAL YAML parse: %w", err)
		}
		records = parsed
	case "xml":
		parsed, err := parseOSCALXML(data)
		if err != nil {
			return 0, fmt.Errorf("OSCAL XML parse: %w", err)
		}
		records = parsed
	default:
		return 0, fmt.Errorf("unknown OSCAL format: %s (supported: json, yaml, xml)", format)
	}

	added := 0
	m.mu.Lock()
	for _, rec := range records {
		pubDate, _ := time.Parse("2006-01-02", rec.DatePublished)
		modDate, _ := time.Parse("2006-01-02", rec.DateModified)

		cve := SPCCVEScore{
			CVEID:          rec.CVEID,
			Description:    rec.Description,
			CVSS:           rec.CVSSScore,
			CVSSVector:     rec.CVSSVector,
			EPSS:           rec.EPSSScore,
			EPSSPercent:    rec.EPSSPercent,
			InKEV:          rec.InKEV,
			DatePublished:  pubDate,
			DateModified:   modDate,
			AffectedCPEs:   rec.AffectedCPEs,
			AttckTechniques: rec.AttckTechniques,
			MISPGalaxyTags:  rec.MISPGalaxyTags,
			OSCALFindingUUID: rec.OSCALFindingUUID,
			APTGroupAssoc:   rec.APTGroupAssoc,
		}

		if _, exists := m.cveIndex[cve.CVEID]; !exists {
			m.cveIndex[cve.CVEID] = len(m.cveCache)
			m.cveCache = append(m.cveCache, cve)
			added++
		}
	}
	m.mu.Unlock()

	logger.With("component", "spc").Info("OSCAL import completed", "format", format, "added", added)
	return added, nil
}

func parseOSCALYAML(data []byte) ([]SPCVulnerabilityRecord, error) {
	var records []SPCVulnerabilityRecord
	text := strings.TrimSpace(string(data))

	if strings.HasPrefix(text, "---") {
		text = strings.TrimPrefix(text, "---")
		text = strings.TrimSpace(text)
	}

	lines := strings.Split(text, "\n")
	var currentRecord *SPCVulnerabilityRecord
	var inFindings bool
	var inFinding bool
	var listKey string
	var listItems []string

	flushRecord := func() {
		if currentRecord != nil && currentRecord.CVEID != "" {
			switch listKey {
			case "affected_cpes":
				currentRecord.AffectedCPEs = listItems
			case "attck_techniques":
				currentRecord.AttckTechniques = listItems
			case "misp_galaxy_tags":
				currentRecord.MISPGalaxyTags = listItems
			case "apt_group_assoc":
				currentRecord.APTGroupAssoc = listItems
			}
			records = append(records, *currentRecord)
		}
		currentRecord = nil
		listKey = ""
		listItems = nil
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := 0
		for _, ch := range line {
			if ch == ' ' {
				indent++
			} else {
				break
			}
		}

		if indent == 0 && strings.HasPrefix(trimmed, "findings:") {
			inFindings = true
			inFinding = false
			continue
		}

		if indent == 0 && !strings.HasPrefix(trimmed, "findings:") {
			inFindings = false
			inFinding = false
			flushRecord()
			continue
		}

		if inFindings && indent == 2 && strings.HasSuffix(trimmed, ":") {
			flushRecord()
			currentRecord = &SPCVulnerabilityRecord{}
			inFinding = true
			listKey = ""
			listItems = nil
			continue
		}

		if inFinding && currentRecord != nil {
			if strings.HasPrefix(trimmed, "- ") {
				item := strings.TrimPrefix(trimmed, "- ")
				item = strings.Trim(item, "\"")
				if listKey != "" {
					listItems = append(listItems, item)
				}
				continue
			}

			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, "\"")

				if listKey != "" && key != listKey {
					switch listKey {
					case "affected_cpes":
						currentRecord.AffectedCPEs = listItems
					case "attck_techniques":
						currentRecord.AttckTechniques = listItems
					case "misp_galaxy_tags":
						currentRecord.MISPGalaxyTags = listItems
					case "apt_group_assoc":
						currentRecord.APTGroupAssoc = listItems
					}
					listKey = ""
					listItems = nil
				}

				if val == "" {
					switch key {
					case "affected_cpes", "attck_techniques", "misp_galaxy_tags", "apt_group_assoc":
						listKey = key
						listItems = nil
					}
					continue
				}

				switch key {
				case "cve_id":
					currentRecord.CVEID = val
				case "description":
					currentRecord.Description = val
				case "cvss_score":
					if f, err := parseFloat(val); err == nil {
						currentRecord.CVSSScore = f
					}
				case "cvss_vector":
					currentRecord.CVSSVector = val
				case "epss_score":
					if f, err := parseFloat(val); err == nil {
						currentRecord.EPSSScore = f
					}
				case "epss_percentile":
					if f, err := parseFloat(val); err == nil {
						currentRecord.EPSSPercent = f
					}
				case "in_kev":
					currentRecord.InKEV = strings.EqualFold(val, "true") || val == "1"
				case "date_published":
					currentRecord.DatePublished = val
				case "date_modified":
					currentRecord.DateModified = val
				case "oscal_finding_uuid":
					currentRecord.OSCALFindingUUID = val
				}
			}
		}
	}

	flushRecord()

	if len(records) == 0 {
		return nil, fmt.Errorf("no valid vulnerability records found in YAML")
	}

	return records, nil
}

func parseFloat(s string) (float64, error) {
	s = strings.TrimSpace(s)
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

type oscalXMLRoot struct {
	XMLName  struct{}          `xml:"oscal"`
	Findings oscalXMLFindings  `xml:"findings"`
}

type oscalXMLFindings struct {
	Finding []oscalXMLFinding `xml:"finding"`
}

type oscalXMLFinding struct {
	CVEID          string   `xml:"cve_id"`
	Description    string   `xml:"description"`
	CVSSScore      float64  `xml:"cvss_score"`
	CVSSVector     string   `xml:"cvss_vector"`
	EPSSScore      float64  `xml:"epss_score"`
	EPSSPercent    float64  `xml:"epss_percentile"`
	InKEV          bool     `xml:"in_kev"`
	DatePublished  string   `xml:"date_published"`
	DateModified   string   `xml:"date_modified"`
	AffectedCPEs   struct {
		CPE []string `xml:"cpe"`
	} `xml:"affected_cpes"`
	AttckTechniques struct {
		Technique []string `xml:"technique"`
	} `xml:"attck_techniques"`
	MISPGalaxyTags struct {
		Tag []string `xml:"tag"`
	} `xml:"misp_galaxy_tags"`
	OSCALFindingUUID string `xml:"oscal_finding_uuid"`
	APTGroupAssoc    struct {
		Group []string `xml:"group"`
	} `xml:"apt_group_assoc"`
}

func parseOSCALXML(data []byte) ([]SPCVulnerabilityRecord, error) {
	var root oscalXMLRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	var records []SPCVulnerabilityRecord
	for _, f := range root.Findings.Finding {
		rec := SPCVulnerabilityRecord{
			CVEID:           f.CVEID,
			Description:     f.Description,
			CVSSScore:       f.CVSSScore,
			CVSSVector:      f.CVSSVector,
			EPSSScore:       f.EPSSScore,
			EPSSPercent:     f.EPSSPercent,
			InKEV:           f.InKEV,
			DatePublished:   f.DatePublished,
			DateModified:    f.DateModified,
			AffectedCPEs:    f.AffectedCPEs.CPE,
			AttckTechniques: f.AttckTechniques.Technique,
			MISPGalaxyTags:  f.MISPGalaxyTags.Tag,
			OSCALFindingUUID: f.OSCALFindingUUID,
			APTGroupAssoc:   f.APTGroupAssoc.Group,
		}
		records = append(records, rec)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no valid vulnerability records found in XML")
	}

	return records, nil
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

func (m *SPCModule) Calculate(hostID string, assetPackages []string) SPCCorrection {
	m.kernel.Extensions().Execute(m.kernel.Context(), "spc.pre_calculate", hostID)

	m.mu.RLock()
	cves := make([]SPCCVEScore, len(m.cveCache))
	copy(cves, m.cveCache)
	asset := m.assetCache[hostID]
	m.mu.RUnlock()

	var sumOfSquares float64
	var affectedCVE []string
	var topImpactID string
	var topImpactVal float64
	var penalties []CVEPenalty

	for i := range cves {
		cve := &cves[i]

		matchType, matched := m.matchCPE(cve, asset, assetPackages)
		if !matched {
			continue
		}
		cve.Matched = true
		cve.MatchType = matchType

		exposure := m.determineExposure(asset)
		cve.Exposure = exposure

		controlLevel := m.determineControlLevel(asset)
		cve.ControlLevel = controlLevel

		cvssFactor := math.Min(1.0, cve.CVSS/10.0)
		epssFactor := math.Min(1.0, cve.EPSS*10)
		kevFactor := 0.0
		if cve.InKEV {
			kevFactor = 1.0
		} else if m.isInKEVCatalog(cve.CVEID) {
			kevFactor = 1.0
			cve.InKEV = true
		}
		if kevFactor == 0 && cve.HasPublicPoC {
			kevFactor = 0.3
		}

		impact := 0.20*cvssFactor + 0.50*epssFactor + 0.30*kevFactor

		nSubTech := len(cve.AttckTechniques)
		if nSubTech > 0 {
			impact = impact * (1.0 + 0.1*float64(nSubTech))
		}

		nAptGroups := len(cve.APTGroupAssoc)
		if nAptGroups > 0 {
			impact = impact * (1.0 + 0.2*float64(nAptGroups))
		}

		localFactor := cve.MatchType.Factor() * cve.Exposure.Factor() * cve.ControlLevel.Factor()

		days := time.Since(cve.DatePublished).Hours() / 24
		if days < 0 {
			days = 0
		}
		timeFactor := math.Max(0.3, 1.0-days/90)

		penalty := impact * localFactor * timeFactor

		penalties = append(penalties, CVEPenalty{
			CVEID:       cve.CVEID,
			Impact:      impact,
			CVSSFactor:  cvssFactor,
			EPSSFactor:  epssFactor,
			KEVFactor:   kevFactor,
			LocalFactor: localFactor,
			TimeFactor:  timeFactor,
			Penalty:     penalty,
		})

		sumOfSquares += penalty * penalty
		affectedCVE = append(affectedCVE, cve.CVEID)

		if penalty > topImpactVal {
			topImpactVal = penalty
			topImpactID = cve.CVEID
		}
	}

	totalPenalty := math.Sqrt(sumOfSquares)
	pscore := math.Max(m.minPScore, 1.00-totalPenalty)

	weightShift := m.generateWeightShift(affectedCVE, cves)
	action := classifyAction(pscore)

	killChainScore := m.calculateKillChainScore(cves, asset)

	correction := SPCCorrection{
		Score:            math.Round(pscore*1000) / 1000,
		Weights:          weightShift,
		Action:           action.String(),
		AffectedCVE:      affectedCVE,
		TopCVEImpact:     topImpactID,
		TotalPenalty:     math.Round(totalPenalty*1000) / 1000,
		PenaltyBreakdown: penalties,
		KillChainScore:   math.Round(killChainScore*100) / 100,
	}

	m.kernel.Extensions().Execute(m.kernel.Context(), "spc.post_calculate", correction)

	m.kernel.Bus().Publish(m.kernel.Context(), Message{
		Topic:   "spc.vector.updated",
		Payload: correction,
		Source:  "spc",
	})

	return correction
}

func (m *SPCModule) matchCPE(cve *SPCCVEScore, asset *LocalAsset, packages []string) (MatchType, bool) {
	if len(cve.AffectedCPEs) == 0 {
		for _, pkg := range packages {
			if strings.Contains(strings.ToLower(cve.CVEID), strings.ToLower(pkg)) ||
				strings.Contains(strings.ToLower(cve.Description), strings.ToLower(pkg)) {
				return MatchCPEProduct, true
			}
		}
		return MatchNone, false
	}

	if asset == nil {
		for _, pkg := range packages {
			for _, cpe := range cve.AffectedCPEs {
				if strings.Contains(strings.ToLower(cpe), strings.ToLower(pkg)) {
					return MatchCPEProduct, true
				}
			}
		}
		return MatchNone, false
	}

	bestMatch := MatchNone

	for _, myCPE := range asset.InstalledCPEs {
		for _, vulnCPE := range cve.AffectedCPEs {
			matchLevel := m.compareCPE(myCPE, vulnCPE)
			if matchLevel > bestMatch {
				bestMatch = matchLevel
			}
		}
	}

	if bestMatch > MatchNone {
		return bestMatch, true
	}

	for _, pkg := range packages {
		for _, cpe := range cve.AffectedCPEs {
			parts := strings.Split(cpe, ":")
			for _, part := range parts {
				if strings.EqualFold(part, pkg) {
					return MatchCPEProduct, true
				}
			}
		}
	}

	return MatchNone, false
}

func (m *SPCModule) compareCPE(installed, vuln string) MatchType {
	instParts := strings.Split(installed, ":")
	vulnParts := strings.Split(vuln, ":")

	minLen := len(instParts)
	if len(vulnParts) < minLen {
		minLen = len(vulnParts)
	}

	matchCount := 0
	for i := 0; i < minLen; i++ {
		vulnPart := vulnParts[i]
		instPart := instParts[i]

		if vulnPart == "*" {
			matchCount++
			continue
		}
		if strings.EqualFold(vulnPart, instPart) {
			matchCount++
			continue
		}
		break
	}

	if matchCount >= 5 {
		return MatchExactVersion
	}
	if matchCount >= 4 {
		return MatchVersionRange
	}
	if matchCount >= 3 {
		return MatchCPEProduct
	}
	if matchCount >= 2 {
		return MatchCPEVendor
	}
	return MatchNone
}

func (m *SPCModule) determineExposure(asset *LocalAsset) ExposureLevel {
	if asset == nil {
		return ExposureInternal
	}

	switch strings.ToLower(asset.NetworkZone) {
	case "public", "internet", "wan":
		return ExposurePublic
	case "dmz":
		return ExposureDMZ
	case "internal", "lan", "intranet":
		return ExposureInternal
	case "localhost", "loopback":
		return ExposureLocalhost
	default:
		if asset.Role == "bastion" || asset.Role == "web-server" {
			return ExposureDMZ
		}
		return ExposureInternal
	}
}

func (m *SPCModule) determineControlLevel(asset *LocalAsset) ControlLevel {
	if asset == nil {
		return ControlNone
	}

	if asset.Compensations.VirtualPatch {
		return ControlEffective
	}
	if asset.Compensations.WAFRules || asset.Compensations.IPSRules {
		return ControlPartial
	}
	if asset.Compensations.AppWhitelist {
		return ControlPartial
	}
	return ControlNone
}

func (m *SPCModule) generateWeightShift(affectedCVE []string, cves []SPCCVEScore) map[string]float64 {
	shift := map[string]float64{
		model.DomainAttackSurface:      0,
		model.DomainBusinessContinuity: 0,
		model.DomainOperationTrust:     0,
		model.DomainResilience:         0,
	}

	cveMap := make(map[string]*SPCCVEScore, len(cves))
	for i := range cves {
		cveMap[cves[i].CVEID] = &cves[i]
	}

	publicExposedCount := 0
	for _, id := range affectedCVE {
		if cve, ok := cveMap[id]; ok && cve.Exposure >= ExposureDMZ {
			publicExposedCount++
		}
	}

	if publicExposedCount >= 3 {
		shift[model.DomainAttackSurface] = 5
		shift[model.DomainBusinessContinuity] = -3
		shift[model.DomainResilience] = -2
	}

	return shift
}

func (m *SPCModule) calculateKillChainScore(cves []SPCCVEScore, asset *LocalAsset) float64 {
	if asset == nil {
		return 100.0
	}

	techToTactics := map[string][]string{
		"T1190": {"initial_access"},
		"T1133": {"initial_access"},
		"T1078": {"initial_access", "persistence", "privilege_escalation"},
		"T1071": {"command_and_control"},
		"T1095": {"command_and_control"},
		"T1571": {"command_and_control"},
		"T1573": {"command_and_control"},
		"T1059": {"execution"},
		"T1203": {"execution"},
		"T1053": {"execution", "persistence"},
		"T1543": {"persistence", "privilege_escalation"},
		"T1547": {"persistence", "privilege_escalation"},
		"T1136": {"persistence"},
		"T1548": {"privilege_escalation", "defense_evasion"},
		"T1068": {"privilege_escalation"},
		"T1055": {"defense_evasion", "privilege_escalation"},
		"T1562": {"defense_evasion"},
		"T1070": {"defense_evasion"},
		"T1550": {"credential_access", "lateral_movement"},
		"T1003": {"credential_access"},
		"T1110": {"credential_access"},
		"T1558": {"credential_access"},
		"T1210": {"lateral_movement"},
		"T1021": {"lateral_movement"},
		"T1080": {"lateral_movement"},
		"T1048": {"exfiltration"},
		"T1041": {"exfiltration"},
		"T1567": {"exfiltration"},
		"T1486": {"impact"},
		"T1489": {"impact"},
		"T1490": {"impact"},
		"T1498": {"impact"},
		"T1499": {"impact"},
		"T1592": {"initial_access"},
		"T1595": {"initial_access"},
		"T1199": {"initial_access"},
		"T1566": {"initial_access"},
	}

	stageScores := make(map[string]float64)
	allStages := []string{
		"initial_access", "execution", "persistence",
		"privilege_escalation", "defense_evasion", "credential_access",
		"lateral_movement", "exfiltration", "impact", "command_and_control",
	}
	for _, stage := range allStages {
		stageScores[stage] = 100.0
	}

	matchedCVECount := 0
	for _, cve := range cves {
		if !cve.Matched {
			continue
		}
		matchedCVECount++

		for _, tech := range cve.AttckTechniques {
			stages, ok := techToTactics[tech]
			if !ok {
				continue
			}
			for _, stage := range stages {
				stageScores[stage] = math.Max(0, stageScores[stage]-10)
			}
		}
	}

	if matchedCVECount == 0 {
		return 100.0
	}

	var total float64
	for _, score := range stageScores {
		total += score
	}
	return total / float64(len(stageScores))
}

func (m *SPCModule) AddCVE(score SPCCVEScore) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.cveIndex[score.CVEID]; exists {
		return
	}
	m.cveIndex[score.CVEID] = len(m.cveCache)
	m.cveCache = append(m.cveCache, score)
}

func (m *SPCModule) AddCVEs(scores []SPCCVEScore) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, score := range scores {
		if _, exists := m.cveIndex[score.CVEID]; !exists {
			m.cveIndex[score.CVEID] = len(m.cveCache)
			m.cveCache = append(m.cveCache, score)
		}
	}
}

func (m *SPCModule) GetCVEs() []SPCCVEScore {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]SPCCVEScore, len(m.cveCache))
	copy(result, m.cveCache)
	return result
}

func (m *SPCModule) GetCVECount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cveCache)
}

func (m *SPCModule) GetKEVCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, cve := range m.cveCache {
		if cve.InKEV {
			count++
		}
	}
	return count
}

func (m *SPCModule) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cveCache = m.cveCache[:0]
	m.cveIndex = make(map[string]int)
}

func (m *SPCModule) LastUpdate() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastUpdate
}

func (m *SPCModule) generateSampleCVEs() []SPCCVEScore {
	now := time.Now()
	return []SPCCVEScore{
		{
			CVEID:          "CVE-2024-1234",
			Description:    "OpenSSL Remote Code Execution in TLS handshake",
			CVSS:           9.8,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			EPSS:           0.72,
			EPSSPercent:    0.95,
			InKEV:          true,
			HasPublicPoC:   true,
			DatePublished:  now.AddDate(0, 0, -28),
			AffectedCPEs:   []string{"cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"},
			AttckTechniques: []string{"T1190", "T1210"},
			MISPGalaxyTags:  []string{"misp-galaxy:mitre-attck-pattern"},
			APTGroupAssoc:   []string{"APT29", "Lazarus"},
		},
		{
			CVEID:          "CVE-2024-5678",
			Description:    "Nginx HTTP/3 Denial of Service via malformed QUIC frames",
			CVSS:           7.5,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			EPSS:           0.15,
			EPSSPercent:    0.62,
			InKEV:          false,
			HasPublicPoC:   false,
			DatePublished:  now.AddDate(0, 0, -54),
			AffectedCPEs:   []string{"cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"},
			AttckTechniques: []string{"T1499"},
			MISPGalaxyTags:  []string{},
		},
		{
			CVEID:          "CVE-2024-9012",
			Description:    "PHP Information Disclosure via crafted multipart form data",
			CVSS:           5.3,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			EPSS:           0.03,
			EPSSPercent:    0.38,
			InKEV:          false,
			HasPublicPoC:   false,
			DatePublished:  now.AddDate(0, 0, -163),
			AffectedCPEs:   []string{"cpe:2.3:a:php:php:8.1.0:*:*:*:*:*:*:*"},
			AttckTechniques: []string{"T1592"},
			MISPGalaxyTags:  []string{},
		},
	}
}

type SPCInterface interface {
	Calculate(hostID string, assetPackages []string) SPCCorrection
	AddCVE(score SPCCVEScore)
	AddCVEs(scores []SPCCVEScore)
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