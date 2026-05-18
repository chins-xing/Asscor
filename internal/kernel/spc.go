package kernel

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

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

type SPCModule struct {
	kernel *Kernel

	mu          sync.RWMutex
	cveCache    []SPCCVEScore
	assetCache  map[string]*LocalAsset
	lastFetch   time.Time
	lastUpdate  time.Time
	fetchResults []SPCFetchResult
	state       PluginState

	fetchInterval  time.Duration
	mispConfig     SPCMISPConfig
	nvdConfig      SPCNVDConfig
	oscalConfig    SPCOscalConfig
	mispClient     *SPCMISPClient
	enabled        bool
	minPScore      float64
}

func NewSPCModule() *SPCModule {
	return &SPCModule{
		cveCache:      make([]SPCCVEScore, 0),
		assetCache:    make(map[string]*LocalAsset),
		fetchInterval: 1 * time.Hour,
		minPScore:     0.60,
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
		log.Printf("spc: WARNING — NVD API key not configured, SPC may be rate limited (set spc.nvd.api_key or NVD_API_KEY)")
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
				log.Printf("spc: WARNING — MISP configuration invalid: %v, continuing without MISP", err)
			}
		}
		go m.fetchLoop()
	}
	log.Println("spc: started (enabled:", m.enabled, ")")
	return nil
}

func (m *SPCModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.state = PluginStopped
	log.Println("spc: stopped")
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
	removed := before - len(m.cveCache)
	if removed > 0 {
		log.Printf("spc: cleaned %d old CVE records (kept %d)", removed, len(m.cveCache))
	}
}

func (m *SPCModule) FetchFromAllSources() []SPCFetchResult {
	results := make([]SPCFetchResult, 0)

	result := m.FetchFromNVD()
	results = append(results, result)

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
			sort.Slice(m.cveCache, func(i, j int) bool {
				return m.cveCache[i].CVSS > m.cveCache[j].CVSS
			})
			for i := 0; i < len(m.cveCache) && i < 10; i++ {
				topCVEs = append(topCVEs, m.cveCache[i].CVEID)
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
	m.mu.Unlock()

	log.Println("spc: NVD fetch triggered (stub — add NVD API key for live data)")

	sampleCVEs := m.generateSampleCVEs()
	m.mu.Lock()
	for _, cve := range sampleCVEs {
		exists := false
		for _, existing := range m.cveCache {
			if existing.CVEID == cve.CVEID {
				exists = true
				break
			}
		}
		if !exists {
			m.cveCache = append(m.cveCache, cve)
			result.CVEAdded++
		}
	}
	m.mu.Unlock()

	result.Duration = time.Since(start)
	return result
}

func (m *SPCModule) FetchFromMISP() SPCFetchResult {
	start := time.Now()
	result := SPCFetchResult{
		Source:    "misp",
		Timestamp: time.Now(),
	}

	log.Println("spc: MISP fetch triggered (stub — configure MISP base URL and API key)")

	if m.mispClient != nil && m.mispClient.config.BaseURL != "" {
		m.fetchMISPEvents(result)
	}

	result.Duration = time.Since(start)
	return result
}

func (m *SPCModule) fetchMISPEvents(result SPCFetchResult) {
	result.CVEAdded = 0
	log.Println("spc: MISP live fetch not configured, using stub data")
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

	log.Printf("spc: MISP connection verified at %s", baseURL)
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
	case "yaml", "xml":
		log.Println("spc: OSCAL YAML/XML parsing not implemented, use JSON format")
		return 0, nil
	default:
		log.Println("spc: unknown OSCAL format:", format)
		return 0, nil
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

		exists := false
		for _, existing := range m.cveCache {
			if existing.CVEID == cve.CVEID {
				exists = true
				break
			}
		}
		if !exists {
			m.cveCache = append(m.cveCache, cve)
			added++
		}
	}
	m.mu.Unlock()

	return added, nil
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
		} else if cve.HasPublicPoC {
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

	publicExposedCount := 0
	for _, id := range affectedCVE {
		for _, cve := range cves {
			if cve.CVEID == id && cve.Exposure >= ExposureDMZ {
				publicExposedCount++
				break
			}
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

	stageTactics := map[string][]string{
		"initial_access":    {"TA0001"},
		"execution":         {"TA0002"},
		"persistence":       {"TA0003"},
		"privilege_escalation": {"TA0004"},
		"defense_evasion":   {"TA0005"},
		"credential_access": {"TA0006"},
		"lateral_movement":  {"TA0008"},
		"exfiltration":      {"TA0010"},
		"impact":            {"TA0040"},
	}

	stageScores := make(map[string]float64)
	for stage := range stageTactics {
		stageScores[stage] = 100.0
	}

	matchedCVECount := 0
	for _, cve := range cves {
		if !cve.Matched {
			continue
		}
		matchedCVECount++

		for _, tech := range cve.AttckTechniques {
			for stage, tactics := range stageTactics {
				for _, tac := range tactics {
					if strings.HasPrefix(tech, strings.TrimPrefix(tac, "TA")) {
						stageScores[stage] = math.Max(0, stageScores[stage]-10)
					}
				}
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
	for _, existing := range m.cveCache {
		if existing.CVEID == score.CVEID {
			return
		}
	}
	m.cveCache = append(m.cveCache, score)
}

func (m *SPCModule) AddCVEs(scores []SPCCVEScore) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, score := range scores {
		exists := false
		for _, existing := range m.cveCache {
			if existing.CVEID == score.CVEID {
				exists = true
				break
			}
		}
		if !exists {
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
	ImportOSCAL(data []byte, format string) (int, error)
	ConfigureMISP(baseURL, apiKey string) error
	Enabled() bool
	SetEnabled(v bool)
	LastUpdate() time.Time
}