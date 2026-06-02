package kernel

import (
	"context"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
)

type SPCModule struct {
	kernel KernelContext

	mu          sync.RWMutex
	cveCache    []SPCCVEScore
	cveIndex    map[string]int
	assetCache  map[string]*LocalAsset
	lastNVDFetch time.Time
	lastUpdate  time.Time
	fetchResults []SPCFetchResult
	state       PluginState

	fetchInterval  time.Duration
	mispConfig     SPCMISPConfig
	nvdConfig      SPCNVDConfig
	epssConfig     SPCEPSSConfig
	kevConfig      SPCKEVConfig
	cnnvdConfig    SPCCNNVDConfig
	cnvdConfig     SPCCNVDConfig
	oscalConfig    SPCOscalConfig
	mispClient     *SPCMISPClient
	enabled        bool
	minPScore      float64
	maxCacheSize   int
	kevCatalog     map[string]bool
	nvdLimiter     chan struct{}
	nvdTimers      []*time.Timer
	done           chan struct{}
	cancelFunc     context.CancelFunc
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
			BaseURL:   defaultNVDBaseURL,
			SyncHours: 6,
		},
		epssConfig: SPCEPSSConfig{
			Enabled:       true,
			DataURL:       defaultEPSSDataURL,
			SyncIntervalH: 24,
		},
		kevConfig: SPCKEVConfig{
			Enabled:       true,
			CatalogURL:    defaultKEVCatalogURL,
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
		Description: "Security Posture Calculator 鈥?computes individualized risk posture from global CVE data, MISP, ATT&CK, and local asset inventory",
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
		m.nvdConfig.BaseURL = defaultNVDBaseURL
		m.nvdConfig.APIKey = os.Getenv("NVD_API_KEY")
		m.nvdConfig.SyncHours = 24
		m.epssConfig.Enabled = true
		m.epssConfig.DataURL = defaultEPSSDataURL
		m.epssConfig.SyncIntervalH = 24
		m.kevConfig.Enabled = true
		m.kevConfig.CatalogURL = defaultKEVCatalogURL
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

	kc.Container().Bind((*SPCInterface)(nil), m)

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
		m.nvdConfig.BaseURL = defaultNVDBaseURL
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
		m.epssConfig.DataURL = defaultEPSSDataURL
	}
	m.epssConfig.SyncIntervalH = spcCfg.EPSS.SyncIntervalH
	if m.epssConfig.SyncIntervalH == 0 {
		m.epssConfig.SyncIntervalH = 24
	}

	m.kevConfig.Enabled = spcCfg.CISAKEV.Enabled
	m.kevConfig.CatalogURL = spcCfg.CISAKEV.CatalogURL
	if m.kevConfig.CatalogURL == "" {
		m.kevConfig.CatalogURL = defaultKEVCatalogURL
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

func (m *SPCModule) Calculate(hostID string, assetPackages []string) SPCCorrection {
	if m.kernel != nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "spc.pre_calculate", hostID)
	}

	var cves []SPCCVEScore
	var asset *LocalAsset
	var kevCatalog map[string]bool

	m.mu.RLock()
	cves = make([]SPCCVEScore, len(m.cveCache))
	copy(cves, m.cveCache)
	if a, ok := m.assetCache[hostID]; ok {
		assetCopy := *a
		asset = &assetCopy
	}
	kevCatalog = make(map[string]bool, len(m.kevCatalog))
	for k, v := range m.kevCatalog {
		kevCatalog[k] = v
	}
	m.mu.RUnlock()

	type cpeIndexEntry struct {
		original string
		lower    string
		vendor   string
		product  string
	}

	cpeIndex := make([][]cpeIndexEntry, len(cves))
	for i := range cves {
		entries := make([]cpeIndexEntry, 0, len(cves[i].AffectedCPEs))
		for _, cpe := range cves[i].AffectedCPEs {
			lower := strings.ToLower(cpe)
			parts := strings.SplitN(lower, ":", 6)
			vendor := ""
			product := ""
			if len(parts) >= 5 {
				vendor = parts[3]
				product = parts[4]
			}
			entries = append(entries, cpeIndexEntry{
				original: cpe,
				lower:    lower,
				vendor:   vendor,
				product:  product,
			})
		}
		cpeIndex[i] = entries
	}

	logger.WithComponent("spc").Info("Calculate called",
		"host_id", hostID,
		"cve_cache_size", len(cves),
		"has_asset", asset != nil,
		"packages_count", len(assetPackages),
		"kev_catalog_size", len(kevCatalog),
	)

	if len(cves) == 0 {
		logger.WithComponent("spc").Warn("CVE cache is empty, SPC cannot calculate risk; returning neutral score. Data sync may still be in progress.")
		return SPCCorrection{
			Score:  1.0,
			Action: "no_data",
		}
	}

	pkgNames := extractPkgNames(assetPackages)
	pkgNameSet := make(map[string]bool, len(pkgNames))
	for _, n := range pkgNames {
		pkgNameSet[strings.ToLower(n)] = true
	}

	installedCPESet := make(map[string]bool, 0)
	if asset != nil && len(asset.InstalledCPEs) > 0 {
		for _, cpe := range asset.InstalledCPEs {
			installedCPESet[strings.ToLower(cpe)] = true
		}
	}

	pkgSample := assetPackages
	if len(pkgSample) > 10 {
		pkgSample = pkgSample[:10]
	}
	logger.WithComponent("spc").Info("Calculate input",
		"host_id", hostID,
		"cve_cache_size", len(cves),
		"has_asset", asset != nil,
		"installed_cpes", len(asset.InstalledCPEs),
		"packages_count", len(assetPackages),
		"pkg_names_count", len(pkgNameSet),
		"pkg_names_sample", extractPkgNames(pkgSample),
	)

	var sumOfSquares float64
	var affectedCVE []string
	var topImpactID string
	var topImpactVal float64
	var penalties []CVEPenalty
	matchStats := struct {
		total      int
		matched    int
		byProduct  int
		byDesc     int
		byVendor   int
		byExact    int
		noCPEs     int
	}{}

	for i := range cves {
		cve := &cves[i]
		matchStats.total++

		matchType, matched := m.matchCPE(cve, asset, assetPackages)

		if !matched {
			continue
		}
		matchStats.matched++

		switch matchType {
		case MatchExactVersion:
			matchStats.byExact++
		case MatchVersionRange:
			matchStats.byProduct++
		case MatchCPEProduct:
			matchStats.byProduct++
		case MatchCPEVendor:
			matchStats.byVendor++
		}
		if len(cve.AffectedCPEs) == 0 {
			matchStats.noCPEs++
		}
		cve.Matched = true
		cve.MatchType = matchType

		exposure := m.determineExposure(asset)
		cve.Exposure = exposure

		controlLevel := m.determineControlLevel(asset)
		cve.ControlLevel = controlLevel

		cvssFactor := math.Min(1.0, cve.CVSS/10.0)
		epssFactor := 0.0
		if cve.EPSS > 0 {
			epssFactor = math.Min(1.0, -math.Log(1-cve.EPSS)/5)
		}
		kevFactor := 0.0
		if cve.InKEV {
			kevFactor = 1.0
		} else if kevCatalog[cve.CVEID] {
			kevFactor = 1.0
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

		products := ""
		if len(cve.AffectedCPEs) > 0 {
			seen := make(map[string]bool)
			parts := make([]string, 0, len(cve.AffectedCPEs))
			for _, cpe := range cve.AffectedCPEs {
				fields := strings.SplitN(cpe, ":", 6)
				if len(fields) >= 5 {
					vendor := fields[3]
					product := fields[4]
					key := vendor + ":" + product
					if !seen[key] {
						seen[key] = true
						parts = append(parts, product)
					}
				}
			}
			if len(parts) > 3 {
				parts = parts[:3]
			}
			products = strings.Join(parts, ", ")
		}

		penalties = append(penalties, CVEPenalty{
			CVEID:       cve.CVEID,
			CVSS:        cve.CVSS,
			EPSS:        cve.EPSS,
			InKEV:       cve.InKEV,
			HasPoC:      cve.HasPublicPoC,
			Impact:      impact,
			CVSSFactor:  cvssFactor,
			EPSSFactor:  epssFactor,
			KEVFactor:   kevFactor,
			LocalFactor: localFactor,
			TimeFactor:  timeFactor,
			Penalty:     penalty,
			Products:    products,
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

	logger.WithComponent("spc").Info("Calculate result",
		"host_id", hostID,
		"p_score", correction.Score,
		"action", correction.Action,
		"affected_cve_count", len(affectedCVE),
		"total_penalty", correction.TotalPenalty,
		"kill_chain_score", correction.KillChainScore,
		"match_stats", fmt.Sprintf("total=%d matched=%d byExact=%d byProduct=%d byVendor=%d byDesc=%d noCPEs=%d",
			matchStats.total, matchStats.matched, matchStats.byExact, matchStats.byProduct, matchStats.byVendor, matchStats.byDesc, matchStats.noCPEs),
	)

	if m.kernel != nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "spc.post_calculate", correction)
	}

	if m.kernel != nil {
		if errs := m.kernel.Bus().PublishSync(m.kernel.Context(), Message{
			Topic:   "spc.vector.updated",
			Payload: correction,
			Source:  "spc",
		}); len(errs) > 0 {
			logger.WithComponent("spc").Warn("sync publish errors", "count", len(errs))
		}
	}

	return correction
}

func (m *SPCModule) matchCPE(cve *SPCCVEScore, asset *LocalAsset, packages []string) (MatchType, bool) {
	pkgNames := extractPkgNames(packages)

	if len(cve.AffectedCPEs) == 0 {
		for _, name := range pkgNames {
			if len(name) < 2 {
				continue
			}
			lowerDesc := strings.ToLower(cve.Description)
			lowerName := strings.ToLower(name)
			if strings.Contains(lowerDesc, lowerName) {
				return MatchCPEProduct, true
			}
		}
		return MatchNone, false
	}

	if asset == nil || len(asset.InstalledCPEs) == 0 {
		for _, name := range pkgNames {
			if len(name) < 2 {
				continue
			}
			lowerName := strings.ToLower(name)
			for _, cpe := range cve.AffectedCPEs {
				lowerCPE := strings.ToLower(cpe)
				if strings.Contains(lowerCPE, lowerName) {
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

	for _, name := range pkgNames {
		if len(name) < 2 {
			continue
		}
		lowerName := strings.ToLower(name)
		for _, cpe := range cve.AffectedCPEs {
			lowerCPE := strings.ToLower(cpe)
			if strings.Contains(lowerCPE, lowerName) {
				return MatchCPEProduct, true
			}
		}
	}

	return MatchNone, false
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
