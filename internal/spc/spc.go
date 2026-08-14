//go:build spc

package spc

import (
	"github.com/asscor/asscor/internal/kernel"
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

type Module struct {
	kc kernel.KernelContext

	mu          sync.RWMutex
	cveCache    []kernel.SPCCVEScore
	cveIndex    map[string]int
	assetCache  map[string]*kernel.LocalAsset
	lastNVDFetch time.Time
	lastUpdate  time.Time
	fetchResults []kernel.SPCFetchResult
	state       kernel.PluginState

	// Lowercase caches for the assessment hot path. matchCPEFast lowercases
	// each CVE's AffectedCPEs/Description on every evaluation; precomputing
	// these (lazily, keyed by CVEID) eliminates repeated allocation of up to
	// 100k CPE strings per assessment.
	cpeLowerCache  sync.Map // CVEID -> []string (lowercased AffectedCPEs)
	descLowerCache sync.Map // CVEID -> string (lowercased Description)

	fetchInterval  time.Duration
	mispConfig     kernel.SPCMISPConfig
	nvdConfig      kernel.SPCNVDConfig
	epssConfig     kernel.SPCEPSSConfig
	kevConfig      kernel.SPCKEVConfig
	cnnvdConfig    kernel.SPCCNNVDConfig
	cnvdConfig     kernel.SPCCNVDConfig
	oscalConfig    kernel.SPCOscalConfig
	mispClient     *kernel.SPCMISPClient
	enabled        bool
	minPScore      float64
	maxCacheSize   int
	kevCatalog     map[string]bool
	nvdLimiter     chan struct{}
	nvdTimers      []*time.Timer
	done           chan struct{}
	cancelFunc     context.CancelFunc
}

func New() *Module {
	return &Module{
		cveCache:      make([]kernel.SPCCVEScore, 0),
		cveIndex:      make(map[string]int),
		assetCache:    make(map[string]*kernel.LocalAsset),
		kevCatalog:    make(map[string]bool),
		fetchInterval: 1 * time.Hour,
		minPScore:     0.60,
		maxCacheSize:  100000,
		enabled:       false,
		nvdLimiter:    make(chan struct{}, 1),
		done:          make(chan struct{}),
		mispConfig: kernel.SPCMISPConfig{
			SyncHours: 1,
			TLPFilter: "white",
			VerifyTLS: true,
		},
		nvdConfig: kernel.SPCNVDConfig{
			BaseURL:   kernel.DefaultNVDBaseURL,
			SyncHours: 6,
		},
		epssConfig: kernel.SPCEPSSConfig{
			Enabled:       true,
			DataURL:       kernel.DefaultEPSSDataURL,
			SyncIntervalH: 24,
		},
		kevConfig: kernel.SPCKEVConfig{
			Enabled:       true,
			CatalogURL:    kernel.DefaultKEVCatalogURL,
			SyncIntervalH: 24,
		},
		oscalConfig: kernel.SPCOscalConfig{
			InputFormat: "json",
		},
	}
}

func (m *Module) Info() kernel.PluginInfo {
	return kernel.PluginInfo{
		Name:        "spc",
		Version:     "2.0.0",
		Description: "Security Posture Calculator 閳?computes individualized risk posture from global CVE data, MISP, ATT&CK, and local asset inventory",
		Author:      "ASSCOR Core Team",
	}
}

func (m *Module) Dependencies() []kernel.PluginDependency {
	return nil
}

func (m *Module) Priority() int {
	return 20
}

func (m *Module) Init(ctx context.Context, kc kernel.KernelContext) error {
	if kc == nil {
		return fmt.Errorf("kernel context must not be nil")
	}
	m.kc = kc
	m.state = kernel.PluginInitialized

	cfg := kc.GetConfigObj()
	if cfg == nil {
		m.enabled = false
		m.minPScore = 0.60
		m.fetchInterval = 24 * time.Hour
		m.nvdConfig.BaseURL = kernel.DefaultNVDBaseURL
		m.nvdConfig.APIKey = os.Getenv("NVD_API_KEY")
		m.nvdConfig.SyncHours = 24
		m.epssConfig.Enabled = true
		m.epssConfig.DataURL = kernel.DefaultEPSSDataURL
		m.epssConfig.SyncIntervalH = 24
		m.kevConfig.Enabled = true
		m.kevConfig.CatalogURL = kernel.DefaultKEVCatalogURL
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

	kc.Container().Bind((*kernel.SPCInterface)(nil), m)

	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.state = kernel.PluginStarted
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

func (m *Module) Stop(ctx context.Context) error {
	m.state = kernel.PluginStopping

	m.mu.Lock()
	for _, t := range m.nvdTimers {
		t.Stop()
	}
	m.nvdTimers = nil
	cancel := m.cancelFunc
	select {
	case <-m.done:
	default:
		close(m.done)
	}
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	m.saveCacheToDisk()
	m.state = kernel.PluginStopped
	logger.WithComponent("spc").Info("stopped")
	return nil
}

func (m *Module) State() kernel.PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *Module) HealthCheck(ctx context.Context) error {
	if m.state != kernel.PluginStarted {
		return fmt.Errorf("spc not started (state=%s)", m.state)
	}
	return nil
}

func (m *Module) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

func (m *Module) SetEnabled(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = v
}

func (m *Module) ConfigureFromConfig(cfg *config.Config) {
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
		m.nvdConfig.BaseURL = kernel.DefaultNVDBaseURL
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
		m.epssConfig.DataURL = kernel.DefaultEPSSDataURL
	}
	m.epssConfig.SyncIntervalH = spcCfg.EPSS.SyncIntervalH
	if m.epssConfig.SyncIntervalH == 0 {
		m.epssConfig.SyncIntervalH = 24
	}

	m.kevConfig.Enabled = spcCfg.CISAKEV.Enabled
	m.kevConfig.CatalogURL = spcCfg.CISAKEV.CatalogURL
	if m.kevConfig.CatalogURL == "" {
		m.kevConfig.CatalogURL = kernel.DefaultKEVCatalogURL
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

func (m *Module) fetchLoop() {
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
		case <-m.kc.Context().Done():
			m.saveCacheToDisk()
			return
		case <-ticker.C:
			m.FetchFromAllSources()
		case <-cleanupTicker.C:
			m.cleanupOldCVEs()
		}
	}
}

func (m *Module) cleanupOldCVEs() {
	cutoff := time.Now().AddDate(0, 0, -365)

	m.mu.RLock()
	cacheCopy := make([]kernel.SPCCVEScore, len(m.cveCache))
	copy(cacheCopy, m.cveCache)
	m.mu.RUnlock()

	kept := make([]kernel.SPCCVEScore, 0, len(cacheCopy))
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

func (m *Module) UpsertAsset(asset kernel.LocalAsset) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assetCache[asset.HostID] = &asset
}

func (m *Module) GetAsset(hostID string) *kernel.LocalAsset {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.assetCache[hostID]
}

func (m *Module) Calculate(hostID string, assetPackages []string) kernel.SPCCorrection {
	if m.kc != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "spc.pre_calculate", hostID)
	}

	var cves []kernel.SPCCVEScore
	var asset *kernel.LocalAsset
	var kevCatalog map[string]bool

	m.mu.RLock()
	// Reference the cache slice and KEV map directly instead of deep-copying up
	// to 100k CVE structs on every assessment. The matching loop is read-only on
	// these shared structures; per-CVE results are collected in a local penalties
	// slice. Cache mutation only happens under m.mu.Lock elsewhere (AddCVE/Merge),
	// and Calculate is invoked synchronously from the assessment path.
	cves = m.cveCache
	if a, ok := m.assetCache[hostID]; ok {
		assetCopy := *a
		asset = &assetCopy
	}
	kevCatalog = m.kevCatalog
	m.mu.RUnlock()

	logger.WithComponent("spc").Debug("Calculate called",
		"host_id", hostID,
		"cve_cache_size", len(cves),
		"has_asset", asset != nil,
		"packages_count", len(assetPackages),
		"kev_catalog_size", len(kevCatalog),
	)

	if len(cves) == 0 {
		logger.WithComponent("spc").Warn("CVE cache is empty, SPC cannot calculate risk; returning neutral score. Data sync may still be in progress.")
		return kernel.SPCCorrection{
			Score:  1.0,
			Action: "no_data",
		}
	}

	pkgNames := extractPkgNames(assetPackages)
	pkgNameSet := make(map[string]bool, len(pkgNames))
	lowerPkgNames := make([]string, 0, len(pkgNames))
	for _, n := range pkgNames {
		if len(n) < 2 {
			continue
		}
		ln := strings.ToLower(n)
		pkgNameSet[ln] = true
		lowerPkgNames = append(lowerPkgNames, ln)
	}

	installedCPESet := make(map[string]bool, 0)
	lowerInstalledCPEs := make([]string, 0)
	if asset != nil && len(asset.InstalledCPEs) > 0 {
		for _, cpe := range asset.InstalledCPEs {
			lc := strings.ToLower(cpe)
			installedCPESet[lc] = true
			lowerInstalledCPEs = append(lowerInstalledCPEs, lc)
		}
	}

	// Fast path: with no package names and no installed CPEs, no CVE can ever
	// match (both matchCPEFast branches require at least one of these inputs).
	// Short-circuit the O(cache) scan instead of iterating up to 100k CVEs.
	if len(lowerPkgNames) == 0 && len(lowerInstalledCPEs) == 0 {
		logger.WithComponent("spc").Debug("Calculate: no package/CPE inputs, returning neutral score", "host_id", hostID)
		return kernel.SPCCorrection{
			Score:  1.0,
			Action: "no_input",
		}
	}

	pkgSample := assetPackages
	if len(pkgSample) > 10 {
		pkgSample = pkgSample[:10]
	}
	logger.WithComponent("spc").Debug("Calculate input",
		"host_id", hostID,
		"cve_cache_size", len(cves),
		"has_asset", asset != nil,
		"installed_cpes", installedCPEsCount(asset),
		"packages_count", len(assetPackages),
		"pkg_names_count", len(pkgNameSet),
		"pkg_names_sample", extractPkgNames(pkgSample),
	)

	var sumOfSquares float64
	var affectedCVE []string
	var topImpactID string
	var topImpactVal float64
	var penalties []kernel.CVEPenalty
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

		matchType, matched := m.matchCPEFast(cve, lowerPkgNames, lowerInstalledCPEs)

		if !matched {
			continue
		}
		matchStats.matched++

		switch matchType {
		case kernel.MatchExactVersion:
			matchStats.byExact++
		case kernel.MatchVersionRange:
			matchStats.byProduct++
		case kernel.MatchCPEProduct:
			matchStats.byProduct++
		case kernel.MatchCPEVendor:
			matchStats.byVendor++
		}
		if len(cve.AffectedCPEs) == 0 {
			matchStats.noCPEs++
		}

		exposure := m.determineExposure(asset)
		controlLevel := m.determineControlLevel(asset)

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

		localFactor := matchType.Factor() * exposure.Factor() * controlLevel.Factor()

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

		penalties = append(penalties, kernel.CVEPenalty{
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
	action := kernel.ClassifyAction(pscore)

	killChainScore := m.calculateKillChainScore(cves, asset)

	correction := kernel.SPCCorrection{
		Score:            math.Round(pscore*1000) / 1000,
		Weights:          weightShift,
		Action:           action.String(),
		AffectedCVE:      affectedCVE,
		TopCVEImpact:     topImpactID,
		TotalPenalty:     math.Round(totalPenalty*1000) / 1000,
		PenaltyBreakdown: penalties,
		KillChainScore:   math.Round(killChainScore*100) / 100,
	}

	logger.WithComponent("spc").Debug("Calculate result",
		"host_id", hostID,
		"p_score", correction.Score,
		"action", correction.Action,
		"affected_cve_count", len(affectedCVE),
		"total_penalty", correction.TotalPenalty,
		"kill_chain_score", correction.KillChainScore,
		"match_stats", fmt.Sprintf("total=%d matched=%d byExact=%d byProduct=%d byVendor=%d byDesc=%d noCPEs=%d",
			matchStats.total, matchStats.matched, matchStats.byExact, matchStats.byProduct, matchStats.byVendor, matchStats.byDesc, matchStats.noCPEs),
	)

	if m.kc != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "spc.post_calculate", correction)
	}

	if m.kc != nil {
		if errs := m.kc.Bus().PublishSync(m.kc.Context(), kernel.Message{
			Topic:   "spc.vector.updated",
			Payload: correction,
			Source:  "spc",
		}); len(errs) > 0 {
			logger.WithComponent("spc").Warn("sync publish errors", "count", len(errs))
		}
	}

	return correction
}

func (m *Module) matchCPEFast(cve *kernel.SPCCVEScore, lowerPkgNames []string, lowerInstalledCPEs []string) (kernel.MatchType, bool) {
	if len(cve.AffectedCPEs) == 0 {
		if len(lowerPkgNames) == 0 {
			return kernel.MatchNone, false
		}
		lowerDesc := m.loweredDescription(cve)
		for _, ln := range lowerPkgNames {
			if strings.Contains(lowerDesc, ln) {
				return kernel.MatchCPEProduct, true
			}
		}
		return kernel.MatchNone, false
	}

	lowerVulnCPEs := m.loweredAffectedCPEs(cve)

	if len(lowerInstalledCPEs) > 0 {
		bestMatch := kernel.MatchNone
		for _, myCPE := range lowerInstalledCPEs {
			for _, vulnCPE := range lowerVulnCPEs {
				matchLevel := m.compareCPE(myCPE, vulnCPE)
				if matchLevel > bestMatch {
					bestMatch = matchLevel
				}
			}
		}
		if bestMatch > kernel.MatchNone {
			return bestMatch, true
		}
	}

	for _, ln := range lowerPkgNames {
		for _, lowerCPE := range lowerVulnCPEs {
			if strings.Contains(lowerCPE, ln) {
				return kernel.MatchCPEProduct, true
			}
		}
	}

	return kernel.MatchNone, false
}

// loweredAffectedCPEs returns the lowercased AffectedCPEs for a CVE, lazily
// caching the result keyed by CVEID. CVE entries are immutable between cache
// mutations (AddCVE/Merge/load), so the cache is safe to reuse across
// assessments; eviction and in-place merge invalidate the entry explicitly.
func (m *Module) loweredAffectedCPEs(cve *kernel.SPCCVEScore) []string {
	if v, ok := m.cpeLowerCache.Load(cve.CVEID); ok {
		return v.([]string)
	}
	v := make([]string, len(cve.AffectedCPEs))
	for i, cpe := range cve.AffectedCPEs {
		v[i] = strings.ToLower(cpe)
	}
	m.cpeLowerCache.Store(cve.CVEID, v)
	return v
}

// loweredDescription returns the lowercased Description for a CVE, lazily
// cached keyed by CVEID (see loweredAffectedCPEs).
func (m *Module) loweredDescription(cve *kernel.SPCCVEScore) string {
	if v, ok := m.descLowerCache.Load(cve.CVEID); ok {
		return v.(string)
	}
	v := strings.ToLower(cve.Description)
	m.descLowerCache.Store(cve.CVEID, v)
	return v
}

// invalidateLowerCaches removes cached lowercase data for a CVE whose
// AffectedCPEs/Description may have changed via in-place merge.
func (m *Module) invalidateLowerCaches(cveID string) {
	m.cpeLowerCache.Delete(cveID)
	m.descLowerCache.Delete(cveID)
}

func (m *Module) matchCPE(cve *kernel.SPCCVEScore, asset *kernel.LocalAsset, packages []string) (kernel.MatchType, bool) {
	pkgNames := extractPkgNames(packages)

	if len(cve.AffectedCPEs) == 0 {
		for _, name := range pkgNames {
			if len(name) < 2 {
				continue
			}
			lowerDesc := strings.ToLower(cve.Description)
			lowerName := strings.ToLower(name)
			if strings.Contains(lowerDesc, lowerName) {
				return kernel.MatchCPEProduct, true
			}
		}
		return kernel.MatchNone, false
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
					return kernel.MatchCPEProduct, true
				}
			}
		}
		return kernel.MatchNone, false
	}

	bestMatch := kernel.MatchNone

	for _, myCPE := range asset.InstalledCPEs {
		for _, vulnCPE := range cve.AffectedCPEs {
			matchLevel := m.compareCPE(myCPE, vulnCPE)
			if matchLevel > bestMatch {
				bestMatch = matchLevel
			}
		}
	}

	if bestMatch > kernel.MatchNone {
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
				return kernel.MatchCPEProduct, true
			}
		}
	}

	return kernel.MatchNone, false
}

func (m *Module) determineExposure(asset *kernel.LocalAsset) kernel.ExposureLevel {
	if asset == nil {
		return kernel.ExposureInternal
	}

	switch strings.ToLower(asset.NetworkZone) {
	case "public", "internet", "wan":
		return kernel.ExposurePublic
	case "dmz":
		return kernel.ExposureDMZ
	case "internal", "lan", "intranet":
		return kernel.ExposureInternal
	case "localhost", "loopback":
		return kernel.ExposureLocalhost
	default:
		if asset.Role == "bastion" || asset.Role == "web-server" {
			return kernel.ExposureDMZ
		}
		return kernel.ExposureInternal
	}
}

func (m *Module) determineControlLevel(asset *kernel.LocalAsset) kernel.ControlLevel {
	if asset == nil {
		return kernel.ControlNone
	}

	if asset.Compensations.VirtualPatch {
		return kernel.ControlEffective
	}
	if asset.Compensations.WAFRules || asset.Compensations.IPSRules {
		return kernel.ControlPartial
	}
	if asset.Compensations.AppWhitelist {
		return kernel.ControlPartial
	}
	return kernel.ControlNone
}

func (m *Module) generateWeightShift(affectedCVE []string, cves []kernel.SPCCVEScore) map[string]float64 {
	shift := map[string]float64{
		model.DomainAttackSurface:      0,
		model.DomainBusinessContinuity: 0,
		model.DomainOperationTrust:     0,
		model.DomainResilience:         0,
	}

	cveMap := make(map[string]*kernel.SPCCVEScore, len(cves))
	for i := range cves {
		cveMap[cves[i].CVEID] = &cves[i]
	}

	publicExposedCount := 0
	for _, id := range affectedCVE {
		if cve, ok := cveMap[id]; ok && cve.Exposure >= kernel.ExposureDMZ {
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

func (m *Module) calculateKillChainScore(cves []kernel.SPCCVEScore, asset *kernel.LocalAsset) float64 {
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
