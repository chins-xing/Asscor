package spc

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
)

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
	action := ClassifyAction(pscore)

	killChainScore := m.calculateKillChainScore(cves, asset)

	correction := SPCCorrection{
		Score:           math.Round(pscore*1000) / 1000,
		Weights:         weightShift,
		Action:          action.String(),
		AffectedCVE:     affectedCVE,
		TopCVEImpact:    topImpactID,
		TotalPenalty:    math.Round(totalPenalty*1000) / 1000,
		PenaltyBreakdown: penalties,
		KillChainScore:  math.Round(killChainScore*100) / 100,
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
		if errs := m.kernel.Bus().PublishSync(m.kernel.Context(), correction); len(errs) > 0 {
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
			tactics, ok := techToTactics[tech]
			if !ok {
				continue
			}
			for _, tactic := range tactics {
				stageScores[tactic] = math.Max(0, stageScores[tactic]-10)
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
