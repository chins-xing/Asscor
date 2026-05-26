package kernel

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

func (m *ATTACKModule) performAttribution(stages []AttackStage, iocs []IOCEntry) *AttributionResult {
	if len(stages) == 0 {
		return nil
	}

	observedTechs := make(map[string]float64)
	for _, s := range stages {
		weight := 1.0
		if s.Confidence > 0 {
			weight = s.Confidence
		}
		if existing, ok := observedTechs[s.TechniqueID]; ok {
			observedTechs[s.TechniqueID] = math.Max(existing, weight)
		} else {
			observedTechs[s.TechniqueID] = weight
		}
	}

	iocActorScores := make(map[string]float64)
	iocEvidenceCount := make(map[string]int)
	for _, ioc := range iocs {
		if ioc.ThreatActor == "" {
			continue
		}
		if ioc.Confidence > 0 {
			iocActorScores[ioc.ThreatActor] += ioc.Confidence
		} else {
			iocActorScores[ioc.ThreatActor] += 0.5
		}
		iocEvidenceCount[ioc.ThreatActor]++
	}

	type actorScore struct {
		id              string
		name            string
		techniqueScore  float64
		iocScore        float64
		combinedScore   float64
		overlapTechs    []string
		evidence        []AttributionEvidence
		country         string
		motivation      string
	}

	var candidates []actorScore

	for groupID, group := range m.aptGroups {
		techScore, overlapTechs := m.calculateTechniqueOverlap(observedTechs, group.Techniques)

		iocScore := 0.0
		if s, ok := iocActorScores[groupID]; ok {
			iocScore = s
		}
		for _, alias := range group.Aliases {
			if s, ok := iocActorScores[alias]; ok {
				iocScore = math.Max(iocScore, s)
			}
		}

		combinedScore := techScore*0.6 + iocScore*0.4
		if iocScore > 0 && techScore > 0 {
			combinedScore = math.Min(combinedScore+0.1, 1.0)
		}

		if combinedScore < 0.1 {
			continue
		}

		var evidence []AttributionEvidence

		if len(overlapTechs) > 0 {
			evidence = append(evidence, AttributionEvidence{
				Type:        "ttp_overlap",
				Description: fmt.Sprintf("Overlaps %d techniques with %s (%s)", len(overlapTechs), group.Name, groupID),
				Weight:      techScore,
				Source:      "attck_attribution",
			})
		}

		if iocScore > 0 {
			evidence = append(evidence, AttributionEvidence{
				Type:        "ioc_match",
				Description: fmt.Sprintf("IOC evidence links to %s (score=%.2f, %d indicators)", group.Name, iocScore, iocEvidenceCount[groupID]),
				Weight:      iocScore,
				Source:      "attck_attribution",
			})
		}

		sectorMatch := m.checkSectorAlignment(stages, group)
		if sectorMatch > 0 {
			evidence = append(evidence, AttributionEvidence{
				Type:        "target_sector",
				Description: fmt.Sprintf("Target sector alignment with %s (score=%.2f)", group.Name, sectorMatch),
				Weight:      sectorMatch,
				Source:      "attck_attribution",
			})
			combinedScore = math.Min(combinedScore+sectorMatch*0.15, 1.0)
		}

		candidates = append(candidates, actorScore{
			id:             groupID,
			name:           group.Name,
			techniqueScore: techScore,
			iocScore:       iocScore,
			combinedScore:  combinedScore,
			overlapTechs:   overlapTechs,
			evidence:       evidence,
		})
	}

	for actorID, actor := range m.threatActors {
		techScore, overlapTechs := m.calculateTechniqueOverlap(observedTechs, actor.Techniques)

		iocScore := 0.0
		if s, ok := iocActorScores[actorID]; ok {
			iocScore = s
		}
		for _, alias := range actor.Aliases {
			if s, ok := iocActorScores[alias]; ok {
				iocScore = math.Max(iocScore, s)
			}
		}

		combinedScore := techScore*0.6 + iocScore*0.4
		if iocScore > 0 && techScore > 0 {
			combinedScore = math.Min(combinedScore+0.1, 1.0)
		}

		if combinedScore < 0.1 {
			continue
		}

		var evidence []AttributionEvidence
		if len(overlapTechs) > 0 {
			evidence = append(evidence, AttributionEvidence{
				Type:        "ttp_overlap",
				Description: fmt.Sprintf("Overlaps %d techniques with %s (%s)", len(overlapTechs), actor.Name, actorID),
				Weight:      techScore,
				Source:      "attck_attribution",
			})
		}

		if iocScore > 0 {
			evidence = append(evidence, AttributionEvidence{
				Type:        "ioc_match",
				Description: fmt.Sprintf("IOC evidence links to %s (score=%.2f)", actor.Name, iocScore),
				Weight:      iocScore,
				Source:      "attck_attribution",
			})
		}

		candidates = append(candidates, actorScore{
			id:             actorID,
			name:           actor.Name,
			techniqueScore: techScore,
			iocScore:       iocScore,
			combinedScore:  combinedScore,
			overlapTechs:   overlapTechs,
			evidence:       evidence,
			country:        actor.Country,
			motivation:     actor.Motivation,
		})
	}

	if len(candidates) == 0 {
		return &AttributionResult{
			PrimaryActor: "Unknown",
			Confidence:   0,
			Methodology:  "multi_source_fusion",
			Evidence: []AttributionEvidence{
				{
					Type:        "no_match",
					Description: "No APT group or threat actor matches observed techniques and IOCs",
					Weight:      0,
					Source:      "attck_attribution",
				},
			},
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].combinedScore > candidates[j].combinedScore
	})

	primary := candidates[0]
	confidence := m.normalizeAttributionConfidence(primary.combinedScore, len(primary.overlapTechs), len(primary.evidence))

	var alternativeActors []AlternativeActor
	for i := 1; i < len(candidates) && i < 5; i++ {
		alt := candidates[i]
		if alt.combinedScore < 0.15 {
			continue
		}
		alternativeActors = append(alternativeActors, AlternativeActor{
			GroupID:    alt.id,
			Name:       alt.name,
			Confidence: math.Round(alt.combinedScore*1000) / 1000,
			Reason:     fmt.Sprintf("TTP overlap: %d techniques, IOC score: %.2f", len(alt.overlapTechs), alt.iocScore),
		})
	}

	result := &AttributionResult{
		PrimaryActor:     primary.name,
		PrimaryGroupID:   primary.id,
		Confidence:       math.Round(confidence*1000) / 1000,
		Evidence:         primary.evidence,
		AlternativeActors: alternativeActors,
		Methodology:      "multi_source_fusion",
		Country:          primary.country,
		Motivation:       primary.motivation,
	}

	logger.WithComponent("attck.apt.attribution").Info("attribution performed",
		"primary_actor", primary.name, "confidence", result.Confidence,
		"technique_overlap", len(primary.overlapTechs), "alternatives", len(alternativeActors))

	return result
}

func (m *ATTACKModule) calculateTechniqueOverlap(observed map[string]float64, actorTechs map[string]float64) (float64, []string) {
	var overlapTechs []string
	var weightedOverlap float64
	var weightedTotal float64

	for tech, actorWeight := range actorTechs {
		weightedTotal += actorWeight
		if obsWeight, ok := observed[tech]; ok {
			overlapTechs = append(overlapTechs, tech)
			weightedOverlap += actorWeight * obsWeight
		}
	}

	if weightedTotal == 0 {
		return 0, nil
	}

	score := weightedOverlap / weightedTotal
	return math.Round(score*1000) / 1000, overlapTechs
}

func (m *ATTACKModule) checkSectorAlignment(stages []AttackStage, group *APTGroupProfile) float64 {
	if len(group.PrimaryTargets) == 0 {
		return 0
	}

	tacticDistribution := make(map[string]int)
	for _, s := range stages {
		tacticDistribution[s.TacticID]++
	}

	hasExfiltration := tacticDistribution["TA0010"] > 0 || tacticDistribution["TA0009"] > 0
	hasImpact := tacticDistribution["TA0040"] > 0
	hasRecon := tacticDistribution["TA0043"] > 0 || tacticDistribution["TA0042"] > 0

	alignmentScore := 0.0

	for _, target := range group.PrimaryTargets {
		switch target {
		case "financial", "cryptocurrency":
			if hasExfiltration && hasImpact {
				alignmentScore += 0.5
			}
		case "government", "military", "diplomatic":
			if hasRecon && hasExfiltration && !hasImpact {
				alignmentScore += 0.5
			}
		case "retail", "hospitality":
			if hasExfiltration {
				alignmentScore += 0.3
			}
		case "healthcare", "telecom":
			if hasRecon {
				alignmentScore += 0.3
			}
		default:
			if hasExfiltration {
				alignmentScore += 0.2
			}
		}
	}

	if len(group.PrimaryTargets) > 0 {
		alignmentScore /= float64(len(group.PrimaryTargets))
	}

	return math.Min(alignmentScore, 1.0)
}

func (m *ATTACKModule) normalizeAttributionConfidence(rawScore float64, overlapCount int, evidenceCount int) float64 {
	confidence := rawScore

	if overlapCount >= 5 {
		confidence = math.Min(confidence+0.1, 1.0)
	} else if overlapCount >= 3 {
		confidence = math.Min(confidence+0.05, 1.0)
	}

	if evidenceCount >= 3 {
		confidence = math.Min(confidence+0.05, 1.0)
	}

	confidence = math.Max(confidence, 0.1)

	return confidence
}

func (m *ATTACKModule) PerformAttribution(chainID string) (*AttributionResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var chain *AttackChain
	for i := range m.attackChains {
		if m.attackChains[i].ID == chainID {
			chain = &m.attackChains[i]
			break
		}
	}

	if chain == nil {
		return nil, fmt.Errorf("attack chain not found: %s", chainID)
	}

	var relevantIOCs []IOCEntry
	for _, ioc := range m.iocs {
		relevantIOCs = append(relevantIOCs, ioc)
	}

	result := m.performAttribution(chain.Stages, relevantIOCs)

	if result != nil {
		chain.Attribution = result
		logger.WithComponent("attck.apt.attribution").Info("attribution performed for chain",
			"chain_id", chainID, "primary_actor", result.PrimaryActor, "confidence", result.Confidence)
	}

	return result, nil
}

func (m *ATTACKModule) GenerateAPTAnalysisReport(hostIDs []string) (*APTAnalysisReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(hostIDs) == 0 {
		return nil, fmt.Errorf("at least one host ID is required")
	}

	hostSet := make(map[string]bool)
	for _, h := range hostIDs {
		hostSet[h] = true
	}

	var chains []AttackChain
	for _, c := range m.attackChains {
		for _, h := range c.HostIDs {
			if hostSet[h] {
				chains = append(chains, c)
				break
			}
		}
	}

	var attributions []AttributionResult
	for _, c := range chains {
		if c.Attribution != nil {
			attributions = append(attributions, *c.Attribution)
		}
	}

	var bAlerts []BehavioralAlert
	for _, a := range m.behavioralAlerts {
		if hostSet[a.HostID] {
			bAlerts = append(bAlerts, a)
		}
	}

	var beacons []BeaconDetection
	for _, d := range m.beaconDetections {
		if hostSet[d.HostID] {
			beacons = append(beacons, d)
		}
	}

	var hResults []HuntResult
	for _, r := range m.huntResults {
		if hostSet[r.HostID] {
			hResults = append(hResults, r)
		}
	}

	riskScore := m.calculateAPTRiskScore(chains, bAlerts, beacons, hResults)
	riskLevel := "low"
	switch {
	case riskScore >= 0.8:
		riskLevel = "critical"
	case riskScore >= 0.6:
		riskLevel = "high"
	case riskScore >= 0.4:
		riskLevel = "medium"
	}

	summary := m.generateAPTSummary(chains, attributions, bAlerts, beacons, riskScore)
	recommendations := m.generateAPTRecommendations(chains, attributions, bAlerts, beacons)

	report := &APTAnalysisReport{
		ID:               fmt.Sprintf("apt-report-%d", time.Now().UnixNano()),
		HostIDs:          hostIDs,
		AttackChains:     chains,
		Attributions:     attributions,
		BehavioralAlerts: bAlerts,
		BeaconDetections: beacons,
		HuntResults:      hResults,
		RiskScore:        math.Round(riskScore*1000) / 1000,
		RiskLevel:        riskLevel,
		Summary:          summary,
		Recommendations:  recommendations,
		Timestamp:        time.Now(),
	}

	m.kernel.Bus().Publish(m.kernel.Context(), Message{
		Topic:   "attck.apt.report_generated",
		Payload: report,
		Source:  "attck.apt",
	})

	logger.WithComponent("attck.apt").Info("APT analysis report generated",
		"hosts", len(hostIDs), "chains", len(chains), "risk_score", report.RiskScore, "risk_level", riskLevel)

	return report, nil
}

func (m *ATTACKModule) calculateAPTRiskScore(chains []AttackChain, alerts []BehavioralAlert, beacons []BeaconDetection, hunts []HuntResult) float64 {
	score := 0.0

	for _, c := range chains {
		chainWeight := 0.0
		switch c.Severity {
		case "critical":
			chainWeight = 0.4
		case "high":
			chainWeight = 0.3
		case "medium":
			chainWeight = 0.2
		default:
			chainWeight = 0.1
		}
		score += chainWeight * c.TotalScore
	}

	criticalAlerts := 0
	highAlerts := 0
	for _, a := range alerts {
		switch a.Severity {
		case "critical":
			criticalAlerts++
		case "high":
			highAlerts++
		}
	}
	alertScore := math.Min(float64(criticalAlerts)*0.1+float64(highAlerts)*0.05, 0.3)
	score += alertScore

	for _, b := range beacons {
		score += b.Score * 0.1
	}

	confirmedHunts := 0
	for _, h := range hunts {
		if h.Confirmed {
			confirmedHunts++
		}
	}
	score += math.Min(float64(confirmedHunts)*0.05, 0.2)

	return math.Min(score, 1.0)
}

func (m *ATTACKModule) generateAPTSummary(chains []AttackChain, attributions []AttributionResult, alerts []BehavioralAlert, beacons []BeaconDetection, riskScore float64) string {
	summary := fmt.Sprintf("APT Analysis: risk_score=%.2f, %d attack chains, %d behavioral alerts, %d beacon detections",
		riskScore, len(chains), len(alerts), len(beacons))

	if len(attributions) > 0 {
		primary := attributions[0]
		summary += fmt.Sprintf(". Primary attribution: %s (confidence=%.2f)", primary.PrimaryActor, primary.Confidence)
	}

	return summary
}

func (m *ATTACKModule) generateAPTRecommendations(chains []AttackChain, attributions []AttributionResult, alerts []BehavioralAlert, beacons []BeaconDetection) []string {
	var recs []string
	seen := make(map[string]bool)

	addRec := func(r string) {
		if !seen[r] {
			seen[r] = true
			recs = append(recs, r)
		}
	}

	for _, c := range chains {
		for _, s := range c.Stages {
			tacticName := s.TacticName
			if tacticName == "" {
				tacticName = s.TacticID
			}
			addRec(fmt.Sprintf("加固 %s 阶段: 检测到 %s (%s), 置信度=%.2f", tacticName, s.TechniqueID, s.TechniqueName, s.Confidence))
		}
	}

	for _, a := range attributions {
		if a.Confidence >= 0.5 {
			addRec(fmt.Sprintf("重点防范 %s 组织: 参考其已知 TTP 调整防御策略", a.PrimaryActor))
		}
	}

	criticalAlertCount := 0
	for _, a := range alerts {
		if a.Severity == "critical" || a.Severity == "high" {
			criticalAlertCount++
		}
	}
	if criticalAlertCount > 0 {
		addRec(fmt.Sprintf("立即处理 %d 条高严重性行为告警", criticalAlertCount))
	}

	for _, b := range beacons {
		if b.Score >= 0.7 {
			addRec(fmt.Sprintf("调查 C2 信标行为: 主机 %s 到 %s (间隔=%.1fs, 抖动=%.3f)", b.HostID, b.Destination, b.Interval, b.Jitter))
		}
	}

	return recs
}
