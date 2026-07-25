//go:build attck_ext

package kernel

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

var tacticOrderMap = map[string]int{
	"TA0043": 0, "TA0042": 1, "TA0001": 2, "TA0002": 3,
	"TA0003": 4, "TA0004": 5, "TA0005": 6, "TA0006": 7,
	"TA0007": 8, "TA0008": 9, "TA0009": 10, "TA0011": 11,
	"TA0010": 12, "TA0040": 13,
}

func (m *ATTACKModule) ReconstructAttackChain(hostIDs []string) (*AttackChain, error) {
	m.mu.Lock()

	if len(hostIDs) == 0 {
		m.mu.Unlock()
		return nil, fmt.Errorf("at least one host ID is required")
	}

	hostSet := make(map[string]bool)
	for _, h := range hostIDs {
		hostSet[h] = true
	}

	var relevantAlerts []DetectionAlert
	var relevantAnomalies []AnomalyEvent
	var relevantIOCs []IOCEntry

	for _, a := range m.alerts {
		if hostSet[a.HostID] && !a.Acknowledged {
			relevantAlerts = append(relevantAlerts, a)
		}
	}
	for _, a := range m.anomalies {
		if hostSet[a.HostID] && a.Score >= 0.5 {
			relevantAnomalies = append(relevantAnomalies, a)
		}
	}
	for _, ioc := range m.iocs {
		relevantIOCs = append(relevantIOCs, ioc)
	}

	if len(relevantAlerts) == 0 && len(relevantAnomalies) == 0 {
		m.mu.Unlock()
		return nil, fmt.Errorf("no unacknowledged alerts or high-score anomalies found for specified hosts")
	}

	stages := m.buildAttackStages(relevantAlerts, relevantAnomalies, relevantIOCs)

	if len(stages) == 0 {
		m.mu.Unlock()
		return nil, fmt.Errorf("could not reconstruct any attack stages from available evidence")
	}

	chain := &AttackChain{
		ID:         fmt.Sprintf("chain-%d", time.Now().UnixNano()),
		Name:       m.generateChainName(stages),
		HostIDs:    hostIDs,
		Stages:     stages,
		Severity:   m.calculateChainSeverity(stages),
		Status:     "active",
		DetectedAt: time.Now(),
	}

	chain.TotalScore = m.calculateChainScore(stages)

	if len(stages) > 0 {
		chain.FirstSeen = stages[0].Timestamp
		chain.LastSeen = stages[len(stages)-1].Timestamp
	}

	attribution := m.performAttribution(stages, relevantIOCs)
	if attribution != nil {
		chain.Attribution = attribution
	}

	m.attackChains = append(m.attackChains, *chain)
	m.attackChains = trimSlice(m.attackChains, maxAttackChains)
	m.mu.Unlock()

	m.kernel.Bus().Publish(m.kernel.Context(), Message{
		Topic:   "attck.apt.chain_detected",
		Payload: chain,
		Source:  "attck.apt",
	})
	if m.kernel != nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "attck.apt.chain_detected", chain)
	}

	logger.WithComponent("attck.apt").Info("attack chain reconstructed",
		"chain_id", chain.ID, "stages", len(stages), "severity", chain.Severity,
		"hosts", len(hostIDs))

	return chain, nil
}

func (m *ATTACKModule) buildAttackStages(alerts []DetectionAlert, anomalies []AnomalyEvent, iocs []IOCEntry) []AttackStage {
	type stageCandidate struct {
		tacticID     string
		tacticName   string
		techniqueID  string
		techniqueName string
		alertIDs     []string
		anomalyIDs   []string
		iocIDs       []string
		hostIDs      []string
		evidence     []string
		confidence   float64
		timestamp    time.Time
	}

	candidates := make(map[string]*stageCandidate)

	for _, a := range alerts {
		key := a.TechniqueID
		if _, ok := candidates[key]; !ok {
			tacticName := m.getTacticNameLocked(a.TacticIDs[0])
			candidates[key] = &stageCandidate{
				tacticID:      a.TacticIDs[0],
				tacticName:    tacticName,
				techniqueID:   a.TechniqueID,
				techniqueName: a.RuleName,
				confidence:    0.7,
				timestamp:     a.Timestamp,
			}
		}
		c := candidates[key]
		c.alertIDs = append(c.alertIDs, a.ID)
		c.hostIDs = append(c.hostIDs, a.HostID)
		c.evidence = append(c.evidence, fmt.Sprintf("Alert %s: %s", a.ID, a.Description))
		if a.Timestamp.Before(c.timestamp) {
			c.timestamp = a.Timestamp
		}
	}

	for _, a := range anomalies {
		if a.TechniqueID == "" {
			continue
		}
		key := a.TechniqueID
		if _, ok := candidates[key]; !ok {
			tacticID := m.getTacticForTechniqueLocked(a.TechniqueID)
			tacticName := m.getTacticNameLocked(tacticID)
			candidates[key] = &stageCandidate{
				tacticID:      tacticID,
				tacticName:    tacticName,
				techniqueID:   a.TechniqueID,
				techniqueName: a.EventType,
				confidence:    a.Score * 0.6,
				timestamp:     a.Timestamp,
			}
		}
		c := candidates[key]
		c.anomalyIDs = append(c.anomalyIDs, a.ID)
		c.hostIDs = append(c.hostIDs, a.HostID)
		c.evidence = append(c.evidence, fmt.Sprintf("Anomaly %s: %s (score=%.2f)", a.ID, a.Description, a.Score))
		c.confidence = math.Min(c.confidence+a.Score*0.2, 1.0)
	}

	for _, ioc := range iocs {
		for _, techID := range ioc.TechniqueIDs {
			if c, ok := candidates[techID]; ok {
				c.iocIDs = append(c.iocIDs, ioc.ID)
				c.evidence = append(c.evidence, fmt.Sprintf("IOC %s: %s=%s (confidence=%.2f)", ioc.ID, ioc.Type, ioc.Value, ioc.Confidence))
				c.confidence = math.Min(c.confidence+ioc.Confidence*0.15, 1.0)
			}
		}
	}

	var stages []AttackStage
	for _, c := range candidates {
		hostIDs := uniqueStrings(c.hostIDs)
		stage := AttackStage{
			TacticID:      c.tacticID,
			TacticName:    c.tacticName,
			TechniqueID:   c.techniqueID,
			TechniqueName: c.techniqueName,
			AlertIDs:      c.alertIDs,
			HostIDs:       hostIDs,
			IOCIDs:        c.iocIDs,
			AnomalyIDs:    c.anomalyIDs,
			Confidence:    math.Round(c.confidence*1000) / 1000,
			Evidence:      c.evidence,
			Timestamp:     c.timestamp,
		}
		stages = append(stages, stage)
	}

	sort.Slice(stages, func(i, j int) bool {
		orderI, okI := tacticOrderMap[stages[i].TacticID]
		orderJ, okJ := tacticOrderMap[stages[j].TacticID]
		if !okI {
			orderI = 99
		}
		if !okJ {
			orderJ = 99
		}
		if orderI != orderJ {
			return orderI < orderJ
		}
		return stages[i].Timestamp.Before(stages[j].Timestamp)
	})

	stages = m.applyCausalReasoning(stages)

	return stages
}

func (m *ATTACKModule) generateChainName(stages []AttackStage) string {
	if len(stages) == 0 {
		return "Empty Attack Chain"
	}

	first := stages[0]
	last := stages[len(stages)-1]

	if len(stages) == 1 {
		return fmt.Sprintf("Single-stage: %s (%s)", first.TechniqueID, first.TacticName)
	}

	return fmt.Sprintf("Multi-stage: %s → %s (%d stages)", first.TacticName, last.TacticName, len(stages))
}

func (m *ATTACKModule) calculateChainSeverity(stages []AttackStage) string {
	criticalCount := 0
	highCount := 0
	for _, s := range stages {
		if s.Confidence >= 0.8 {
			criticalCount++
		} else if s.Confidence >= 0.6 {
			highCount++
		}
	}

	switch {
	case criticalCount >= 3 || len(stages) >= 6:
		return "critical"
	case criticalCount >= 1 || highCount >= 3:
		return "high"
	case highCount >= 1 || len(stages) >= 3:
		return "medium"
	default:
		return "low"
	}
}

func (m *ATTACKModule) calculateChainScore(stages []AttackStage) float64 {
	if len(stages) == 0 {
		return 0
	}

	var sum float64
	for _, s := range stages {
		stageWeight := 1.0
		if order, ok := tacticOrderMap[s.TacticID]; ok {
			switch {
			case order <= 2:
				stageWeight = 0.7
			case order <= 6:
				stageWeight = 1.0
			case order <= 10:
				stageWeight = 1.2
			default:
				stageWeight = 1.5
			}
		}
		sum += s.Confidence * stageWeight
	}

	score := sum / float64(len(stages))
	return math.Round(score*1000) / 1000
}

func (m *ATTACKModule) GetAttackChains(hostID string, limit int) []AttackChain {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []AttackChain
	for i := len(m.attackChains) - 1; i >= 0; i-- {
		c := m.attackChains[i]
		if hostID != "" {
			found := false
			for _, h := range c.HostIDs {
				if h == hostID {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		result = append(result, c)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

func (m *ATTACKModule) CorrelateMultiIndicator(hostIDs []string) []MultiIndicatorCorrelation {
	m.mu.Lock()
	defer m.mu.Unlock()

	hostSet := make(map[string]bool)
	for _, h := range hostIDs {
		hostSet[h] = true
	}

	var correlations []MultiIndicatorCorrelation

	alertByTech := make(map[string][]DetectionAlert)
	for _, a := range m.alerts {
		if len(hostIDs) == 0 || hostSet[a.HostID] {
			alertByTech[a.TechniqueID] = append(alertByTech[a.TechniqueID], a)
		}
	}

	anomalyByTech := make(map[string][]AnomalyEvent)
	for _, a := range m.anomalies {
		if a.TechniqueID != "" && (len(hostIDs) == 0 || hostSet[a.HostID]) && a.Score >= 0.5 {
			anomalyByTech[a.TechniqueID] = append(anomalyByTech[a.TechniqueID], a)
		}
	}

	iocByTech := make(map[string][]IOCEntry)
	for _, ioc := range m.iocs {
		for _, techID := range ioc.TechniqueIDs {
			iocByTech[techID] = append(iocByTech[techID], ioc)
		}
	}

	allTechIDs := make(map[string]bool)
	for t := range alertByTech {
		allTechIDs[t] = true
	}
	for t := range anomalyByTech {
		allTechIDs[t] = true
	}
	for t := range iocByTech {
		allTechIDs[t] = true
	}

	for techID := range allTechIDs {
		alerts := alertByTech[techID]
		anomalies := anomalyByTech[techID]
		iocs := iocByTech[techID]

		sourceCount := 0
		if len(alerts) > 0 {
			sourceCount++
		}
		if len(anomalies) > 0 {
			sourceCount++
		}
		if len(iocs) > 0 {
			sourceCount++
		}

		if sourceCount < 2 {
			continue
		}

		var indicatorIDs []string
		var hostIDs []string
		var tacticIDs []string
		var evidence []string

		for _, a := range alerts {
			indicatorIDs = append(indicatorIDs, "alert:"+a.ID)
			hostIDs = append(hostIDs, a.HostID)
			tacticIDs = append(tacticIDs, a.TacticIDs...)
			evidence = append(evidence, fmt.Sprintf("Alert: %s", a.Description))
		}
		for _, a := range anomalies {
			indicatorIDs = append(indicatorIDs, "anomaly:"+a.ID)
			hostIDs = append(hostIDs, a.HostID)
			evidence = append(evidence, fmt.Sprintf("Anomaly: %s (score=%.2f)", a.Description, a.Score))
		}
		for _, ioc := range iocs {
			indicatorIDs = append(indicatorIDs, "ioc:"+ioc.ID)
			evidence = append(evidence, fmt.Sprintf("IOC: %s=%s", ioc.Type, ioc.Value))
		}

		alertCount := len(alerts)
		anomalyCount := len(anomalies)
		iocCount := len(iocs)
		beaconCount := 0
		for _, d := range m.beaconDetections {
			if d.TechniqueID == techID && (len(hostIDs) == 0 || hostSet[d.HostID]) {
				beaconCount++
			}
		}

		score := math.Min(1.0, (float64(alertCount)*0.3+float64(anomalyCount)*0.2+float64(iocCount)*0.3+float64(beaconCount)*0.2)/2.0)

		tacticID := m.getTacticForTechniqueLocked(techID)
		tacticIDs = append(tacticIDs, tacticID)

		correlations = append(correlations, MultiIndicatorCorrelation{
			ID:              fmt.Sprintf("mic-%d", time.Now().UnixNano()),
			IndicatorIDs:    indicatorIDs,
			TechniqueIDs:    []string{techID},
			TacticIDs:       uniqueStrings(tacticIDs),
			HostIDs:         uniqueStrings(hostIDs),
			Score:           math.Round(score*1000) / 1000,
			Description:     fmt.Sprintf("Multi-source correlation for %s: %d alerts, %d anomalies, %d IOCs", techID, len(alerts), len(anomalies), len(iocs)),
			CorrelationType: "multi_source",
			Timestamp:       time.Now(),
		})
	}

	transitionCorrelations := m.correlateByTransitions(alertByTech, hostSet)
	correlations = append(correlations, transitionCorrelations...)

	sort.Slice(correlations, func(i, j int) bool {
		return correlations[i].Score > correlations[j].Score
	})

	return correlations
}

func (m *ATTACKModule) correlateByTransitions(alertByTech map[string][]DetectionAlert, hostSet map[string]bool) []MultiIndicatorCorrelation {
	var correlations []MultiIndicatorCorrelation

	for fromTech, fromAlerts := range alertByTech {
		transitions, ok := m.transMatrix[fromTech]
		if !ok {
			continue
		}

		for toTech, prob := range transitions {
			toAlerts, ok := alertByTech[toTech]
			if !ok || prob < 0.3 {
				continue
			}

			var commonHosts []string
			fromHosts := make(map[string]bool)
			for _, a := range fromAlerts {
				fromHosts[a.HostID] = true
			}
			for _, a := range toAlerts {
				if fromHosts[a.HostID] {
					commonHosts = append(commonHosts, a.HostID)
				}
			}

			if len(commonHosts) == 0 {
				continue
			}

			var indicatorIDs []string
			for _, a := range fromAlerts {
				indicatorIDs = append(indicatorIDs, "alert:"+a.ID)
			}
			for _, a := range toAlerts {
				indicatorIDs = append(indicatorIDs, "alert:"+a.ID)
			}

			correlations = append(correlations, MultiIndicatorCorrelation{
				ID:              fmt.Sprintf("mic-trans-%d", time.Now().UnixNano()),
				IndicatorIDs:    indicatorIDs,
				TechniqueIDs:    []string{fromTech, toTech},
				TacticIDs:       []string{m.getTacticForTechniqueLocked(fromTech), m.getTacticForTechniqueLocked(toTech)},
				HostIDs:         uniqueStrings(commonHosts),
				Score:           math.Round(prob*1000) / 1000,
				Description:     fmt.Sprintf("Transition correlation: %s → %s (probability=%.2f, %d shared hosts)", fromTech, toTech, prob, len(commonHosts)),
				CorrelationType: "transition",
				Timestamp:       time.Now(),
			})
		}
	}

	return correlations
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] && s != "" {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
