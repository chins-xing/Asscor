package kernel

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

func (m *ATTACKModule) CreateHuntHypothesis(hypothesis HuntHypothesis) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if hypothesis.ID == "" || hypothesis.Name == "" {
		return fmt.Errorf("hunt hypothesis ID and name must not be empty")
	}

	if hypothesis.TechniqueID == "" {
		return fmt.Errorf("hunt hypothesis must reference a technique ID")
	}

	if hypothesis.CreatedAt.IsZero() {
		hypothesis.CreatedAt = time.Now()
	}

	if hypothesis.Status == "" {
		hypothesis.Status = "active"
	}

	if hypothesis.Priority == "" {
		hypothesis.Priority = "medium"
	}

	for i, h := range m.huntHypotheses {
		if h.ID == hypothesis.ID {
			m.huntHypotheses[i] = hypothesis
			logger.WithComponent("attck.hunt").Info("updated hunt hypothesis", "id", hypothesis.ID, "technique", hypothesis.TechniqueID)
			return nil
		}
	}

	m.huntHypotheses = append(m.huntHypotheses, hypothesis)
	logger.WithComponent("attck.hunt").Info("created hunt hypothesis", "id", hypothesis.ID, "technique", hypothesis.TechniqueID, "priority", hypothesis.Priority)
	return nil
}

func (m *ATTACKModule) GetHuntHypothesis(hypothesisID string) *HuntHypothesis {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, h := range m.huntHypotheses {
		if h.ID == hypothesisID {
			cp := h
			return &cp
		}
	}
	return nil
}

func (m *ATTACKModule) ListHuntHypotheses(techniqueID string, status string) []HuntHypothesis {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []HuntHypothesis
	for _, h := range m.huntHypotheses {
		if techniqueID != "" && h.TechniqueID != techniqueID {
			continue
		}
		if status != "" && h.Status != status {
			continue
		}
		result = append(result, h)
	}

	sort.Slice(result, func(i, j int) bool {
		priorityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
		pi, okI := priorityOrder[result[i].Priority]
		pj, okJ := priorityOrder[result[j].Priority]
		if !okI {
			pi = 4
		}
		if !okJ {
			pj = 4
		}
		if pi != pj {
			return pi < pj
		}
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})

	return result
}

func (m *ATTACKModule) DeleteHuntHypothesis(hypothesisID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, h := range m.huntHypotheses {
		if h.ID == hypothesisID {
			m.huntHypotheses = append(m.huntHypotheses[:i], m.huntHypotheses[i+1:]...)
			logger.WithComponent("attck.hunt").Info("deleted hunt hypothesis", "id", hypothesisID)
			return true
		}
	}
	return false
}

func (m *ATTACKModule) ExecuteHunt(hypothesisID string, hostID string) (*HuntResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var hypothesis *HuntHypothesis
	for i := range m.huntHypotheses {
		if m.huntHypotheses[i].ID == hypothesisID {
			hypothesis = &m.huntHypotheses[i]
			break
		}
	}

	if hypothesis == nil {
		return nil, fmt.Errorf("hunt hypothesis not found: %s", hypothesisID)
	}

	findings := m.executeHuntLogic(*hypothesis, hostID)

	confirmed := false
	confidence := 0.0
	if len(findings) > 0 {
		confirmed = true
		confidence = math.Min(float64(len(findings))*0.3, 1.0)
	}

	result := &HuntResult{
		ID:           fmt.Sprintf("hunt-result-%d", time.Now().UnixNano()),
		HypothesisID: hypothesisID,
		HostID:       hostID,
		Findings:     findings,
		Confirmed:    confirmed,
		Confidence:   math.Round(confidence*1000) / 1000,
		Timestamp:    time.Now(),
	}

	m.huntResults = append(m.huntResults, *result)

	for i, h := range m.huntHypotheses {
		if h.ID == hypothesisID {
			m.huntHypotheses[i].Status = "completed"
			break
		}
	}

	if confirmed {
		m.kernel.Bus().Publish(m.kernel.Context(), Message{
			Topic:   "attck.apt.hunt_confirmed",
			Payload: result,
			Source:  "attck.apt",
		})
	}

	logger.WithComponent("attck.hunt").Info("hunt executed",
		"hypothesis", hypothesisID, "host", hostID,
		"confirmed", confirmed, "confidence", result.Confidence, "findings", len(findings))

	return result, nil
}

func (m *ATTACKModule) executeHuntLogic(hypothesis HuntHypothesis, hostID string) []HuntFinding {
	var findings []HuntFinding

	for _, alert := range m.alerts {
		if alert.HostID != hostID || alert.Acknowledged {
			continue
		}
		if alert.TechniqueID == hypothesis.TechniqueID {
			findings = append(findings, HuntFinding{
				Description: fmt.Sprintf("Detection alert matches hypothesis: %s", alert.Description),
				TechniqueID: alert.TechniqueID,
				Evidence:    fmt.Sprintf("Alert %s at %v", alert.ID, alert.Timestamp),
				Fields:      alert.Fields,
			})
		}
	}

	for _, anomaly := range m.anomalies {
		if anomaly.HostID != hostID || anomaly.Score < 0.5 {
			continue
		}
		if anomaly.TechniqueID == hypothesis.TechniqueID {
			findings = append(findings, HuntFinding{
				Description: fmt.Sprintf("Anomaly matches hypothesis: %s (score=%.2f)", anomaly.Description, anomaly.Score),
				TechniqueID: anomaly.TechniqueID,
				Evidence:    fmt.Sprintf("Anomaly %s at %v, deviation=%.2f", anomaly.ID, anomaly.Timestamp, anomaly.Deviation),
			})
		}
	}

	for _, bAlert := range m.behavioralAlerts {
		if bAlert.HostID != hostID {
			continue
		}
		if bAlert.TechniqueID == hypothesis.TechniqueID {
			findings = append(findings, HuntFinding{
				Description: fmt.Sprintf("Behavioral alert matches hypothesis: %s (deviation=%.2f)", bAlert.IndicatorName, bAlert.Deviation),
				TechniqueID: bAlert.TechniqueID,
				Evidence:    fmt.Sprintf("Observed=%.2f, Baseline=%.2f", bAlert.ObservedValue, bAlert.BaselineValue),
			})
		}
	}

	for _, ioc := range m.iocs {
		matched := false
		for _, techID := range ioc.TechniqueIDs {
			if techID == hypothesis.TechniqueID {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		findings = append(findings, HuntFinding{
			Description: fmt.Sprintf("IOC matches hypothesis: %s=%s (confidence=%.2f)", ioc.Type, ioc.Value, ioc.Confidence),
			TechniqueID: hypothesis.TechniqueID,
			Evidence:    fmt.Sprintf("IOC %s from %s", ioc.ID, ioc.Source),
		})
	}

	for _, beacon := range m.beaconDetections {
		if beacon.HostID != hostID {
			continue
		}
		if beacon.TechniqueID == hypothesis.TechniqueID || hypothesis.TechniqueID == "T1071" {
			findings = append(findings, HuntFinding{
				Description: fmt.Sprintf("Beaconing detected: interval=%.1fs, jitter=%.3f, score=%.2f", beacon.Interval, beacon.Jitter, beacon.Score),
				TechniqueID: beacon.TechniqueID,
				Evidence:    fmt.Sprintf("Beacon %s, %d data points", beacon.ID, beacon.DataPoints),
			})
		}
	}

	return findings
}

func (m *ATTACKModule) GetHuntResults(hostID string, limit int) []HuntResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []HuntResult
	for i := len(m.huntResults) - 1; i >= 0; i-- {
		r := m.huntResults[i]
		if hostID != "" && r.HostID != hostID {
			continue
		}
		result = append(result, r)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

func (m *ATTACKModule) AutoGenerateHypotheses(hostID string) ([]HuntHypothesis, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var hypotheses []HuntHypothesis

	hostAlertTechs := make(map[string]int)
	for _, a := range m.alerts {
		if a.HostID == hostID && !a.Acknowledged {
			hostAlertTechs[a.TechniqueID]++
		}
	}

	hostAnomalyTechs := make(map[string]int)
	for _, a := range m.anomalies {
		if a.HostID == hostID && a.Score >= 0.5 && a.TechniqueID != "" {
			hostAnomalyTechs[a.TechniqueID]++
		}
	}

	for techID := range hostAlertTechs {
		nextTechs := m.predictNextTechniques(techID)
		for _, nextTech := range nextTechs {
			hypothesis := HuntHypothesis{
				ID:          fmt.Sprintf("hunt-auto-%s-%s-%d", hostID, nextTech, time.Now().UnixNano()),
				Name:        fmt.Sprintf("Auto-generated: predict %s after %s on %s", nextTech, techID, hostID),
				Description: fmt.Sprintf("Based on observed technique %s, predict adversary may use %s next", techID, nextTech),
				TechniqueID: nextTech,
				TacticIDs:   []string{m.getTacticForTechnique(nextTech)},
				DataSource:  "transition_prediction",
				Query:       fmt.Sprintf("technique:%s AND host:%s", nextTech, hostID),
				Priority:    "high",
				Status:      "active",
				CreatedAt:   time.Now(),
			}
			hypotheses = append(hypotheses, hypothesis)
		}
	}

	for techID := range hostAnomalyTechs {
		hypothesis := HuntHypothesis{
			ID:          fmt.Sprintf("hunt-anomaly-%s-%s-%d", hostID, techID, time.Now().UnixNano()),
			Name:        fmt.Sprintf("Anomaly-driven: investigate %s on %s", techID, hostID),
			Description: fmt.Sprintf("Anomalous behavior detected for technique %s, investigate further", techID),
			TechniqueID: techID,
			TacticIDs:   []string{m.getTacticForTechnique(techID)},
			DataSource:  "anomaly_driven",
			Query:       fmt.Sprintf("anomaly:%s AND host:%s", techID, hostID),
			Priority:    "medium",
			Status:      "active",
			CreatedAt:   time.Now(),
		}
		hypotheses = append(hypotheses, hypothesis)
	}

	beaconHypotheses := m.generateBeaconHypotheses(hostID)
	hypotheses = append(hypotheses, beaconHypotheses...)

	existingSet := make(map[string]bool)
	for _, h := range m.huntHypotheses {
		existingSet[h.TechniqueID+"|"+h.DataSource] = true
	}

	var newHypotheses []HuntHypothesis
	for _, h := range hypotheses {
		key := h.TechniqueID + "|" + h.DataSource
		if !existingSet[key] {
			newHypotheses = append(newHypotheses, h)
			m.huntHypotheses = append(m.huntHypotheses, h)
			existingSet[key] = true
		}
	}

	logger.WithComponent("attck.hunt").Info("auto-generated hunt hypotheses",
		"host", hostID, "total", len(hypotheses), "new", len(newHypotheses))

	return newHypotheses, nil
}

func (m *ATTACKModule) predictNextTechniques(techID string) []string {
	transitions, ok := m.transMatrix[techID]
	if !ok {
		return nil
	}

	type techProb struct {
		id   string
		prob float64
	}

	var candidates []techProb
	for nextTech, prob := range transitions {
		if prob >= 0.3 {
			candidates = append(candidates, techProb{nextTech, prob})
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].prob > candidates[j].prob
	})

	var result []string
	for i, c := range candidates {
		if i >= 3 {
			break
		}
		result = append(result, c.id)
	}

	return result
}

func (m *ATTACKModule) generateBeaconHypotheses(hostID string) []HuntHypothesis {
	var hypotheses []HuntHypothesis

	for _, beacon := range m.beaconDetections {
		if beacon.HostID != hostID {
			continue
		}
		if beacon.Score < 0.5 {
			continue
		}

		hypothesis := HuntHypothesis{
			ID:          fmt.Sprintf("hunt-beacon-%s-%d", hostID, time.Now().UnixNano()),
			Name:        fmt.Sprintf("Beacon-driven: investigate C2 channel on %s", hostID),
			Description: fmt.Sprintf("Beaconing detected to %s (interval=%.1fs, jitter=%.3f), investigate C2 infrastructure", beacon.Destination, beacon.Interval, beacon.Jitter),
			TechniqueID: "T1071",
			TacticIDs:   []string{"TA0011"},
			DataSource:  "beacon_detection",
			Query:       fmt.Sprintf("destination:%s AND host:%s", beacon.Destination, hostID),
			Priority:    "critical",
			Status:      "active",
			CreatedAt:   time.Now(),
		}
		hypotheses = append(hypotheses, hypothesis)
	}

	return hypotheses
}

func (m *ATTACKModule) GetAPTAnalysisReports(hostID string, limit int) []APTAnalysisReport {
	m.mu.RLock()
	chains := m.attackChains
	alerts := m.behavioralAlerts
	beacons := m.beaconDetections
	hunts := m.huntResults
	m.mu.RUnlock()

	if len(chains) == 0 && len(alerts) == 0 && len(beacons) == 0 {
		return nil
	}

	hostSet := map[string]bool{}
	if hostID != "" {
		hostSet[hostID] = true
	}

	var reports []APTAnalysisReport

	if hostID != "" {
		report, err := m.GenerateAPTAnalysisReport([]string{hostID})
		if err == nil && report != nil {
			reports = append(reports, *report)
		}
	} else {
		allHosts := map[string]bool{}
		for _, c := range chains {
			for _, h := range c.HostIDs {
				allHosts[h] = true
			}
		}
		for _, a := range alerts {
			allHosts[a.HostID] = true
		}
		for _, b := range beacons {
			allHosts[b.HostID] = true
		}
		for _, h := range hunts {
			allHosts[h.HostID] = true
		}

		for h := range allHosts {
			report, err := m.GenerateAPTAnalysisReport([]string{h})
			if err == nil && report != nil {
				reports = append(reports, *report)
			}
		}
	}

	if limit > 0 && len(reports) > limit {
		reports = reports[:limit]
	}

	return reports
}
