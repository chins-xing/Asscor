//go:build attck_ext

package attck

import (
	"fmt"
	"github.com/asscor/asscor/internal/kernel"
	"math"
	"sort"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

func (m *Module) PerformGapAnalysis(hostID string) (*AssessmentReport, error) {
	m.mu.Lock()

	report := &AssessmentReport{
		ID:             fmt.Sprintf("assess-%d", time.Now().UnixNano()),
		HostID:         hostID,
		Framework:      "MITRE ATT&CK",
		Version:        m.attckVersion,
		AssessmentTime: time.Now(),
	}

	totalTechs := 0
	coveredTechs := 0

	for _, tactic := range m.tactics {
		for _, tech := range tactic.Techniques {
			totalTechs++

			mapping := ControlMapping{
				TechniqueID:   tech.ID,
				TechniqueName: tech.Name,
				TacticID:      tactic.ID,
				AsscorChecks:  tech.AsscorChecks,
			}

			for _, r := range m.detectionRules {
				if r.TechniqueID == tech.ID && r.Enabled {
					mapping.DetectionRules = append(mapping.DetectionRules, r.ID)
				}
			}

			mapping.Mitigations = m.getMitigationsForTechnique(tech.ID)

			hasCheck := len(tech.AsscorChecks) > 0
			hasDetection := len(mapping.DetectionRules) > 0
			hasMitigation := len(mapping.Mitigations) > 0

			coverageScore := 0.0
			if hasCheck {
				coverageScore += 0.4
			}
			if hasDetection {
				coverageScore += 0.35
			}
			if hasMitigation {
				coverageScore += 0.25
			}
			mapping.Score = math.Round(coverageScore*100) / 100

			switch {
			case coverageScore >= 0.75:
				mapping.CoverageLevel = "full"
			case coverageScore >= 0.5:
				mapping.CoverageLevel = "partial"
			case coverageScore > 0:
				mapping.CoverageLevel = "minimal"
			default:
				mapping.CoverageLevel = "none"
			}

			if coverageScore > 0 {
				coveredTechs++
			}

			if coverageScore < 0.75 {
				gap := ControlGap{
					TechniqueID:   tech.ID,
					TechniqueName: tech.Name,
					TacticID:      tactic.ID,
					TacticName:    tactic.Name,
					Score:         coverageScore,
				}

				switch {
				case !hasCheck && !hasDetection && !hasMitigation:
					gap.GapType = "no_coverage"
					gap.Severity = "critical"
					gap.Description = fmt.Sprintf("No controls, detections, or mitigations for %s", tech.ID)
					gap.DesiredState = "Implement at least one control or detection"
				case !hasDetection:
					gap.GapType = "detection_gap"
					gap.Severity = "high"
					gap.Description = fmt.Sprintf("No detection rules for %s", tech.ID)
					gap.CurrentState = fmt.Sprintf("%d ASSCOR checks, %d mitigations", len(tech.AsscorChecks), len(mapping.Mitigations))
					gap.DesiredState = "Add detection rule"
				case !hasCheck:
					gap.GapType = "control_gap"
					gap.Severity = "medium"
					gap.Description = fmt.Sprintf("No ASSCOR security checks for %s", tech.ID)
					gap.CurrentState = fmt.Sprintf("%d detection rules, %d mitigations", len(mapping.DetectionRules), len(mapping.Mitigations))
					gap.DesiredState = "Implement security check"
				case !hasMitigation:
					gap.GapType = "mitigation_gap"
					gap.Severity = "low"
					gap.Description = fmt.Sprintf("No documented mitigations for %s", tech.ID)
					gap.DesiredState = "Document and implement mitigations"
				default:
					gap.GapType = "coverage_gap"
					gap.Severity = "low"
					gap.Description = fmt.Sprintf("Partial coverage for %s (score: %.2f)", tech.ID, coverageScore)
					gap.DesiredState = "Improve coverage to full (≥0.75)"
				}

				report.Gaps = append(report.Gaps, gap)
			}

			report.ControlMaps = append(report.ControlMaps, mapping)
		}
	}

	report.TotalTechniques = totalTechs
	report.CoveredTechs = coveredTechs
	if totalTechs > 0 {
		report.CoverageRate = math.Round(float64(coveredTechs)/float64(totalTechs)*1000) / 1000
	}

	report.Score = m.calculateAssessmentScore(report)

	report.Recommendations = m.generateAssessmentRecommendations(report)

	m.assessmentReports = append(m.assessmentReports, *report)
	if len(m.assessmentReports) > 1000 {
		m.assessmentReports = m.assessmentReports[len(m.assessmentReports)-1000:]
	}
	m.mu.Unlock()

	m.kc.Bus().Publish(m.kc.Context(), kernel.Message{
		Topic:   "attck.assessment.complete",
		Payload: report,
		Source:  "attck.assessment",
	})
	if m.kc != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "attck.assessment.complete", report)
	}

	logger.WithComponent("attck.assessment").Info("gap analysis completed",
		"host", hostID, "total", totalTechs, "covered", coveredTechs,
		"rate", report.CoverageRate, "score", report.Score)

	return report, nil
}

func (m *Module) calculateAssessmentScore(report *AssessmentReport) float64 {
	if len(report.ControlMaps) == 0 {
		return 0
	}

	var sum float64
	for _, cm := range report.ControlMaps {
		sum += cm.Score
	}

	score := sum / float64(len(report.ControlMaps))
	return math.Round(score*1000) / 1000
}

func (m *Module) getMitigationsForTechnique(techID string) []Mitigation {
	mitigationMap := map[string][]Mitigation{
		"T1566": {
			{ID: "M1049", Name: "Antivirus/Antimalware", Description: "Use anti-phishing features", Category: "detection", Effectiveness: 0.6},
			{ID: "M1017", Name: "User Training", Description: "Train users to identify phishing", Category: "prevention", Effectiveness: 0.7},
		},
		"T1190": {
			{ID: "M1050", Name: "Application Isolation", Description: "Isolate web-facing applications", Category: "prevention", Effectiveness: 0.7},
			{ID: "M1051", Name: "Update Software", Description: "Keep software patched", Category: "prevention", Effectiveness: 0.8},
		},
		"T1059": {
			{ID: "M1038", Name: "Execution Prevention", Description: "Block script execution where possible", Category: "prevention", Effectiveness: 0.6},
			{ID: "M1026", Name: "Privileged Account Management", Description: "Restrict script execution privileges", Category: "prevention", Effectiveness: 0.5},
		},
		"T1003": {
			{ID: "M1026", Name: "Privileged Account Management", Description: "Limit credential dumping opportunities", Category: "prevention", Effectiveness: 0.6},
			{ID: "M1015", Name: "Active Directory Configuration", Description: "Configure AD to limit credential access", Category: "prevention", Effectiveness: 0.5},
		},
		"T1021": {
			{ID: "M1035", Name: "Limit Access to Resource Over Network", Description: "Restrict network service access", Category: "prevention", Effectiveness: 0.7},
			{ID: "M1042", Name: "Disable or Remove Feature or Program", Description: "Disable unnecessary remote services", Category: "prevention", Effectiveness: 0.6},
		},
		"T1078": {
			{ID: "M1026", Name: "Privileged Account Management", Description: "Manage privileged accounts", Category: "prevention", Effectiveness: 0.7},
			{ID: "M1018", Name: "User Account Management", Description: "Manage user accounts and permissions", Category: "prevention", Effectiveness: 0.6},
		},
		"T1070": {
			{ID: "M1029", Name: "Remote Data Storage", Description: "Store logs remotely", Category: "prevention", Effectiveness: 0.8},
			{ID: "M1047", Name: "Audit", Description: "Audit log access and modifications", Category: "detection", Effectiveness: 0.7},
		},
		"T1486": {
			{ID: "M1053", Name: "Data Backup", Description: "Maintain offline backups", Category: "recovery", Effectiveness: 0.9},
			{ID: "M1040", Name: "Behavior Prevention on Endpoint", Description: "Prevent encryption behavior", Category: "prevention", Effectiveness: 0.5},
		},
		"T1053": {
			{ID: "M1026", Name: "Privileged Account Management", Description: "Restrict scheduled task creation", Category: "prevention", Effectiveness: 0.6},
			{ID: "M1018", Name: "User Account Management", Description: "Limit user ability to create scheduled tasks", Category: "prevention", Effectiveness: 0.5},
		},
		"T1548": {
			{ID: "M1026", Name: "Privileged Account Management", Description: "Manage sudo privileges", Category: "prevention", Effectiveness: 0.7},
			{ID: "M1036", Name: "OS Configuration", Description: "Configure OS to limit privilege escalation", Category: "prevention", Effectiveness: 0.6},
		},
		"T1048": {
			{ID: "M1037", Name: "Filter Network Traffic", Description: "Filter egress traffic", Category: "prevention", Effectiveness: 0.6},
			{ID: "M1057", Name: "Network Intrusion Prevention", Description: "Use NIPS to detect exfiltration", Category: "detection", Effectiveness: 0.5},
		},
		"T1071": {
			{ID: "M1031", Name: "Network Intrusion Prevention", Description: "Use NIPS to detect C2", Category: "detection", Effectiveness: 0.6},
			{ID: "M1037", Name: "Filter Network Traffic", Description: "Filter suspicious network traffic", Category: "prevention", Effectiveness: 0.5},
		},
	}

	if mitigs, ok := mitigationMap[techID]; ok {
		return mitigs
	}
	return nil
}

func (m *Module) generateAssessmentRecommendations(report *AssessmentReport) []Recommendation {
	var recs []Recommendation

	criticalGaps := make(map[string][]ControlGap)
	highGaps := make(map[string][]ControlGap)

	for _, gap := range report.Gaps {
		switch gap.Severity {
		case "critical":
			criticalGaps[gap.GapType] = append(criticalGaps[gap.GapType], gap)
		case "high":
			highGaps[gap.GapType] = append(highGaps[gap.GapType], gap)
		}
	}

	if len(criticalGaps["no_coverage"]) > 0 {
		var techIDs []string
		for _, g := range criticalGaps["no_coverage"] {
			techIDs = append(techIDs, g.TechniqueID)
		}
		recs = append(recs, Recommendation{
			ID:           fmt.Sprintf("rec-%d", len(recs)+1),
			Priority:     "critical",
			Category:     "no_coverage",
			Title:        "Address techniques with zero coverage",
			Description:  fmt.Sprintf("%d techniques have no controls, detections, or mitigations. These represent the highest risk gaps.", len(criticalGaps["no_coverage"])),
			TechniqueIDs: techIDs,
			Effort:       "high",
			Impact:       "critical",
			Status:       "open",
		})
	}

	if len(highGaps["detection_gap"]) > 0 {
		var techIDs []string
		for _, g := range highGaps["detection_gap"] {
			techIDs = append(techIDs, g.TechniqueID)
		}
		recs = append(recs, Recommendation{
			ID:           fmt.Sprintf("rec-%d", len(recs)+1),
			Priority:     "high",
			Category:     "detection_gap",
			Title:        "Implement missing detection rules",
			Description:  fmt.Sprintf("%d techniques lack detection rules. Adding these will significantly improve visibility.", len(highGaps["detection_gap"])),
			TechniqueIDs: techIDs,
			Effort:       "medium",
			Impact:       "high",
			Status:       "open",
		})
	}

	if report.CoverageRate < 0.5 {
		recs = append(recs, Recommendation{
			ID:          fmt.Sprintf("rec-%d", len(recs)+1),
			Priority:    "high",
			Category:    "overall_coverage",
			Title:       "Improve overall ATT&CK coverage",
			Description: fmt.Sprintf("Current coverage rate is %.1f%%. Target at least 50%% coverage for baseline security posture.", report.CoverageRate*100),
			Effort:      "high",
			Impact:      "high",
			Status:      "open",
		})
	}

	tacticCoverage := make(map[string]struct{ total, covered int })
	for _, cm := range report.ControlMaps {
		tc := tacticCoverage[cm.TacticID]
		tc.total++
		if cm.Score > 0 {
			tc.covered++
		}
		tacticCoverage[cm.TacticID] = tc
	}

	for tacticID, tc := range tacticCoverage {
		if tc.total > 0 && float64(tc.covered)/float64(tc.total) < 0.3 {
			recs = append(recs, Recommendation{
				ID:          fmt.Sprintf("rec-%d", len(recs)+1),
				Priority:    "medium",
				Category:    "tactic_coverage",
				Title:       fmt.Sprintf("Improve coverage for tactic %s", tacticID),
				Description: fmt.Sprintf("Tactic %s has only %d/%d techniques covered (%.0f%%). Focus on critical techniques in this tactic.", tacticID, tc.covered, tc.total, float64(tc.covered)/float64(tc.total)*100),
				Effort:      "medium",
				Impact:      "medium",
				Status:      "open",
			})
		}
	}

	sort.Slice(recs, func(i, j int) bool {
		priorityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
		return priorityOrder[recs[i].Priority] < priorityOrder[recs[j].Priority]
	})

	return recs
}

func (m *Module) GetControlMapping(techniqueID string) *ControlMapping {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, tactic := range m.tactics {
		for _, tech := range tactic.Techniques {
			if tech.ID == techniqueID {
				mapping := ControlMapping{
					TechniqueID:   tech.ID,
					TechniqueName: tech.Name,
					TacticID:      tactic.ID,
					AsscorChecks:  tech.AsscorChecks,
				}

				for _, r := range m.detectionRules {
					if r.TechniqueID == tech.ID && r.Enabled {
						mapping.DetectionRules = append(mapping.DetectionRules, r.ID)
					}
				}

				mapping.Mitigations = m.getMitigationsForTechnique(tech.ID)

				hasCheck := len(tech.AsscorChecks) > 0
				hasDetection := len(mapping.DetectionRules) > 0
				hasMitigation := len(mapping.Mitigations) > 0

				score := 0.0
				if hasCheck {
					score += 0.4
				}
				if hasDetection {
					score += 0.35
				}
				if hasMitigation {
					score += 0.25
				}
				mapping.Score = math.Round(score*100) / 100

				switch {
				case score >= 0.75:
					mapping.CoverageLevel = "full"
				case score >= 0.5:
					mapping.CoverageLevel = "partial"
				case score > 0:
					mapping.CoverageLevel = "minimal"
				default:
					mapping.CoverageLevel = "none"
				}

				return &mapping
			}
		}
	}
	return nil
}

func (m *Module) GetAssessmentReports(hostID string, limit int) []AssessmentReport {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []AssessmentReport
	for i := len(m.assessmentReports) - 1; i >= 0; i-- {
		r := m.assessmentReports[i]
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

func (m *Module) CreateImprovementTrack(track ImprovementTrack) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if track.ID == "" || track.Name == "" {
		return fmt.Errorf("improvement track ID and name must not be empty")
	}

	track.LastUpdated = time.Now()
	m.improvementTracks[track.ID] = track

	logger.WithComponent("attck.assessment").Info("created improvement track", "id", track.ID, "name", track.Name)
	return nil
}

func (m *Module) GetImprovementTrack(trackID string) *ImprovementTrack {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if t, ok := m.improvementTracks[trackID]; ok {
		return &t
	}
	return nil
}

func (m *Module) ListImprovementTracks() []ImprovementTrack {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]ImprovementTrack, 0, len(m.improvementTracks))
	for _, t := range m.improvementTracks {
		result = append(result, t)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}

func (m *Module) UpdateImprovementAction(trackID, actionID string, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	track, ok := m.improvementTracks[trackID]
	if !ok {
		return fmt.Errorf("improvement track not found: %s", trackID)
	}

	for i, action := range track.Actions {
		if action.ID == actionID {
			track.Actions[i].Status = status
			if status == "completed" {
				track.Actions[i].CompletedAt = time.Now()
			}
			track.LastUpdated = time.Now()
			m.improvementTracks[trackID] = track

			logger.WithComponent("attck.assessment").Info("updated improvement action", "track", trackID, "action", actionID, "status", status)
			return nil
		}
	}

	return fmt.Errorf("action not found: %s", actionID)
}

func (m *Module) CalculateImprovementProgress(trackID string) (float64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	track, ok := m.improvementTracks[trackID]
	if !ok {
		return 0, fmt.Errorf("improvement track not found: %s", trackID)
	}

	if len(track.Actions) == 0 {
		return 0, nil
	}

	completed := 0
	for _, action := range track.Actions {
		if action.Status == "completed" {
			completed++
		}
	}

	progress := float64(completed) / float64(len(track.Actions))
	return math.Round(progress*1000) / 1000, nil
}
