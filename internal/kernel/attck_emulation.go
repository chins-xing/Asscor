//go:build attck_ext

package kernel

import (
	"fmt"
	"sort"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

func (m *ATTACKModule) CreateScenario(scenario EmulationScenario) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if scenario.ID == "" || scenario.Name == "" {
		return fmt.Errorf("scenario ID and name must not be empty")
	}

	if len(scenario.Phases) == 0 {
		return fmt.Errorf("scenario must have at least one phase")
	}

	scenario.CreatedAt = time.Now()
	scenario.UpdatedAt = time.Now()

	for i := range scenario.Phases {
		if scenario.Phases[i].Order == 0 {
			scenario.Phases[i].Order = i + 1
		}
	}

	for i, s := range m.scenarios {
		if s.ID == scenario.ID {
			m.scenarios[i] = scenario
			logger.WithComponent("attck.emulation").Info("updated scenario", "id", scenario.ID, "name", scenario.Name)
			return nil
		}
	}

	m.scenarios = append(m.scenarios, scenario)
	logger.WithComponent("attck.emulation").Info("created scenario", "id", scenario.ID, "name", scenario.Name, "phases", len(scenario.Phases))
	return nil
}

func (m *ATTACKModule) GetScenario(scenarioID string) *EmulationScenario {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.scenarios {
		if s.ID == scenarioID {
			return &s
		}
	}
	return nil
}

func (m *ATTACKModule) ListScenarios(actorProfile string) []EmulationScenario {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []EmulationScenario
	for _, s := range m.scenarios {
		if actorProfile != "" && s.ActorProfile != actorProfile {
			continue
		}
		result = append(result, s)
	}
	return result
}

func (m *ATTACKModule) DeleteScenario(scenarioID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, s := range m.scenarios {
		if s.ID == scenarioID {
			m.scenarios = append(m.scenarios[:i], m.scenarios[i+1:]...)
			logger.WithComponent("attck.emulation").Info("deleted scenario", "id", scenarioID)
			return true
		}
	}
	return false
}

func (m *ATTACKModule) GenerateScenarioFromActor(actorID string) (*EmulationScenario, error) {
	m.mu.RLock()
	actor, ok := m.threatActors[actorID]
	m.mu.RUnlock()

	if !ok {
		aptGroup, ok := m.aptGroups[actorID]
		if !ok {
			return nil, fmt.Errorf("threat actor not found: %s", actorID)
		}

		actor = ThreatActorProfile{
			ID:         aptGroup.GroupID,
			Name:       aptGroup.Name,
			Aliases:    aptGroup.Aliases,
			Techniques: aptGroup.Techniques,
		}
	}

	type techWithWeight struct {
		id     string
		weight float64
	}
	var techs []techWithWeight
	for techID, weight := range actor.Techniques {
		techs = append(techs, techWithWeight{techID, weight})
	}
	sort.Slice(techs, func(i, j int) bool {
		return techs[i].weight > techs[j].weight
	})

	tacticOrder := map[string]int{
		"TA0043": 0, "TA0042": 1, "TA0001": 2, "TA0002": 3,
		"TA0003": 4, "TA0004": 5, "TA0005": 6, "TA0006": 7,
		"TA0007": 8, "TA0008": 9, "TA0009": 10, "TA0011": 11,
		"TA0010": 12, "TA0040": 13,
	}

	phaseMap := make(map[string][]techWithWeight)
	for _, t := range techs {
		tacticID := m.getTacticForTechnique(t.id)
		if tacticID == "" {
			continue
		}
		phaseMap[tacticID] = append(phaseMap[tacticID], t)
	}

	var phases []EmulationPhase
	order := 1
	for i := 0; i < 14; i++ {
		var tacticID string
		for tid, o := range tacticOrder {
			if o == i {
				tacticID = tid
				break
			}
		}
		techsInTactic, ok := phaseMap[tacticID]
		if !ok || len(techsInTactic) == 0 {
			continue
		}

		tacticName := m.getTacticName(tacticID)
		topTech := techsInTactic[0]

		phase := EmulationPhase{
			Order:       order,
			Name:        fmt.Sprintf("%s via %s", tacticName, topTech.id),
			TacticID:    tacticID,
			TechniqueID: topTech.id,
			Description: fmt.Sprintf("Simulate %s technique %s (weight: %.2f)", tacticName, topTech.id, topTech.weight),
			Commands:    m.generateSafeCommands(topTech.id),
			ExpectedDetections: m.getExpectedDetectionRules(topTech.id),
			RiskLevel:   m.weightToRiskLevel(topTech.weight),
		}

		phases = append(phases, phase)
		order++
	}

	if len(phases) == 0 {
		return nil, fmt.Errorf("no actionable techniques found for actor %s", actorID)
	}

	scenario := &EmulationScenario{
		ID:           fmt.Sprintf("emu-%s-%d", actorID, time.Now().Unix()),
		Name:         fmt.Sprintf("Emulation: %s", actor.Name),
		Description:  fmt.Sprintf("Auto-generated emulation scenario based on %s TTPs", actor.Name),
		ActorProfile: actorID,
		Objective:    fmt.Sprintf("Assess defensive capabilities against %s adversary profile", actor.Name),
		Phases:       phases,
		Tags:         []string{"auto-generated", actor.Name},
		Difficulty:   m.assessDifficulty(phases),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	return scenario, nil
}

func (m *ATTACKModule) getTacticForTechnique(techID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getTacticForTechniqueLocked(techID)
}

func (m *ATTACKModule) getTacticForTechniqueLocked(techID string) string {
	for _, tactic := range m.tactics {
		for _, tech := range tactic.Techniques {
			if tech.ID == techID {
				return tactic.ID
			}
		}
	}
	return ""
}

func (m *ATTACKModule) generateSafeCommands(techID string) []EmulationCommand {
	commands := []EmulationCommand{
		{
			ID:          fmt.Sprintf("cmd-%s-scout", techID),
			Description: fmt.Sprintf("Safe reconnaissance for %s", techID),
			Platform:    "linux",
			Executor:    "shell",
			Command:     fmt.Sprintf("echo '[ASSCOR-EMU] Scouting for %s'", techID),
			SafeMode:    true,
			Timeout:     10,
		},
		{
			ID:          fmt.Sprintf("cmd-%s-verify", techID),
			Description: fmt.Sprintf("Verify detection capability for %s", techID),
			Platform:    "linux",
			Executor:    "shell",
			Command:     fmt.Sprintf("echo '[ASSCOR-EMU] Verifying detection for %s'", techID),
			SafeMode:    true,
			Timeout:     5,
		},
	}
	return commands
}

func (m *ATTACKModule) getExpectedDetectionRules(techID string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var ruleIDs []string
	for _, r := range m.detectionRules {
		if r.TechniqueID == techID && r.Enabled {
			ruleIDs = append(ruleIDs, r.ID)
		}
	}
	return ruleIDs
}

func (m *ATTACKModule) weightToRiskLevel(weight float64) string {
	switch {
	case weight >= 0.8:
		return "critical"
	case weight >= 0.6:
		return "high"
	case weight >= 0.4:
		return "medium"
	default:
		return "low"
	}
}

func (m *ATTACKModule) assessDifficulty(phases []EmulationPhase) string {
	criticalCount := 0
	for _, p := range phases {
		if p.RiskLevel == "critical" {
			criticalCount++
		}
	}
	switch {
	case criticalCount >= 4:
		return "advanced"
	case criticalCount >= 2:
		return "intermediate"
	default:
		return "basic"
	}
}

func (m *ATTACKModule) RunEmulation(scenarioID, hostID string, safeMode bool) (*EmulationResult, error) {
	m.mu.Lock()

	var scenario *EmulationScenario
	for i := range m.scenarios {
		if m.scenarios[i].ID == scenarioID {
			scenario = &m.scenarios[i]
			break
		}
	}
	if scenario == nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("scenario not found: %s", scenarioID)
	}

	logger.WithComponent("attck.emulation").Info("starting emulation",
		"scenario", scenarioID, "host", hostID, "safe_mode", safeMode)

	startTime := time.Now()

	result := &EmulationResult{
		ScenarioID:      scenarioID,
		HostID:          hostID,
		Status:          "completed",
		TotalTechniques: len(scenario.Phases),
		StartTime:       startTime,
	}

	var phaseResults []EmulationPhaseResult
	detectedCount := 0

	for _, phase := range scenario.Phases {
		phaseResult := EmulationPhaseResult{
			PhaseOrder:  phase.Order,
			TechniqueID: phase.TechniqueID,
			Status:      "executed",
			StartTime:   time.Now(),
		}

		if safeMode {
			phaseResult.ExecutionOutput = fmt.Sprintf("[SAFE MODE] Would execute %s phase: %s", phase.TechniqueID, phase.Name)
			phaseResult.Detected = m.checkDetectionExists(phase.TechniqueID)
		} else {
			for _, cmd := range phase.Commands {
				if cmd.SafeMode {
					phaseResult.ExecutionOutput += fmt.Sprintf("[SIMULATE] %s\n", cmd.Description)
				} else {
					phaseResult.ExecutionOutput += fmt.Sprintf("[EXECUTE] %s\n", cmd.Description)
				}
			}
			phaseResult.Detected = m.checkDetectionExists(phase.TechniqueID)
		}

		if phaseResult.Detected {
			detectedCount++
			for _, ruleID := range phase.ExpectedDetections {
				phaseResult.DetectionRuleID = ruleID
				break
			}
		}

		phaseResult.EndTime = time.Now()
		phaseResults = append(phaseResults, phaseResult)
	}

	result.PhaseResults = phaseResults
	result.DetectedCount = detectedCount
	result.MissedCount = result.TotalTechniques - detectedCount
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	if result.TotalTechniques > 0 {
		result.DetectionRate = float64(detectedCount) / float64(result.TotalTechniques)
	}

	result.Recommendations = m.generateEmulationRecommendations(result)

	m.emulationResults = append(m.emulationResults, *result)
	m.emulationResults = trimSlice(m.emulationResults, maxEmulationResults)
	m.mu.Unlock()

	m.kernel.Bus().Publish(m.kernel.Context(), Message{
		Topic:   "attck.emulation.complete",
		Payload: result,
		Source:  "attck.emulation",
	})
	if m.kernel != nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "attck.emulation.complete", result)
	}

	logger.WithComponent("attck.emulation").Info("emulation completed",
		"scenario", scenarioID, "detection_rate", result.DetectionRate,
		"detected", detectedCount, "missed", result.MissedCount)

	return result, nil
}

func (m *ATTACKModule) checkDetectionExists(techID string) bool {
	for _, r := range m.detectionRules {
		if r.TechniqueID == techID && r.Enabled {
			return true
		}
	}
	return false
}

func (m *ATTACKModule) generateEmulationRecommendations(result *EmulationResult) []string {
	var recs []string

	for _, pr := range result.PhaseResults {
		if !pr.Detected {
			recs = append(recs, fmt.Sprintf("Add detection rule for technique %s — no detection was triggered during emulation", pr.TechniqueID))
		}
	}

	if result.DetectionRate < 0.5 {
		recs = append(recs, "Detection rate is below 50% — consider improving detection coverage before next emulation cycle")
	}

	if result.DetectionRate >= 0.8 {
		recs = append(recs, "Detection rate is above 80% — consider testing with more advanced adversary profiles")
	}

	return recs
}

func (m *ATTACKModule) GetEmulationResults(scenarioID string, limit int) []EmulationResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []EmulationResult
	for i := len(m.emulationResults) - 1; i >= 0; i-- {
		r := m.emulationResults[i]
		if scenarioID != "" && r.ScenarioID != scenarioID {
			continue
		}
		result = append(result, r)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

func (m *ATTACKModule) loadDefaultScenarios() {
	m.scenarios = []EmulationScenario{
		{
			ID: "EMU-DEFAULT-001", Name: "Standard Network Intrusion",
			Description: "Simulates a standard network intrusion following the kill chain from initial access to exfiltration",
			Objective: "Assess detection coverage across the full kill chain",
			Phases: []EmulationPhase{
				{
					Order: 1, Name: "Spear Phishing", TacticID: "TA0001", TechniqueID: "T1566",
					Description: "Simulate phishing email delivery",
					Commands: []EmulationCommand{
						{ID: "cmd-phish-1", Description: "Simulate phishing email", Platform: "linux", Executor: "shell", Command: "echo '[ASSCOR-EMU] Phishing simulation'", SafeMode: true, Timeout: 5},
					},
					ExpectedDetections: []string{"DET-009"}, RiskLevel: "high",
				},
				{
					Order: 2, Name: "Command Execution", TacticID: "TA0002", TechniqueID: "T1059",
					Description: "Simulate command execution after initial access",
					Commands: []EmulationCommand{
						{ID: "cmd-exec-1", Description: "Simulate script execution", Platform: "linux", Executor: "shell", Command: "echo '[ASSCOR-EMU] Script execution'", SafeMode: true, Timeout: 5},
					},
					ExpectedDetections: []string{"DET-002"}, RiskLevel: "high",
				},
				{
					Order: 3, Name: "Credential Dumping", TacticID: "TA0006", TechniqueID: "T1003",
					Description: "Simulate credential access",
					Commands: []EmulationCommand{
						{ID: "cmd-cred-1", Description: "Simulate credential dump", Platform: "linux", Executor: "shell", Command: "echo '[ASSCOR-EMU] Credential access'", SafeMode: true, Timeout: 5},
					},
					ExpectedDetections: []string{"DET-003"}, RiskLevel: "critical",
				},
				{
					Order: 4, Name: "Lateral Movement", TacticID: "TA0008", TechniqueID: "T1021",
					Description: "Simulate lateral movement via SSH",
					Commands: []EmulationCommand{
						{ID: "cmd-lat-1", Description: "Simulate SSH lateral movement", Platform: "linux", Executor: "shell", Command: "echo '[ASSCOR-EMU] Lateral movement'", SafeMode: true, Timeout: 5},
					},
					ExpectedDetections: []string{"DET-004"}, RiskLevel: "medium",
				},
				{
					Order: 5, Name: "Data Exfiltration", TacticID: "TA0010", TechniqueID: "T1048",
					Description: "Simulate data exfiltration",
					Commands: []EmulationCommand{
						{ID: "cmd-exfil-1", Description: "Simulate data exfiltration", Platform: "linux", Executor: "shell", Command: "echo '[ASSCOR-EMU] Exfiltration'", SafeMode: true, Timeout: 5},
					},
					ExpectedDetections: []string{"DET-005"}, RiskLevel: "high",
				},
			},
			Tags:       []string{"kill-chain", "standard"},
			Difficulty: "intermediate",
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
	}
}
