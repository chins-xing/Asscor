//go:build attck_ext

package kernel

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

func (m *ATTACKModule) RegisterDetectionRule(rule DetectionRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if rule.ID == "" {
		return fmt.Errorf("detection rule ID must not be empty")
	}
	if rule.TechniqueID == "" {
		return fmt.Errorf("detection rule must reference a technique ID")
	}

	rule.UpdatedAt = time.Now()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now()
	}

	for i, r := range m.detectionRules {
		if r.ID == rule.ID {
			m.detectionRules[i] = rule
			logger.WithComponent("attck.detection").Info("updated detection rule", "rule_id", rule.ID, "technique", rule.TechniqueID)
			return nil
		}
	}

	m.detectionRules = append(m.detectionRules, rule)
	logger.WithComponent("attck.detection").Info("registered detection rule", "rule_id", rule.ID, "technique", rule.TechniqueID)
	return nil
}

func (m *ATTACKModule) GetDetectionRule(ruleID string) *DetectionRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, r := range m.detectionRules {
		if r.ID == ruleID {
			cp := r
			return &cp
		}
	}
	return nil
}

func (m *ATTACKModule) ListDetectionRules(techniqueID string, enabledOnly bool) []DetectionRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []DetectionRule
	for _, r := range m.detectionRules {
		if techniqueID != "" && r.TechniqueID != techniqueID {
			continue
		}
		if enabledOnly && !r.Enabled {
			continue
		}
		result = append(result, r)
	}
	return result
}

func (m *ATTACKModule) DeleteDetectionRule(ruleID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, r := range m.detectionRules {
		if r.ID == ruleID {
			m.detectionRules = append(m.detectionRules[:i], m.detectionRules[i+1:]...)
			logger.WithComponent("attck.detection").Info("deleted detection rule", "rule_id", ruleID)
			return true
		}
	}
	return false
}

func (m *ATTACKModule) EvaluateDetectionRule(ruleID, hostID, rawLog string, fields map[string]string) (*DetectionAlert, error) {
	m.mu.Lock()

	var rule *DetectionRule
	for i := range m.detectionRules {
		if m.detectionRules[i].ID == ruleID {
			rule = &m.detectionRules[i]
			break
		}
	}
	if rule == nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("detection rule not found: %s", ruleID)
	}
	if !rule.Enabled {
		m.mu.Unlock()
		return nil, fmt.Errorf("detection rule is disabled: %s", ruleID)
	}

	matched := m.matchRule(rule, rawLog, fields)
	if !matched {
		m.mu.Unlock()
		return nil, nil
	}

	sanitizedLog := sanitizeRawLog(rawLog)

	alert := DetectionAlert{
		ID:          fmt.Sprintf("alert-%d", time.Now().UnixNano()),
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		TechniqueID: rule.TechniqueID,
		TacticIDs:   rule.TacticIDs,
		Severity:    rule.Severity,
		HostID:      hostID,
		Description: rule.Description,
		RawLog:      sanitizedLog,
		Fields:      fields,
		Status:      "new",
		Timestamp:   time.Now(),
	}

	m.alerts = append(m.alerts, alert)
	m.alerts = trimSlice(m.alerts, maxAlerts)

	m.mu.Unlock()

	m.kernel.Bus().Publish(m.kernel.Context(), Message{
		Topic:   "attck.detection.alert",
		Payload: alert,
		Source:  "attck.detection",
	})
	if m.kernel != nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "attck.detection.alert", alert)
	}

	logger.WithComponent("attck.detection").Info("alert triggered",
		"alert_id", alert.ID, "rule", rule.ID, "technique", rule.TechniqueID, "host", hostID)

	return &alert, nil
}

func (m *ATTACKModule) matchRule(rule *DetectionRule, rawLog string, fields map[string]string) bool {
	if rule.Query == "" {
		return false
	}

	if rawLog != "" {
		if strings.Contains(strings.ToLower(rawLog), strings.ToLower(rule.Query)) {
			return true
		}
	}

	for _, v := range fields {
		if strings.Contains(strings.ToLower(v), strings.ToLower(rule.Query)) {
			return true
		}
	}

	return false
}

func (m *ATTACKModule) GetAlerts(hostID, severity string, limit int) []DetectionAlert {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []DetectionAlert
	for i := len(m.alerts) - 1; i >= 0; i-- {
		a := m.alerts[i]
		if hostID != "" && a.HostID != hostID {
			continue
		}
		if severity != "" && a.Severity != severity {
			continue
		}
		result = append(result, a)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

func (m *ATTACKModule) AcknowledgeAlert(alertID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.alerts {
		if m.alerts[i].ID == alertID {
			m.alerts[i].Acknowledged = true
			m.alerts[i].Status = "acknowledged"
			return true
		}
	}
	return false
}

func (m *ATTACKModule) RecordAnomaly(event AnomalyEvent) {
	m.mu.Lock()

	if event.ID == "" {
		event.ID = fmt.Sprintf("anomaly-%d", time.Now().UnixNano())
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	m.anomalies = append(m.anomalies, event)
	m.anomalies = trimSlice(m.anomalies, maxAnomalies)

	m.mu.Unlock()

	if event.Score > 0.7 && event.TechniqueID != "" {
		m.kernel.Bus().Publish(m.kernel.Context(), Message{
			Topic:   "attck.detection.anomaly",
			Payload: event,
				Source:  "attck.detection",
			})
			if m.kernel != nil {
				m.kernel.Extensions().Execute(m.kernel.Context(), "attck.detection.anomaly", event)
			}
		}

	logger.WithComponent("attck.detection").Info("anomaly recorded",
		"anomaly_id", event.ID, "type", event.EventType, "score", event.Score, "technique", event.TechniqueID)
}

func (m *ATTACKModule) GetAnomalies(hostID string, minScore float64, limit int) []AnomalyEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []AnomalyEvent
	for i := len(m.anomalies) - 1; i >= 0; i-- {
		a := m.anomalies[i]
		if hostID != "" && a.HostID != hostID {
			continue
		}
		if a.Score < minScore {
			continue
		}
		result = append(result, a)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

func (m *ATTACKModule) CorrelateAlerts(hostID string) []CorrelationResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hostAlerts := make([]DetectionAlert, 0)
	for _, a := range m.alerts {
		if a.HostID == hostID && !a.Acknowledged {
			hostAlerts = append(hostAlerts, a)
		}
	}

	if len(hostAlerts) < 2 {
		return nil
	}

	var results []CorrelationResult

	tacticGroups := make(map[string][]DetectionAlert)
	for _, a := range hostAlerts {
		for _, tid := range a.TacticIDs {
			tacticGroups[tid] = append(tacticGroups[tid], a)
		}
	}

	idx := 0
	for tacticID, alerts := range tacticGroups {
		if len(alerts) < 2 {
			continue
		}

		techIDs := make(map[string]bool)
		alertIDs := make([]string, 0, len(alerts))
		for _, a := range alerts {
			techIDs[a.TechniqueID] = true
			alertIDs = append(alertIDs, a.ID)
		}

		uniqueTechs := make([]string, 0, len(techIDs))
		for t := range techIDs {
			uniqueTechs = append(uniqueTechs, t)
		}

		tacticName := m.getTacticName(tacticID)

		score := m.calculateCorrelationScore(alerts, tacticID)

		isKillChain := m.isKillChainProgression(hostAlerts)

		result := CorrelationResult{
			ID:           fmt.Sprintf("corr-%d-%d", time.Now().UnixNano(), idx),
			AlertIDs:     alertIDs,
			TechniqueIDs: uniqueTechs,
			TacticIDs:    []string{tacticID},
			Score:        score,
			Description:  fmt.Sprintf("Correlated %d alerts in tactic %s (%s)", len(alerts), tacticName, tacticID),
			AttackPhase:  tacticName,
			IsKillChain:  isKillChain,
			Timestamp:    time.Now(),
		}

		results = append(results, result)
		idx++
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	return results
}

func (m *ATTACKModule) calculateCorrelationScore(alerts []DetectionAlert, tacticID string) float64 {
	severityWeight := map[string]float64{
		"critical": 1.0,
		"high":     0.8,
		"medium":   0.5,
		"low":      0.3,
		"info":     0.1,
	}

	var sum float64
	for _, a := range alerts {
		w, ok := severityWeight[a.Severity]
		if !ok {
			w = 0.3
		}
		sum += w
	}

	score := sum / float64(len(alerts))
	return math.Round(score*1000) / 1000
}

func (m *ATTACKModule) isKillChainProgression(alerts []DetectionAlert) bool {
	tacticOrder := map[string]int{
		"TA0043": 1, "TA0042": 2, "TA0001": 3, "TA0002": 4,
		"TA0003": 5, "TA0004": 6, "TA0005": 7, "TA0006": 8,
		"TA0007": 9, "TA0008": 10, "TA0009": 11, "TA0011": 12,
		"TA0010": 13, "TA0040": 14,
	}

	seen := make(map[string]bool)
	for _, a := range alerts {
		for _, tid := range a.TacticIDs {
			seen[tid] = true
		}
	}

	var seenOrders []int
	for tid := range seen {
		if order, ok := tacticOrder[tid]; ok {
			seenOrders = append(seenOrders, order)
		}
	}

	if len(seenOrders) < 3 {
		return false
	}

	sort.Ints(seenOrders)

	consecutive := 1
	maxConsecutive := 1
	for i := 1; i < len(seenOrders); i++ {
		if seenOrders[i] == seenOrders[i-1]+1 {
			consecutive++
			if consecutive > maxConsecutive {
				maxConsecutive = consecutive
			}
		} else {
			consecutive = 1
		}
	}

	return maxConsecutive >= 3
}

func (m *ATTACKModule) GetDetectionSummary() DetectionSummary {
	m.mu.RLock()
	defer m.mu.RUnlock()

	summary := DetectionSummary{
		TotalRules:       len(m.detectionRules),
		AlertsBySeverity: make(map[string]int),
		AlertsByTactic:   make(map[string]int),
		AlertsByTechnique: make(map[string]int),
	}

	for _, r := range m.detectionRules {
		if r.Enabled {
			summary.ActiveRules++
		}
	}

	summary.TotalAlerts = len(m.alerts)
	for _, a := range m.alerts {
		if !a.Acknowledged {
			summary.OpenAlerts++
		}
		summary.AlertsBySeverity[a.Severity]++
		summary.AlertsByTechnique[a.TechniqueID]++
		for _, tid := range a.TacticIDs {
			summary.AlertsByTactic[tid]++
		}
	}

	summary.Anomalies = len(m.anomalies)

	hostAlertCount := make(map[string]int)
	for _, a := range m.alerts {
		hostAlertCount[a.HostID]++
	}
	type hostCount struct {
		host  string
		count int
	}
	var hc []hostCount
	for h, c := range hostAlertCount {
		hc = append(hc, hostCount{h, c})
	}
	sort.Slice(hc, func(i, j int) bool { return hc[i].count > hc[j].count })
	for i, h := range hc {
		if i >= 10 {
			break
		}
		summary.TopAlertHosts = append(summary.TopAlertHosts, h.host)
	}

	summary.CoverageGaps = m.findDetectionGaps()

	return summary
}

func (m *ATTACKModule) findDetectionGaps() []string {
	ruleTechs := make(map[string]bool)
	for _, r := range m.detectionRules {
		if r.Enabled {
			ruleTechs[r.TechniqueID] = true
		}
	}

	var gaps []string
	for _, tactic := range m.tactics {
		for _, tech := range tactic.Techniques {
			if len(tech.AsscorChecks) > 0 && !ruleTechs[tech.ID] {
				gaps = append(gaps, fmt.Sprintf("%s (%s) — has ASSCOR checks but no detection rule", tech.ID, tactic.Name))
			}
		}
	}
	return gaps
}

func (m *ATTACKModule) getTacticName(tacticID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getTacticNameLocked(tacticID)
}

func (m *ATTACKModule) getTacticNameLocked(tacticID string) string {
	for _, t := range m.tactics {
		if t.ID == tacticID {
			return t.Name
		}
	}
	return tacticID
}

func (m *ATTACKModule) loadDefaultDetectionRules() {
	m.detectionRules = []DetectionRule{
		{
			ID: "DET-001", Name: "Brute Force Login Attempt", Description: "Detects multiple failed login attempts indicating brute force activity",
			TechniqueID: "T1110", TacticIDs: []string{"TA0006"}, Severity: "high",
			LogSources: []string{"auth", "syslog"}, Query: "failed password", Enabled: true,
			Tags: []string{"authentication", "brute_force"}, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
		{
			ID: "DET-002", Name: "Suspicious PowerShell Execution", Description: "Detects encoded or obfuscated PowerShell commands",
			TechniqueID: "T1059.001", TacticIDs: []string{"TA0002"}, Severity: "high",
			LogSources: []string{"syslog", "process"}, Query: "encodedcommand", Enabled: true,
			Tags: []string{"execution", "powershell"}, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
		{
			ID: "DET-003", Name: "Credential Dumping Indicator", Description: "Detects LSASS access or credential dumping tool execution",
			TechniqueID: "T1003", TacticIDs: []string{"TA0006"}, Severity: "critical",
			LogSources: []string{"process", "syslog"}, Query: "procdump", Enabled: true,
			Tags: []string{"credential_access", "dumping"}, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
		{
			ID: "DET-004", Name: "Lateral Movement via SSH", Description: "Detects SSH connections to multiple internal hosts",
			TechniqueID: "T1021.004", TacticIDs: []string{"TA0008"}, Severity: "medium",
			LogSources: []string{"auth", "syslog"}, Query: "session opened", Enabled: true,
			Tags: []string{"lateral_movement", "ssh"}, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
		{
			ID: "DET-005", Name: "Data Exfiltration Indicator", Description: "Detects large outbound data transfers",
			TechniqueID: "T1048", TacticIDs: []string{"TA0010"}, Severity: "high",
			LogSources: []string{"network", "firewall"}, Query: "transfer", Enabled: true,
			Tags: []string{"exfiltration", "network"}, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
		{
			ID: "DET-006", Name: "Persistence via Cron Modification", Description: "Detects modifications to cron jobs for persistence",
			TechniqueID: "T1053.003", TacticIDs: []string{"TA0003"}, Severity: "medium",
			LogSources: []string{"syslog", "file"}, Query: "crontab", Enabled: true,
			Tags: []string{"persistence", "scheduled_task"}, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
		{
			ID: "DET-007", Name: "Privilege Escalation via Sudo", Description: "Detects sudo usage to gain elevated privileges",
			TechniqueID: "T1548.003", TacticIDs: []string{"TA0004"}, Severity: "medium",
			LogSources: []string{"auth", "syslog"}, Query: "sudo", Enabled: true,
			Tags: []string{"privilege_escalation", "sudo"}, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
		{
			ID: "DET-008", Name: "Defense Evasion via Log Deletion", Description: "Detects deletion or clearing of system logs",
			TechniqueID: "T1070.002", TacticIDs: []string{"TA0005"}, Severity: "high",
			LogSources: []string{"syslog", "file"}, Query: "log deleted", Enabled: true,
			Tags: []string{"defense_evasion", "log_deletion"}, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
		{
			ID: "DET-009", Name: "Exploitation of Public-Facing App", Description: "Detects exploitation attempts against web applications",
			TechniqueID: "T1190", TacticIDs: []string{"TA0001"}, Severity: "critical",
			LogSources: []string{"web", "nginx", "apache"}, Query: "sql injection", Enabled: true,
			Tags: []string{"initial_access", "web_exploit"}, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
		{
			ID: "DET-010", Name: "Command and Control Beacon", Description: "Detects periodic outbound connections indicating C2 beaconing",
			TechniqueID: "T1071.001", TacticIDs: []string{"TA0011"}, Severity: "high",
			LogSources: []string{"network", "dns"}, Query: "beacon", Enabled: true,
			Tags: []string{"command_and_control", "beaconing"}, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
	}
}

var sanitizeLogPattern = regexp.MustCompile(`(?i)(password|passwd|api_key|apikey|token|secret|authorization|credential)[=:]\s*\S+`)

func sanitizeRawLog(rawLog string) string {
	return sanitizeLogPattern.ReplaceAllString(rawLog, `$1=***REDACTED***`)
}
