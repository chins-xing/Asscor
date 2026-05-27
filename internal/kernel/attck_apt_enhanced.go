package kernel

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

type GroupBaseline struct {
	Role         string             `json:"role"`
	Metrics      map[string]float64 `json:"metrics"`
	SampleCount  int                `json:"sample_count"`
	HostIDs      []string           `json:"host_ids"`
	ComputedAt   time.Time          `json:"computed_at"`
}

type BayesianNode struct {
	Name        string   `json:"name"`
	States      []string `json:"states"`
	Parents     []string `json:"parents"`
	CPT         [][]float64 `json:"cpt"`
	Description string   `json:"description"`
}

type BayesianNetwork struct {
	Nodes       map[string]*BayesianNode `json:"nodes"`
	Edges       []BayesianEdge           `json:"edges"`
	Description string                   `json:"description"`
}

type BayesianEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type BayesianInferenceResult struct {
	TargetNode  string             `json:"target_node"`
	Probabilities map[string]float64 `json:"probabilities"`
	Evidence     map[string]string  `json:"evidence"`
	TopActor     string             `json:"top_actor"`
	TopProb      float64            `json:"top_probability"`
	Confidence   float64            `json:"confidence"`
}

type ReputationEntry struct {
	Destination string   `json:"destination"`
	Service     string   `json:"service"`
	Category    string   `json:"category"`
	IsLegitimate bool    `json:"is_legitimate"`
	Reason      string   `json:"reason"`
	Source      string   `json:"source"`
}

type YARARule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Author      string   `json:"author"`
	Description string   `json:"description"`
	TechniqueID string   `json:"technique_id"`
	TacticIDs   []string `json:"tactic_ids"`
	Severity    string   `json:"severity"`
	RuleContent string   `json:"rule_content"`
	Tags        []string `json:"tags"`
	Enabled     bool     `json:"enabled"`
}

type SigmaRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Author      string   `json:"author"`
	Description string   `json:"description"`
	TechniqueID string   `json:"technique_id"`
	TacticIDs   []string `json:"tactic_ids"`
	Severity    string   `json:"severity"`
	LogSource   string   `json:"log_source"`
	Detection   string   `json:"detection"`
	Condition   string   `json:"condition"`
	Tags        []string `json:"tags"`
	Enabled     bool     `json:"enabled"`
}

type RuleMatchResult struct {
	RuleID      string   `json:"rule_id"`
	RuleName    string   `json:"rule_name"`
	RuleType    string   `json:"rule_type"`
	TechniqueID string   `json:"technique_id"`
	TacticIDs   []string `json:"tactic_ids"`
	Severity    string   `json:"severity"`
	MatchDetail string   `json:"match_detail"`
	HostID      string   `json:"host_id"`
	Confidence  float64  `json:"confidence"`
	Timestamp   time.Time `json:"timestamp"`
}

type CrossHostConnection struct {
	SourceHost string    `json:"source_host"`
	DestHost   string    `json:"dest_host"`
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"`
	Service    string    `json:"service"`
	Count      int       `json:"connection_count"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	IsAnomalous bool     `json:"is_anomalous"`
	TechniqueID string   `json:"technique_id"`
}

type LateralMovementEvidence struct {
	SourceHost     string               `json:"source_host"`
	TargetHosts    []string             `json:"target_hosts"`
	TechniqueID    string               `json:"technique_id"`
	Connections    []CrossHostConnection `json:"connections"`
	Score          float64              `json:"score"`
	Timestamp      time.Time            `json:"timestamp"`
}



func (m *ATTACKModule) ComputeGroupBaseline(role string) *GroupBaseline {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matchingBaselines []BehavioralBaseline
	var hostIDs []string
	for hostID, baseline := range m.baselines {
		asset := m.getAssetForHost(hostID)
		if asset != nil && asset.Role == role {
			matchingBaselines = append(matchingBaselines, baseline)
			hostIDs = append(hostIDs, hostID)
		}
	}

	if len(matchingBaselines) == 0 {
		return nil
	}

	mergedMetrics := make(map[string]float64)
	metricCounts := make(map[string]int)
	for _, b := range matchingBaselines {
		for k, v := range b.Metrics {
			mergedMetrics[k] += v
			metricCounts[k]++
		}
	}

	for k, v := range mergedMetrics {
		if count, ok := metricCounts[k]; ok && count > 0 {
			mergedMetrics[k] = math.Round(v/float64(count)*1000) / 1000
		}
	}

	totalSamples := 0
	for _, b := range matchingBaselines {
		totalSamples += b.SampleCount
	}

	group := &GroupBaseline{
		Role:        role,
		Metrics:     mergedMetrics,
		SampleCount: totalSamples,
		HostIDs:     hostIDs,
		ComputedAt:  time.Now(),
	}

	logger.WithComponent("attck.behavioral").Info("group baseline computed",
		"role", role, "hosts", len(hostIDs), "metrics", len(mergedMetrics))

	return group
}

func (m *ATTACKModule) ApplyGroupBaseline(hostID string, role string) bool {
	group := m.ComputeGroupBaseline(role)
	if group == nil {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	baseline := BehavioralBaseline{
		HostID:      hostID,
		Metrics:     group.Metrics,
		SampleCount: group.SampleCount,
		Period:      24 * time.Hour,
		ComputedAt:  time.Now(),
	}
	m.baselines[hostID] = baseline

	logger.WithComponent("attck.behavioral").Info("group baseline applied to host",
		"host", hostID, "role", role, "metrics", len(group.Metrics))

	return true
}

func (m *ATTACKModule) getAssetForHost(hostID string) *LocalAsset {
	if m.kernel == nil {
		return nil
	}
	impl, ok := m.kernel.Container().Resolve((*SPCInterface)(nil))
	if !ok {
		return nil
	}
	spc, ok := impl.(SPCInterface)
	if !ok {
		return nil
	}
	return spc.GetAsset(hostID)
}

func (m *ATTACKModule) BuildBayesianAttributionNetwork() *BayesianNetwork {
	nodes := make(map[string]*BayesianNode)

	nodes["ttp_overlap"] = &BayesianNode{
		Name:        "ttp_overlap",
		States:      []string{"high", "medium", "low"},
		Parents:     nil,
		Description: "TTP overlap with known APT groups",
	}

	nodes["ioc_match"] = &BayesianNode{
		Name:        "ioc_match",
		States:      []string{"strong", "weak", "none"},
		Parents:     nil,
		Description: "IOC evidence strength",
	}

	nodes["sector_alignment"] = &BayesianNode{
		Name:        "sector_alignment",
		States:      []string{"aligned", "partial", "none"},
		Parents:     nil,
		Description: "Target sector alignment with APT group",
	}

	nodes["kill_chain_coherence"] = &BayesianNode{
		Name:        "kill_chain_coherence",
		States:      []string{"coherent", "partial", "incoherent"},
		Parents:     nil,
		Description: "Attack chain coherence with known APT methodology",
	}

	nodes["attribution"] = &BayesianNode{
		Name:        "attribution",
		States:      []string{"high_confidence", "medium_confidence", "low_confidence", "unknown"},
		Parents:     []string{"ttp_overlap", "ioc_match", "sector_alignment", "kill_chain_coherence"},
		Description: "Attribution confidence level",
		CPT: [][]float64{
			{0.85, 0.10, 0.04, 0.01},
			{0.60, 0.25, 0.12, 0.03},
			{0.30, 0.35, 0.25, 0.10},
			{0.10, 0.20, 0.40, 0.30},
			{0.70, 0.18, 0.09, 0.03},
			{0.45, 0.30, 0.18, 0.07},
			{0.20, 0.30, 0.30, 0.20},
			{0.08, 0.15, 0.35, 0.42},
			{0.55, 0.25, 0.14, 0.06},
			{0.35, 0.30, 0.22, 0.13},
			{0.15, 0.25, 0.35, 0.25},
			{0.05, 0.12, 0.30, 0.53},
			{0.65, 0.20, 0.11, 0.04},
			{0.40, 0.30, 0.20, 0.10},
			{0.18, 0.27, 0.32, 0.23},
			{0.06, 0.14, 0.30, 0.50},
			{0.50, 0.28, 0.15, 0.07},
			{0.30, 0.32, 0.24, 0.14},
			{0.12, 0.22, 0.35, 0.31},
			{0.04, 0.10, 0.28, 0.58},
			{0.40, 0.30, 0.20, 0.10},
			{0.25, 0.30, 0.28, 0.17},
			{0.10, 0.20, 0.35, 0.35},
			{0.03, 0.08, 0.25, 0.64},
			{0.30, 0.32, 0.24, 0.14},
			{0.18, 0.28, 0.30, 0.24},
			{0.08, 0.16, 0.32, 0.44},
			{0.02, 0.06, 0.20, 0.72},
			{0.20, 0.30, 0.30, 0.20},
			{0.12, 0.22, 0.32, 0.34},
			{0.05, 0.12, 0.28, 0.55},
			{0.01, 0.04, 0.15, 0.80},
			{0.25, 0.30, 0.28, 0.17},
			{0.15, 0.25, 0.32, 0.28},
			{0.06, 0.14, 0.30, 0.50},
			{0.02, 0.05, 0.18, 0.75},
			{0.15, 0.25, 0.32, 0.28},
			{0.08, 0.18, 0.34, 0.40},
			{0.03, 0.08, 0.25, 0.64},
			{0.01, 0.03, 0.12, 0.84},
			{0.10, 0.20, 0.35, 0.35},
			{0.05, 0.12, 0.30, 0.53},
			{0.02, 0.06, 0.20, 0.72},
			{0.01, 0.02, 0.10, 0.87},
			{0.05, 0.12, 0.30, 0.53},
			{0.03, 0.08, 0.25, 0.64},
			{0.01, 0.04, 0.15, 0.80},
			{0.00, 0.01, 0.08, 0.91},
			{0.03, 0.08, 0.25, 0.64},
			{0.01, 0.04, 0.18, 0.77},
			{0.01, 0.02, 0.10, 0.87},
			{0.00, 0.01, 0.05, 0.94},
			{0.01, 0.04, 0.18, 0.77},
			{0.01, 0.02, 0.12, 0.85},
			{0.00, 0.01, 0.06, 0.93},
			{0.00, 0.00, 0.03, 0.97},
			{0.01, 0.03, 0.15, 0.81},
			{0.00, 0.02, 0.10, 0.88},
			{0.00, 0.01, 0.05, 0.94},
			{0.00, 0.00, 0.02, 0.98},
			{0.00, 0.01, 0.08, 0.91},
			{0.00, 0.01, 0.05, 0.94},
			{0.00, 0.00, 0.03, 0.97},
			{0.00, 0.00, 0.01, 0.99},
			{0.00, 0.01, 0.05, 0.94},
			{0.00, 0.00, 0.03, 0.97},
			{0.00, 0.00, 0.01, 0.99},
			{0.00, 0.00, 0.01, 0.99},
			{0.00, 0.00, 0.03, 0.97},
			{0.00, 0.00, 0.01, 0.99},
			{0.00, 0.00, 0.00, 1.00},
			{0.00, 0.00, 0.00, 1.00},
			{0.00, 0.00, 0.01, 0.99},
			{0.00, 0.00, 0.00, 1.00},
			{0.00, 0.00, 0.00, 1.00},
			{0.00, 0.00, 0.00, 1.00},
			{0.00, 0.00, 0.00, 1.00},
			{0.00, 0.00, 0.00, 1.00},
			{0.00, 0.00, 0.00, 1.00},
			{0.00, 0.00, 0.00, 1.00},
		},
	}

	edges := []BayesianEdge{
		{From: "ttp_overlap", To: "attribution"},
		{From: "ioc_match", To: "attribution"},
		{From: "sector_alignment", To: "attribution"},
		{From: "kill_chain_coherence", To: "attribution"},
	}

	return &BayesianNetwork{
		Nodes:       nodes,
		Edges:       edges,
		Description: "APT Attribution Bayesian Network — infers attribution confidence from multi-source evidence",
	}
}

func (m *ATTACKModule) PerformBayesianAttribution(chainID string) (*BayesianInferenceResult, error) {
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

	network := m.BuildBayesianAttributionNetwork()

	evidence := make(map[string]string)

	ttpOverlap := m.computeTTPOverlapScore(chain.Stages)
	switch {
	case ttpOverlap >= 0.7:
		evidence["ttp_overlap"] = "high"
	case ttpOverlap >= 0.4:
		evidence["ttp_overlap"] = "medium"
	default:
		evidence["ttp_overlap"] = "low"
	}

	iocStrength := m.computeIOCStrength()
	switch {
	case iocStrength >= 0.7:
		evidence["ioc_match"] = "strong"
	case iocStrength >= 0.3:
		evidence["ioc_match"] = "weak"
	default:
		evidence["ioc_match"] = "none"
	}

	sectorScore := m.computeSectorScore(chain.Stages)
	switch {
	case sectorScore >= 0.6:
		evidence["sector_alignment"] = "aligned"
	case sectorScore >= 0.3:
		evidence["sector_alignment"] = "partial"
	default:
		evidence["sector_alignment"] = "none"
	}

	coherence := m.computeKillChainCoherence(chain.Stages)
	switch {
	case coherence >= 0.7:
		evidence["kill_chain_coherence"] = "coherent"
	case coherence >= 0.4:
		evidence["kill_chain_coherence"] = "partial"
	default:
		evidence["kill_chain_coherence"] = "incoherent"
	}

	probs := m.inferBayesian(network, evidence)

	topActor := "unknown"
	topProb := 0.0
	for state, prob := range probs {
		if prob > topProb {
			topProb = prob
			topActor = state
		}
	}

	confidence := topProb
	if topActor == "unknown" {
		confidence = 1.0 - topProb
	}

	result := &BayesianInferenceResult{
		TargetNode:    "attribution",
		Probabilities: probs,
		Evidence:      evidence,
		TopActor:      topActor,
		TopProb:       math.Round(topProb*1000) / 1000,
		Confidence:    math.Round(confidence*1000) / 1000,
	}

	logger.WithComponent("attck.apt.bayesian").Info("Bayesian attribution performed",
		"chain_id", chainID, "top_actor", topActor, "confidence", result.Confidence,
		"evidence", fmt.Sprintf("%v", evidence))

	return result, nil
}

func (m *ATTACKModule) computeTTPOverlapScore(stages []AttackStage) float64 {
	if len(m.aptGroups) == 0 {
		return 0
	}

	observedTechs := make(map[string]bool)
	for _, s := range stages {
		observedTechs[s.TechniqueID] = true
	}

	maxOverlap := 0.0
	for _, group := range m.aptGroups {
		overlap := 0
		total := 0
		for tech := range group.Techniques {
			total++
			if observedTechs[tech] {
				overlap++
			}
		}
		if total > 0 {
			ratio := float64(overlap) / float64(total)
			if ratio > maxOverlap {
				maxOverlap = ratio
			}
		}
	}
	return maxOverlap
}

func (m *ATTACKModule) computeIOCStrength() float64 {
	if len(m.iocs) == 0 {
		return 0
	}

	var totalConf float64
	actorLinked := 0
	for _, ioc := range m.iocs {
		totalConf += ioc.Confidence
		if ioc.ThreatActor != "" {
			actorLinked++
		}
	}

	avgConf := totalConf / float64(len(m.iocs))
	actorBonus := float64(actorLinked) / float64(len(m.iocs)) * 0.3
	return math.Min(avgConf+actorBonus, 1.0)
}

func (m *ATTACKModule) computeSectorScore(stages []AttackStage) float64 {
	if len(m.aptGroups) == 0 {
		return 0
	}

	maxScore := 0.0
	for _, group := range m.aptGroups {
		score := m.checkSectorAlignment(stages, group)
		if score > maxScore {
			maxScore = score
		}
	}
	return maxScore
}

func (m *ATTACKModule) computeKillChainCoherence(stages []AttackStage) float64 {
	if len(stages) < 2 {
		return 0.5
	}

	coherentTransitions := 0
	totalTransitions := 0

	for i := 0; i < len(stages)-1; i++ {
		for _, rule := range causalRules {
			if rule.CauseTech == stages[i].TechniqueID && rule.EffectTech == stages[i+1].TechniqueID {
				coherentTransitions++
				break
			}
		}
		totalTransitions++
	}

	if totalTransitions == 0 {
		return 0.5
	}

	return float64(coherentTransitions) / float64(totalTransitions)
}

func (m *ATTACKModule) inferBayesian(network *BayesianNetwork, evidence map[string]string) map[string]float64 {
	attributionNode := network.Nodes["attribution"]
	if attributionNode == nil {
		return map[string]float64{"unknown": 1.0}
	}

	stateIndex := func(node *BayesianNode, state string) int {
		for i, s := range node.States {
			if s == state {
				return i
			}
		}
		return len(node.States) - 1
	}

	parentIndices := make([]int, len(attributionNode.Parents))
	for i, parentName := range attributionNode.Parents {
		parentNode := network.Nodes[parentName]
		if parentNode == nil {
			parentIndices[i] = len(parentNode.States) - 1
			continue
		}
		if state, ok := evidence[parentName]; ok {
			parentIndices[i] = stateIndex(parentNode, state)
		} else {
			parentIndices[i] = len(parentNode.States) - 1
		}
	}

	stride := 1
	for p := len(attributionNode.Parents) - 1; p > 0; p-- {
		parentNode := network.Nodes[attributionNode.Parents[p]]
		if parentNode != nil {
			stride *= len(parentNode.States)
		}
	}

	rowIndex := 0
	for p, idx := range parentIndices {
		s := 1
		for q := p + 1; q < len(parentIndices); q++ {
			parentNode := network.Nodes[attributionNode.Parents[q]]
			if parentNode != nil {
				s *= len(parentNode.States)
			}
		}
		rowIndex += idx * s
	}

	if rowIndex >= len(attributionNode.CPT) {
		return map[string]float64{"unknown": 1.0}
	}

	probs := make(map[string]float64)
	row := attributionNode.CPT[rowIndex]
	total := 0.0
	for _, p := range row {
		total += p
	}
	if total == 0 {
		total = 1.0
	}
	for i, state := range attributionNode.States {
		probs[state] = math.Round(row[i]/total*1000) / 1000
	}

	return probs
}

func (m *ATTACKModule) FilterBeaconWithReputation(detections []BeaconDetection) []BeaconDetection {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var filtered []BeaconDetection
	for _, det := range detections {
		isKnownLegitimate := false

		for _, entry := range m.reputationDB {
			if strings.Contains(strings.ToLower(det.Destination), strings.ToLower(entry.Destination)) {
				if entry.IsLegitimate && entry.Category == "time_sync" && det.Jitter < 0.1 {
					isKnownLegitimate = true
					logger.WithComponent("attck.beacon").Info("beacon filtered by reputation",
						"destination", det.Destination, "category", entry.Category,
						"jitter", det.Jitter, "reason", entry.Reason)
					break
				}
			}
		}

		if !isKnownLegitimate {
			filtered = append(filtered, det)
		}
	}

	logger.WithComponent("attck.beacon").Info("beacon reputation filtering completed",
		"input", len(detections), "output", len(filtered), "filtered", len(detections)-len(filtered))

	return filtered
}

func (m *ATTACKModule) AddReputationEntry(entry ReputationEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.reputationDB = append(m.reputationDB, entry)
	logger.WithComponent("attck.beacon").Info("reputation entry added",
		"destination", entry.Destination, "category", entry.Category, "legitimate", entry.IsLegitimate)
}

func (m *ATTACKModule) GetReputationEntries(category string) []ReputationEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []ReputationEntry
	for _, entry := range m.reputationDB {
		if category != "" && entry.Category != category {
			continue
		}
		result = append(result, entry)
	}
	return result
}

func (m *ATTACKModule) LoadYARARules(rules []YARARule) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	loaded := 0
	for i := range rules {
		if rules[i].ID == "" || rules[i].Name == "" || rules[i].RuleContent == "" {
			continue
		}
		if rules[i].TechniqueID == "" {
			continue
		}
		rules[i].Enabled = true
		m.yaraRules = append(m.yaraRules, rules[i])
		loaded++
	}

	logger.WithComponent("attck.rules").Info("YARA rules loaded", "total", len(rules), "valid", loaded)
	return loaded
}

func (m *ATTACKModule) LoadSigmaRules(rules []SigmaRule) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	loaded := 0
	for i := range rules {
		if rules[i].ID == "" || rules[i].Name == "" || rules[i].Detection == "" {
			continue
		}
		if rules[i].TechniqueID == "" {
			continue
		}
		rules[i].Enabled = true
		m.sigmaRules = append(m.sigmaRules, rules[i])
		loaded++
	}

	logger.WithComponent("attck.rules").Info("Sigma rules loaded", "total", len(rules), "valid", loaded)
	return loaded
}

func (m *ATTACKModule) MatchYARARules(hostID string, filePaths []string, fileContents map[string]string) []RuleMatchResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []RuleMatchResult

	for _, rule := range m.yaraRules {
		if !rule.Enabled {
			continue
		}

		for path, content := range fileContents {
			if m.matchYARAPattern(rule.RuleContent, content) {
				results = append(results, RuleMatchResult{
					RuleID:      rule.ID,
					RuleName:    rule.Name,
					RuleType:    "yara",
					TechniqueID: rule.TechniqueID,
					TacticIDs:   rule.TacticIDs,
					Severity:    rule.Severity,
					MatchDetail: fmt.Sprintf("YARA rule '%s' matched on file %s", rule.Name, path),
					HostID:      hostID,
					Confidence:  0.8,
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return results
}

func (m *ATTACKModule) MatchSigmaRules(hostID string, logEntries []map[string]string) []RuleMatchResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []RuleMatchResult

	for _, rule := range m.sigmaRules {
		if !rule.Enabled {
			continue
		}

		for _, entry := range logEntries {
			if m.matchSigmaPattern(rule, entry) {
				results = append(results, RuleMatchResult{
					RuleID:      rule.ID,
					RuleName:    rule.Name,
					RuleType:    "sigma",
					TechniqueID: rule.TechniqueID,
					TacticIDs:   rule.TacticIDs,
					Severity:    rule.Severity,
					MatchDetail: fmt.Sprintf("Sigma rule '%s' matched on log entry", rule.Name),
					HostID:      hostID,
					Confidence:  0.75,
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	return results
}

func (m *ATTACKModule) matchYARAPattern(ruleContent string, fileContent string) bool {
	keywords := extractYARAKeywords(ruleContent)
	if len(keywords) == 0 {
		return false
	}

	matched := 0
	for _, kw := range keywords {
		if strings.Contains(fileContent, kw) {
			matched++
		}
	}

	return matched > 0 && float64(matched)/float64(len(keywords)) >= 0.5
}

func (m *ATTACKModule) matchSigmaPattern(rule SigmaRule, entry map[string]string) bool {
	if rule.LogSource != "" {
		if source, ok := entry["source"]; ok && source != rule.LogSource {
			return false
		}
	}

	keywords := strings.Fields(rule.Detection)
	if len(keywords) == 0 {
		return false
	}

	matched := 0
	for _, kw := range keywords {
		kw = strings.Trim(kw, "\"'|{}[]()")
		if kw == "" || len(kw) < 3 {
			continue
		}
		for _, v := range entry {
			if strings.Contains(strings.ToLower(v), strings.ToLower(kw)) {
				matched++
				break
			}
		}
	}

	return matched > 0 && float64(matched)/float64(len(keywords)) >= 0.3
}

func extractYARAKeywords(ruleContent string) []string {
	var keywords []string
	lines := strings.Split(ruleContent, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "$") && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				value := strings.TrimSpace(parts[1])
				value = strings.Trim(value, " \"")
				if len(value) >= 3 {
					keywords = append(keywords, value)
				}
			}
		}
	}
	return keywords
}

func (m *ATTACKModule) AnalyzeCrossHostConnections(connections []CrossHostConnection) []LateralMovementEvidence {
	m.mu.Lock()
	defer m.mu.Unlock()

	hostConnections := make(map[string][]CrossHostConnection)
	for _, conn := range connections {
		hostConnections[conn.SourceHost] = append(hostConnections[conn.SourceHost], conn)
	}

	var evidences []LateralMovementEvidence

	for sourceHost, conns := range hostConnections {
		var targetHosts []string
		var anomalousConns []CrossHostConnection
		techniqueCounts := make(map[string]int)

		for _, conn := range conns {
			if conn.IsAnomalous {
				anomalousConns = append(anomalousConns, conn)
				found := false
				for _, h := range targetHosts {
					if h == conn.DestHost {
						found = true
						break
					}
				}
				if !found {
					targetHosts = append(targetHosts, conn.DestHost)
				}
				if conn.TechniqueID != "" {
					techniqueCounts[conn.TechniqueID]++
				}
			}
		}

		if len(anomalousConns) == 0 {
			continue
		}

		topTechnique := "T1021"
		maxCount := 0
		for tech, count := range techniqueCounts {
			if count > maxCount {
				maxCount = count
				topTechnique = tech
			}
		}

		score := m.computeLateralMovementScore(anomalousConns, targetHosts)

		evidence := LateralMovementEvidence{
			SourceHost:  sourceHost,
			TargetHosts: targetHosts,
			TechniqueID: topTechnique,
			Connections: anomalousConns,
			Score:       math.Round(score*1000) / 1000,
			Timestamp:   time.Now(),
		}

		evidences = append(evidences, evidence)
	}

	sort.Slice(evidences, func(i, j int) bool {
		return evidences[i].Score > evidences[j].Score
	})

	logger.WithComponent("attck.lateral").Info("cross-host analysis completed",
		"total_connections", len(connections), "evidences", len(evidences))

	return evidences
}

func (m *ATTACKModule) computeLateralMovementScore(conns []CrossHostConnection, targets []string) float64 {
	connScore := math.Min(float64(len(conns))/10.0, 1.0) * 0.4
	targetScore := math.Min(float64(len(targets))/5.0, 1.0) * 0.3

	serviceDiversity := make(map[string]bool)
	for _, c := range conns {
		if c.Service != "" {
			serviceDiversity[c.Service] = true
		}
	}
	diversityScore := math.Min(float64(len(serviceDiversity))/3.0, 1.0) * 0.3

	return connScore + targetScore + diversityScore
}
