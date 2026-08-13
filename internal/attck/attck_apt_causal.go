//go:build attck_ext

package attck

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

type CausalRelation struct {
	CauseTech  string  `json:"cause_technique"`
	EffectTech string  `json:"effect_technique"`
	Strength   float64 `json:"strength"`
	Reason     string  `json:"reason"`
}

type CausalChain struct {
	Relations []CausalRelation `json:"relations"`
	Score     float64          `json:"score"`
}

var causalRules = []CausalRelation{
	{CauseTech: "T1566", EffectTech: "T1059", Strength: 0.9, Reason: "phishing leads to command execution"},
	{CauseTech: "T1566", EffectTech: "T1204", Strength: 0.85, Reason: "phishing leads to user execution"},
	{CauseTech: "T1059", EffectTech: "T1003", Strength: 0.8, Reason: "command execution enables credential dumping"},
	{CauseTech: "T1059", EffectTech: "T1082", Strength: 0.7, Reason: "command execution enables system discovery"},
	{CauseTech: "T1003", EffectTech: "T1078", Strength: 0.85, Reason: "credential dump enables valid account usage"},
	{CauseTech: "T1078", EffectTech: "T1021", Strength: 0.8, Reason: "valid accounts enable lateral movement"},
	{CauseTech: "T1021", EffectTech: "T1071", Strength: 0.75, Reason: "lateral movement establishes C2 channels"},
	{CauseTech: "T1082", EffectTech: "T1087", Strength: 0.7, Reason: "system discovery leads to account discovery"},
	{CauseTech: "T1087", EffectTech: "T1003", Strength: 0.65, Reason: "account discovery targets credential access"},
	{CauseTech: "T1059", EffectTech: "T1071", Strength: 0.6, Reason: "command execution may establish C2"},
	{CauseTech: "T1190", EffectTech: "T1059", Strength: 0.85, Reason: "public app exploitation leads to command execution"},
	{CauseTech: "T1190", EffectTech: "T1210", Strength: 0.8, Reason: "public app exploitation enables remote services"},
	{CauseTech: "T1210", EffectTech: "T1021", Strength: 0.85, Reason: "exploitation of remote services enables lateral movement"},
	{CauseTech: "T1071", EffectTech: "T1048", Strength: 0.6, Reason: "C2 channel may use alternative protocols for exfil"},
	{CauseTech: "T1078", EffectTech: "T1098", Strength: 0.7, Reason: "valid accounts enable account manipulation"},
	{CauseTech: "T1059", EffectTech: "T1562", Strength: 0.65, Reason: "command execution may disable security tools"},
	{CauseTech: "T1562", EffectTech: "T1070", Strength: 0.7, Reason: "defense evasion leads to indicator removal"},
	{CauseTech: "T1021", EffectTech: "T1041", Strength: 0.6, Reason: "lateral movement enables data exfiltration via C2"},
	{CauseTech: "T1071", EffectTech: "T1041", Strength: 0.65, Reason: "C2 channel used for exfiltration"},
	{CauseTech: "T1005", EffectTech: "T1041", Strength: 0.7, Reason: "data collection precedes exfiltration"},
}

func (m *Module) buildCausalGraph(stages []AttackStage) map[string][]CausalRelation {
	graph := make(map[string][]CausalRelation)
	stageTechs := make(map[string]bool)
	for _, s := range stages {
		stageTechs[s.TechniqueID] = true
	}
	for _, rule := range causalRules {
		if stageTechs[rule.CauseTech] || stageTechs[rule.EffectTech] {
			graph[rule.CauseTech] = append(graph[rule.CauseTech], rule)
		}
	}
	return graph
}

func (m *Module) applyCausalReasoning(stages []AttackStage) []AttackStage {
	if len(stages) < 2 {
		return stages
	}

	graph := m.buildCausalGraph(stages)

	type stageWithCausal struct {
		stage        AttackStage
		causalScore  float64
		causalLinks  int
		predecessors []string
	}

	enriched := make([]stageWithCausal, len(stages))
	for i, s := range stages {
		enriched[i] = stageWithCausal{stage: s}
	}

	for i := range enriched {
		for j := range enriched {
			if i == j {
				continue
			}
			relations := graph[enriched[j].stage.TechniqueID]
			for _, r := range relations {
				if r.EffectTech == enriched[i].stage.TechniqueID {
					enriched[i].causalScore += r.Strength
					enriched[i].causalLinks++
					enriched[i].predecessors = append(enriched[i].predecessors, enriched[j].stage.TechniqueID)
				}
			}
		}
	}

	for i := range enriched {
		if enriched[i].causalLinks > 0 {
			avgCausal := enriched[i].causalScore / float64(enriched[i].causalLinks)
			boost := math.Min(avgCausal*0.15, 0.2)
			enriched[i].stage.Confidence = math.Min(enriched[i].stage.Confidence+boost, 1.0)
			enriched[i].stage.Confidence = math.Round(enriched[i].stage.Confidence*1000) / 1000
			if len(enriched[i].predecessors) > 0 {
				causeStr := strings.Join(enriched[i].predecessors, ", ")
				enriched[i].stage.Evidence = append(enriched[i].stage.Evidence,
					fmt.Sprintf("Causal link: %s → %s (avg_strength=%.2f)", causeStr, enriched[i].stage.TechniqueID, avgCausal))
			}
		}
	}

	sort.SliceStable(enriched, func(i, j int) bool {
		orderI, okI := tacticOrderMap[enriched[i].stage.TacticID]
		orderJ, okJ := tacticOrderMap[enriched[j].stage.TacticID]
		if !okI {
			orderI = 99
		}
		if !okJ {
			orderJ = 99
		}
		if orderI != orderJ {
			return orderI < orderJ
		}
		if enriched[i].causalScore != enriched[j].causalScore {
			return enriched[i].causalScore > enriched[j].causalScore
		}
		return enriched[i].stage.Timestamp.Before(enriched[j].stage.Timestamp)
	})

	result := make([]AttackStage, len(enriched))
	for i, e := range enriched {
		e.stage.Order = i + 1
		result[i] = e.stage
	}
	return result
}

func (m *Module) ComputeCausalChain(techniqueIDs []string) *CausalChain {
	chain := &CausalChain{}
	visited := make(map[string]bool)

	var walk func(current string, depth int)
	walk = func(current string, depth int) {
		if depth > 10 || visited[current] {
			return
		}
		visited[current] = true
		for _, rule := range causalRules {
			if rule.CauseTech == current {
				for _, id := range techniqueIDs {
					if id == rule.EffectTech {
						chain.Relations = append(chain.Relations, rule)
						walk(rule.EffectTech, depth+1)
						break
					}
				}
			}
		}
	}

	for _, id := range techniqueIDs {
		walk(id, 0)
	}

	totalStrength := 0.0
	for _, r := range chain.Relations {
		totalStrength += r.Strength
	}
	if len(chain.Relations) > 0 {
		chain.Score = math.Round(totalStrength/float64(len(chain.Relations))*1000) / 1000
	}
	return chain
}
