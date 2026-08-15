//go:build engine

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/engine"
	ascorprism "github.com/asscor/asscor/internal/engine/prism"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
	prismlib "github.com/chins-xing/prism"
)

var registeredASSCOrATTACKInit func(assessor *engine.Assessor, cfg *config.Config)

func main() {
	configPath := flag.String("config", "config.ini", "配置文件路径")
	jsonOutput := flag.Bool("json", false, "以JSON格式输出")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告: 无法加载配置文件 %s: %v\n使用默认配置\n", *configPath, err)
		cfg = config.Default()
	}

	assessor := engine.NewAssessor(cfg)

	attachSPC(cfg, assessor)

	if cfg.ATTACK.Enabled && registeredASSCOrATTACKInit != nil {
		registeredASSCOrATTACKInit(assessor, cfg)
		logger.WithComponent("main").Info("ATT&CK module initialized and attached to assessor")
	}

	result := assessor.Assess("", "")

	// SRD/Prism 三层风险分析（Core → Semantic → Inference）
	applyPrism(cfg, result)

	if *jsonOutput {
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	} else {
		fmt.Print(assessor.PrintReport(result))
	}

	if !result.Acceptable {
		os.Exit(1)
	}
}

// applyPrism runs the Prism SRD three-layer risk analysis on a single-host result.
func applyPrism(cfg *config.Config, result *model.AssessmentResult) {
	engine := ascorprism.NewEngine()

	pcfg := engine.Config()
	ac := cfg.AdapterConfig
	if v := parseF(ac["prism.score_floor"]); v > 0 {
		pcfg.ScoreFloor = v
	}
	if v := parseF(ac["prism.debt_alpha"]); v > 0 {
		pcfg.DebtAlpha = v
	}
	engine.UpdateConfig(pcfg)

	hostID := result.HostID
	if hostID == "" {
		hostID = "localhost"
	}

	node := &prismlib.NodeState{
		HostID:    hostID,
		SSAMScore: result.FinalScore,
	}
	for _, c := range result.Checks {
		if !c.Passed {
			node.FailedChecks = append(node.FailedChecks, prismlib.CheckFailure{
				CheckID: c.CheckID,
				Delta:   c.Delta,
			})
		}
	}

	allNodes := map[string]*prismlib.NodeState{hostID: node}
	prismResult := engine.ComputeDynamicScore(node, nil, allNodes, time.Now().Unix())

	result.PrismScore = prismResult.PrismScore
	result.PrismExternalRisk = prismResult.ExternalRisk
	result.PrismPropRisk = prismResult.PropagatedRisk
	result.PrismDebtRaw = prismResult.DebtRaw
	result.PrismRiskVelocity = prismResult.RiskVelocity

	semantic := engine.ComputeSemanticState(&prismResult)
	if semantic != nil {
		result.PrismSemanticState = semantic.CurrentState
		result.PrismStateVector = semantic.StateVector
		result.PrismStableMem = semantic.StableMembership
		result.PrismDegradedMem = semantic.DegradedMembership
		result.PrismUntrustedMem = semantic.UntrustedMembership
		result.PrismCollapseMem = semantic.CollapseMembership
	}

	future := engine.PredictFuture(semantic, nil)
	if future != nil {
		result.PrismInferenceTrend = future.Trend
		result.PrismInferenceCollapseRisk = future.CollapseRisk
	}

	logger.WithComponent("main").Info("Prism SRD analysis complete",
		"prism_score", result.PrismScore,
		"semantic_state", result.PrismSemanticState,
		"trend", result.PrismInferenceTrend)
}

func parseF(s string) float64 {
	var f float64
	fmt.Sscanf(s, "%f", &f)
	return f
}
