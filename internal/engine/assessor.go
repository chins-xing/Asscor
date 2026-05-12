package engine

import (
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"github.com/argus-security/argus/internal/checks"
	"github.com/argus-security/argus/internal/config"
	"github.com/argus-security/argus/internal/model"
)

type Assessor struct {
	cfg          *config.Config
	maxWorkers   int
	resultsCache sync.Map
	mu           sync.RWMutex
}

func NewAssessor(cfg *config.Config) *Assessor {
	return &Assessor{
		cfg:        cfg,
		maxWorkers: 10,
	}
}

func (a *Assessor) Assess() *model.AssessmentResult {
	hostname, _ := os.Hostname()
	result := &model.AssessmentResult{
		HostID:    hostname,
		Hostname:  hostname,
		Timestamp: time.Now(),
		Threshold: a.cfg.Threshold,
	}

	items := checks.GetAll()
	if len(items) == 0 {
		result.Acceptable = true
		result.FinalScore = 100
		result.DomainScores = model.DomainScores{
			AttackSurface:      100,
			BusinessContinuity: 100,
			OperationTrust:     100,
			Resilience:         100,
		}
		result.ThreatCoeff = a.cfg.ThreatCoeff
		result.SPCScore = 1.0
		return result
	}

	a.runChecksConcurrently(items, result)

	a.computeDomainScores(result)

	a.evaluateEdgeFactors(result)

	result.ThreatCoeff = a.cfg.ThreatCoeff
	result.SPCScore = 1.0

	result.FinalScore = a.computeFinalScore(result)
	result.Acceptable = result.FinalScore >= result.Threshold

	return result
}

func (a *Assessor) runChecksConcurrently(items []model.CheckItem, result *model.AssessmentResult) {
	sem := make(chan struct{}, a.maxWorkers)
	var wg sync.WaitGroup
	resultsCh := make(chan model.CheckResult, len(items))

	for _, item := range items {
		wg.Add(1)
		go func(it model.CheckItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resultsCh <- it.Run()
		}(item)
	}

	wg.Wait()
	close(resultsCh)

	for r := range resultsCh {
		result.Checks = append(result.Checks, r)
	}
}

func (a *Assessor) computeDomainScores(result *model.AssessmentResult) {
	domainDeltas := make(map[string]float64)
	for _, domain := range model.AllDomains {
		domainDeltas[domain] = 100
	}

	for _, check := range result.Checks {
		if check.Passed {
			continue
		}
		delta := a.cfg.CheckDeltas[check.CheckID]
		if delta == 0 {
			delta = check.Delta
		}
		domainDeltas[check.Domain] = math.Max(0, domainDeltas[check.Domain]+delta)
	}

	result.DomainScores = model.DomainScores{
		AttackSurface:      math.Max(0, domainDeltas[model.DomainAttackSurface]),
		BusinessContinuity: math.Max(0, domainDeltas[model.DomainBusinessContinuity]),
		OperationTrust:     math.Max(0, domainDeltas[model.DomainOperationTrust]),
		Resilience:         math.Max(0, domainDeltas[model.DomainResilience]),
	}
}

func (a *Assessor) evaluateEdgeFactors(result *model.AssessmentResult) {
	result.EdgeFactors = model.EdgeFactors{
		TwoFactorFailure:     1.0,
		SynCookieOff:         1.0,
		ResourceCritical:     1.0,
		SupplyChainUnchecked: 1.0,
		AutoBlockNoWhitelist: 1.0,
	}

	for _, check := range result.Checks {
		if check.Passed {
			continue
		}
		switch check.CheckID {
		case "RS-005":
			p, _ := a.checkPassed("RS-005", result)
			if !p {
				result.EdgeFactors.SynCookieOff = a.cfg.EdgeFactors.SynCookieOff
			}
		}
	}
}

func (a *Assessor) checkPassed(id string, result *model.AssessmentResult) (bool, string) {
	for _, c := range result.Checks {
		if c.CheckID == id {
			return c.Passed, c.Detail
		}
	}
	return true, ""
}

func (a *Assessor) computeFinalScore(result *model.AssessmentResult) float64 {
	weights := a.cfg.Weights
	weightedSum := result.DomainScores.AttackSurface*weights.AttackSurface +
		result.DomainScores.BusinessContinuity*weights.BusinessContinuity +
		result.DomainScores.OperationTrust*weights.OperationTrust +
		result.DomainScores.Resilience*weights.Resilience

	baseScore := weightedSum / 100

	factors := result.EdgeFactors.ActiveFactors()
	for _, f := range factors {
		baseScore *= f
	}

	baseScore *= result.ThreatCoeff
	baseScore *= result.SPCScore

	return math.Round(baseScore*100) / 100
}

func (a *Assessor) PrintReport(result *model.AssessmentResult) string {
	var status string
	if result.Acceptable {
		status = "可接受 ✓"
	} else {
		status = "不可接受 ✗"
	}

	report := fmt.Sprintf(`
╔══════════════════════════════════════════════════════════════╗
║              ARGUS 1.2 安全可接受性评估报告                    ║
╠══════════════════════════════════════════════════════════════╣
║  主机: %-50s ║
║  时间: %-50s ║
╠══════════════════════════════════════════════════════════════╣
║  最终得分: %6.2f / 100    阈值: %6.2f    状态: %-12s ║
╠══════════════════════════════════════════════════════════════╣
║  核心域得分:                                                 ║
║    攻击面管理:   %6.2f  (权重 %4.1f)                        ║
║    业务连续性:   %6.2f  (权重 %4.1f)                        ║
║    操作可信度:   %6.2f  (权重 %4.1f)                        ║
║    韧性:         %6.2f  (权重 %4.1f)                        ║
╠══════════════════════════════════════════════════════════════╣
║  威胁系数 μ: %6.2f    SPC修正: %6.2f                       ║
╚══════════════════════════════════════════════════════════════╝
`,
		result.Hostname,
		result.Timestamp.Format("2006-01-02 15:04:05"),
		result.FinalScore,
		result.Threshold,
		status,
		result.DomainScores.AttackSurface,
		a.cfg.Weights.AttackSurface,
		result.DomainScores.BusinessContinuity,
		a.cfg.Weights.BusinessContinuity,
		result.DomainScores.OperationTrust,
		a.cfg.Weights.OperationTrust,
		result.DomainScores.Resilience,
		a.cfg.Weights.Resilience,
		result.ThreatCoeff,
		result.SPCScore,
	)

	failedCount := 0
	for _, c := range result.Checks {
		if !c.Passed {
			failedCount++
		}
	}

	report += fmt.Sprintf("\n检查项汇总: %d 项检查, %d 项通过, %d 项未通过\n\n",
		len(result.Checks), len(result.Checks)-failedCount, failedCount)

	if failedCount > 0 {
		report += "未通过检查项详情:\n"
		report += fmt.Sprintf("%-12s %-8s %-24s %s\n", "检查ID", "域", "名称", "详情")
		report += fmt.Sprintf("%s\n", "--------------------------------------------------------------------------------")
		for _, c := range result.Checks {
			if !c.Passed {
				report += fmt.Sprintf("%-12s %-8s %-24s %s\n", c.CheckID, c.Domain, c.Name, c.Detail)
			}
		}
	}

	return report
}
