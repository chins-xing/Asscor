//go:build engine && assessor

package engine

import (
	"math"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
)

// 方向①（情报可信度原生变量）在 **legacy 动态评分路径** 上的规则表接线。
//
// 背景（实测发现）：插件路径 `internal/engine/ssam` 的 `EngineAdapter.ComputeScore`
// 会在映射前调用 `ssam.ResolveCheckConfidence(cfg, result)`，而 legacy 路径
// （`cmd/asscor` 走的就是它）此前**没有任何调用点** ⇒ 同一份 `[confidence.check]`
// 在 `asscor` 上完全不生效（实测：开规则表后分数 63.79 一动不动、evidence_confidence 仍是 1），
// 在插件路径上却生效 —— 两条路径的分数口径分叉。
//
// 本测试钉住修复后的行为：规则表必须在 `legacyCheckInputs` 里落到 CheckInput.Confidence，
// 且**五级优先级**（精确 ID > 正则 > 来源 > 域 > default）逐级可验。
func TestLegacyCheckInputsResolvesConfidenceRules(t *testing.T) {
	cfg, err := config.Parse(`
[confidence]
enabled = true
default = 1.0
floor = 0.05

[confidence.check]
OT-008 = 0.50

[confidence.checkrx]
^ot-0 = 0.30

[confidence.source]
user = 0.80

[confidence.domain]
resilience = 0.60
`)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	a := &Assessor{cfg: cfg}
	res := &model.AssessmentResult{Checks: []model.CheckResult{
		{CheckID: "OT-008", Domain: "operation_trust", Passed: false, Delta: -5},                                // check
		{CheckID: "OT-009", Domain: "operation_trust", Passed: false, Delta: -5},                                // checkrx
		{CheckID: "USR-001", Domain: "attack_surface", Passed: false, Delta: -5, Source: model.CheckSourceUser}, // source
		{CheckID: "RS-016", Domain: "resilience", Passed: false, Delta: -5},                                     // domain
		{CheckID: "AS-003", Domain: "attack_surface", Passed: false, Delta: -5},                                 // default
	}}

	inputs := a.legacyCheckInputs(res)
	want := []float64{0.50, 0.30, 0.80, 0.60, 1.00}
	levels := []string{"check", "checkrx", "source", "domain", "default"}
	for i, w := range want {
		if math.Abs(inputs[i].Confidence-w) > 1e-9 {
			t.Errorf("%s 层级未生效：[%s] 期望 %v，得到 %v",
				levels[i], res.Checks[i].CheckID, w, inputs[i].Confidence)
		}
	}

	// 关闭时必须是 no-op（历史逐位兼容：Confidence 保持 0，由库按 1.0 处理）。
	off, err := config.Parse("[confidence]\nenabled = false\n")
	if err != nil {
		t.Fatalf("parse off config: %v", err)
	}
	b := &Assessor{cfg: off}
	res2 := &model.AssessmentResult{Checks: []model.CheckResult{
		{CheckID: "OT-008", Domain: "operation_trust", Passed: false, Delta: -5},
	}}
	if got := b.legacyCheckInputs(res2)[0].Confidence; got != 0 {
		t.Errorf("disabled 时不得写入 confidence（want 0 = 未指定），got %v", got)
	}
}
