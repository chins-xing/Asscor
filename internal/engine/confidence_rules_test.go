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
// 本测试钉住修复后的行为：规则表必须在 `legacyCheckInputs` 里落到 CheckInput.Confidence。
func TestLegacyCheckInputsResolvesConfidenceRules(t *testing.T) {
	cfg, err := config.Parse(`
[confidence]
enabled = true
default = 1.0
floor = 0.05

[confidence.check]
OT-008 = 0.50

[confidence.source]
builtin = 0.80
`)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	a := &Assessor{cfg: cfg}
	res := &model.AssessmentResult{Checks: []model.CheckResult{
		{CheckID: "OT-008", Domain: "operation_trust", Passed: false, Delta: -5},
		{CheckID: "OT-999", Domain: "operation_trust", Passed: false, Delta: -4},
	}}

	inputs := a.legacyCheckInputs(res)
	if len(inputs) != 2 {
		t.Fatalf("inputs = %d, want 2", len(inputs))
	}
	if math.Abs(inputs[0].Confidence-0.50) > 1e-9 {
		t.Errorf("按检查 ID 的规则未生效：[confidence.check] OT-008 = 0.50，got %v", inputs[0].Confidence)
	}
	if math.Abs(inputs[1].Confidence-0.80) > 1e-9 {
		t.Errorf("按来源的规则未生效：[confidence.source] builtin = 0.80，got %v", inputs[1].Confidence)
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
