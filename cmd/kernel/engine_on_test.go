//go:build engine

package main

import (
	"context"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/model"
	ssamlib "github.com/chins-xing/ssam"
)

// TestAssemblyRootInstallsEdgeFactorModel 校验**装配根**的行为（Task 7 验收条件 7）：
// cmd/kernel 通过 newSSAMEngineAdapter 创建的适配器，必须已经按同一份 cfg 装载了边缘因子
// 合成模型 —— 即"启动时装配一次，任何构造路径都装到位"。
//
// 判据用输出的溯源戳记（model/params_hash）与评分本身：两者都只有在引擎真的装载并使用了
// 那套参数时才会出现/改变。
func TestAssemblyRootInstallsEdgeFactorModel(t *testing.T) {
	t.Cleanup(func() {
		ssamlib.RegisterEdgeFactorStrategy(nil)
		ssamlib.RegisterDomainAdjust(nil)
	})

	t.Run("启用模型段：装配根装载参数并接入评分", func(t *testing.T) {
		eng := newSSAMEngineAdapter(graphAssemblyConfig())
		if eng == nil {
			t.Fatal("engine 构建标签下 newSSAMEngineAdapter 不得返回 nil")
		}
		result := assemblyResult(graphAssemblyChecks())
		if err := eng.ComputeScore(context.Background(), result); err != nil {
			t.Fatalf("ComputeScore: %v", err)
		}
		if result.EdgeFactors.Model != "graph" || result.EdgeFactors.ParamsHash == "" {
			t.Fatalf("装配根必须先装载模型再评分：戳记 = (%q,%q)",
				result.EdgeFactors.Model, result.EdgeFactors.ParamsHash)
		}
		// 域分 90 被 P_AS = 0.2+0.8·exp(-0.25) 修正 ⇒ 总分 87.04；未装配时是 72.5（乘性路径）。
		if result.FinalScore != 87.04 {
			t.Fatalf("装配根配置评分 = %v, want 87.04（域级修正必须生效）", result.FinalScore)
		}
	})

	t.Run("出厂配置：零注册，评分与历史一致且不盖戳", func(t *testing.T) {
		cfg := config.Default()
		eng := newSSAMEngineAdapter(cfg)
		result := assemblyResult([]model.CheckResult{
			{CheckID: "EF-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -10},
			{CheckID: "OT-005", Domain: model.DomainOperationTrust, Passed: false, Delta: -10},
			{CheckID: "RS-006", Domain: model.DomainResilience, Passed: false},
			{CheckID: "RS-007", Domain: model.DomainResilience, Passed: false},
		})
		if err := eng.ComputeScore(context.Background(), result); err != nil {
			t.Fatalf("ComputeScore: %v", err)
		}
		if result.EdgeFactors.Model != "" || result.EdgeFactors.ParamsHash != "" {
			t.Fatalf("未配置模型段时不得盖戳：(%q,%q)", result.EdgeFactors.Model, result.EdgeFactors.ParamsHash)
		}
		if result.FinalScore != 73.9 {
			t.Fatalf("出厂配置评分 = %v, want 73.9（历史值，逐位一致）", result.FinalScore)
		}
	})
}

func assemblyResult(checks []model.CheckResult) *model.AssessmentResult {
	return &model.AssessmentResult{
		HostID: "assembly-root-host", Threshold: 60, SPCScore: 1.0, ThreatCoeff: 1.0, Checks: checks,
	}
}

// graphAssemblyConfig 与 internal/engine/ssam 的接线夹具同形（单域 graph + 一个小写 ID 的
// 自定义因子），这里独立定义以示装配根只依赖 config 结构，不依赖测试助手。
func graphAssemblyConfig() *config.Config {
	return &config.Config{
		Weights:     model.Weights{AttackSurface: 1},
		Threshold:   60,
		ThreatCoeff: 1.0,
		EdgeFactors: model.EdgeFactors{
			TwoFactorFailure: 0.85, SYNCookieDisabled: 0.75, SELinuxDisabled: 0.80,
			AppArmorDisabled: 0.82, NoSIEM: 0.90, NoIDS: 0.88,
		},
		EdgeFactorsCustom: map[string]config.CustomEdgeFactorConfig{
			"ef-a": {Factor: 0.5, TriggerCheck: "CHK-A"},
		},
		EdgeFactorModel: config.EdgeFactorModelConfig{
			Model:  "graph",
			PFloor: 0.2,
			Lambda: map[string]float64{"attack_surface": 1.0},
			Vectors: map[string]map[string]float64{
				"EF-A": {
					"attack_surface": 0.5, "business_continuity": 0,
					"operation_trust": 0, "resilience": 0, "kernel_security": 0,
				},
			},
		},
	}
}

func graphAssemblyChecks() []model.CheckResult {
	return []model.CheckResult{
		{CheckID: "CHK-A", Domain: model.DomainAttackSurface, Passed: false},
		{CheckID: "AS-001", Domain: model.DomainAttackSurface, Passed: false, Delta: -10},
	}
}
