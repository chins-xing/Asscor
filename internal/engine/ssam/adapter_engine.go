//go:build engine

package ssam

import (
	"context"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/engine"
	"github.com/chins-xing/asscor/internal/model"
)

// EngineAdapter wraps ssam.Engine to implement engine.AssessorEngine.
// This is the bridge that makes SSAM into an ASSCOR plugin.
// Dependency direction: ssam → ASSCOR (not ASSCOR → ssam).
type EngineAdapter struct {
	engine *Engine
	// confCfg retains the kernel config used for confidence resolution
	// (per-check rule lookup happens right before each ComputeScore, so it
	// reflects hot-reloaded [confidence] rules via ReloadWeights).
	confCfg *config.Config
}

// NewEngineAdapter creates a new SSAM adapter that satisfies engine.AssessorEngine.
// Pass the returned value to Assessor.SetPluginEngine().
func NewEngineAdapter(cfg *config.Config) *EngineAdapter {
	e := NewEngine()
	if cfg != nil {
		e.SetWeights(ConfigToWeights(cfg))
		e.SetEdgeFactors(ConfigToEdgeFactors(cfg))
		e.SetConfidencePolicy(ConfigToConfidencePolicy(cfg))
	}
	e.InitializeDefaults(nil, nil)
	return &EngineAdapter{engine: e, confCfg: cfg}
}

// confCfgPtr returns the retained config (may be nil).
func (a *EngineAdapter) confCfgPtr() *config.Config { return a.confCfg }

func (a *EngineAdapter) ComputeScore(ctx context.Context, result *model.AssessmentResult) error {
	// Confidence-native: fill per-check confidences from the kernel rule
	// table before mapping into the library input (design §3). Results that
	// already carry an explicit upstream confidence are preserved.
	ResolveCheckConfidence(a.confCfgPtr(), result)

	input := &AssessmentInput{
		HostID:      result.HostID,
		Hostname:    result.Hostname,
		Threshold:   result.Threshold,
		Checks:      CheckResultsToInputs(result.Checks),
		ThreatCoeff: result.ThreatCoeff,
		SPCScore:    result.SPCScore,
	}
	output, err := a.engine.ComputeScore(ctx, input)
	if err != nil {
		return err
	}
	OutputToModel(output, result)
	// 溯源（spec §4 规则 4）：把「本次评分使用的模型 + 参数指纹」写进输出层，供实验报告
	// 与审计复现。三条边界一律留零值（omitempty ⇒ JSON 不输出）：
	//   - 未配置 [edge_factors.model]（出厂配置与全部历史配置都是如此）⇒ 走历史乘性路径，
	//     零值就是「未使用新模型」的表达，历史输出逐位不变（裁定 1）；
	//   - 模型段存在但参数不可用（ParamsFromConfig 报错）⇒ 宁可留空，也不写一个无法复现的
	//     指纹 —— 假指纹比缺指纹更糟，它会让审计以为这次评分可复现；
	//   - 指纹取自 ParamsFromConfig(a.confCfg)，即本次评分所用参数集的装配来源（Task 7 的
	//     ApplyEdgeFactorModel 消费同一份 cfg，故两者是同一套参数）。
	if cfg := a.confCfgPtr(); cfg != nil && cfg.EdgeFactorModel.Model != "" {
		if p, enabled, err := ParamsFromConfig(cfg); err == nil && enabled {
			result.EdgeFactors.Model = string(p.Model)
			result.EdgeFactors.ParamsHash = p.Hash()
		}
	}
	return nil
}

func (a *EngineAdapter) Name() string {
	return "ssam_v2.0"
}

func (a *EngineAdapter) ReloadWeights(cfg *config.Config) {
	if cfg == nil {
		return
	}
	a.confCfg = cfg
	a.engine.SetWeights(ConfigToWeights(cfg))
	a.engine.SetEdgeFactors(ConfigToEdgeFactors(cfg))
	a.engine.SetConfidencePolicy(ConfigToConfidencePolicy(cfg))
}

var _ engine.AssessorEngine = (*EngineAdapter)(nil)
