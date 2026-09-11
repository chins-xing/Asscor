//go:build engine

package ssam

import (
	"context"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/engine"
	"github.com/chins-xing/asscor/internal/logger"
	"github.com/chins-xing/asscor/internal/model"
)

// EngineAdapter wraps ssam.Engine to implement engine.AssessorEngine.
// This is the bridge that makes SSAM into an ASSCOR plugin.
// Dependency direction: ssam → ASSCOR (not ASSCOR → ssam).
type EngineAdapter struct {
	engine *Engine
	// confCfg retains the kernel config used for per-check confidence
	// resolution right before each ComputeScore (per-check rule lookup happens
	// there, so it reflects hot-reloaded [confidence] rules via ReloadWeights).
	// It is also the config this adapter assembles the edge factor synthesis
	// model from (Task 7): the model params it hands to the engine are the ones
	// stamped into the output's provenance fields.
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
	// Task 7 的接线点：装配边缘因子合成模型（未配置 ⇒ 零注册，内仓默认路径逐位一致）。
	// 放在构造函数里（而不是只在 cmd/kernel 里调一次）是为了让**任何**构造路径都装到位 ——
	// 对进程级全局钩子来说，"少装一次"就是"评分用了上一个模型的参数"。
	// 参数不可用时不阻断构造（配置解析层已对格式 fail-fast），但会退回默认乘性路径，
	// 且不盖戳：输出绝不说自己用了某套参数。
	if err := e.ApplyEdgeFactorModel(cfg); err != nil {
		logger.WithComponent("ssam").Warn(
			"edge factor model not assembled — scoring stays on the default multiplicative path",
			"error", err)
	}
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

	// 溯源盖戳（Task 7 承接 Task 5 评审 I1 的交接条件）：判据是「**engine 已装载同一套
	// 参数**」—— 这里从 Engine 侧取**实际装载**的 Params/指纹，而不是再看一眼配置。
	//
	// 为什么必须是引擎侧：`[edge_factors.model]` 段是运维可达的，它的 trigger.* 覆盖
	// **独立于合成模型**就生效（ConfigToEdgeFactors 消费它），解析层又只要求"段存在必须有
	// model 键"，所以"配置里写了"≠"评分用了它"。只有 Engine 真的装载了参数（并且真的把
	// 它们接进了评分链），盖戳才是事实。
	//
	// 因此：参数不可用（ParamsFromConfig 报错、λ 缺失）⇒ 引擎未装载 ⇒ 留零值
	// （零值 + omitempty ⇒ JSON 里不出现 model/params_hash，历史输出格式不变），
	// 而不是写一个假指纹。盖戳必须在 OutputToModel **之后**：那次映射会用全新的
	// model.EdgeFactors 整体替换 result.EdgeFactors，之前的戳记会被静默覆盖。
	if p, loaded := a.engine.LoadedEdgeFactorParams(); loaded {
		result.EdgeFactors.Model = string(p.Model)
		result.EdgeFactors.ParamsHash = p.Hash()
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
	// 热重载必须**重装**合成模型：钩子是进程级全局状态、且闭包自带装配时的参数集，
	// 不重装就会让新配置继续用旧模型/旧参数评分，而溯源戳记又已随之清空或错位 ——
	// 「实际用的参数」与「声明的参数」必须永远同源（Task 7 验收条件 5/7）。
	if err := a.engine.ApplyEdgeFactorModel(cfg); err != nil {
		logger.WithComponent("ssam").Warn(
			"edge factor model not re-assembled on reload — scoring falls back to the default multiplicative path",
			"error", err)
	}
}

var _ engine.AssessorEngine = (*EngineAdapter)(nil)
