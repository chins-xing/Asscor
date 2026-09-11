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
	// confCfg retains the kernel config used for per-check confidence
	// resolution right before each ComputeScore (per-check rule lookup happens
	// there, so it reflects hot-reloaded [confidence] rules via ReloadWeights).
	// It is currently the only config the adapter reads while scoring: the
	// edge factor *model* params are NOT consumed here yet (see the provenance
	// note in ComputeScore — stamping stays off until Task 7 wires it up).
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
	// 溯源字段（model.EdgeFactors.Model / .ParamsHash）在此**刻意不盖戳**（Task 5 评审裁定 I1）。
	//
	// 为什么不盖：本函数今天无法证明「本次评分用了哪套参数」。ssam 的评分仍由内仓的默认乘性
	// 策略算出 —— edgefactor.Synthesize 在生产代码里没有调用方，ParamsFromConfig 的生产调用
	// 方也只有本文件（Task 5 初版曾在此盖戳）；而 [edge_factors.model] 段是**运维可达**的：
	// 它的 trigger.* 覆盖今天就生效（ConfigToEdgeFactors 消费它），且解析层要求「段存在必须
	// 有 model 键」，所以「配置里写了」不等于「评分用了它」。照配置盖戳会让输出**声称一个
	// 评分并未使用的模型**，比留空更糟 —— 宁可留空也不写假指纹（同理：参数不可用时更不能写）。
	//
	// Task 7 的前置条件：接线（ApplyEdgeFactorModel 真正装载参数并注册合成策略）之后才启用
	// 盖戳，判据必须是「engine 已装载同一套参数」（取 Engine 侧装载后的 params，而不是再看
	// 一眼配置），并由 Task 7 的验收条件断言「指纹 == 引擎实际装载参数的 Hash()，且热重载后
	// 仍相等」。在此之前两条真实评分路径（本适配器与 legacy）的 JSON 都不含这两个键，该
	// 「溯源超前窗口」由 internal/engine/ssam/provenance_test.go 与
	// internal/engine/assessor_provenance_test.go 显式钉住，而不是靠口头保证。
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
