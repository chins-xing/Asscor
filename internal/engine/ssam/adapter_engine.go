//go:build engine

package ssam

import (
	"context"
	"time"

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

		// 观测链（Task 1 / spec §5.1 的 observed.edge_factor_chain[]）：与溯源戳**同一处、
		// 同一判据**的另一种落地 —— 没装载就既不该盖戳、也不该输出链。
		//
		// 两个来源都不是"再看一眼配置"推出来的：
		//   - 因子集合与观测值来自本次评分**自己的输出**（output.EdgeFactors）；
		//   - 触发检查来自配置层的**解析结果**（默认表 + trigger.* 覆盖，两条评分路径共用
		//     的同一张表），因为内仓结果类型没有该字段，也不该知道配置层的触发映射。
		result.EdgeFactorChain = observeEdgeFactorChain(
			output.EdgeFactors, config.ResolveEdgeFactorTriggerMap(a.confCfgPtr()), time.Now())
	} else {
		// 未装载（未配置 / 参数不可用 / 已热重载为未启用）：不留任何链。写 nil 而不是不动它，
		// 是为了让"同一个 result 被再次评分"时不会残留上一次的观测链（假溯源）。
		result.EdgeFactorChain = nil
	}
	return nil
}

// observeEdgeFactorChain 把本次评分的逐因子结果映射成输出层的观测链（spec §5.1）。
//
// 三条口径（Task 1 裁定，改任何一条都会改变离线重算的含义）：
//
//  1. EffectiveFactor 写**在线观测值** —— 即内仓策略层 ApplyEdgeFactorsToChecksPolicy 已按
//     可信度衰减一次后的值（EdgeFactorResult.Factor），**不是**配置里的因子权重 f_i。
//     对 V/G/C 而言装配层会再衰减一次（eff = edgefactor.EffectiveFactor(观测值, c)，
//     合计 c²），这是 spec §10.2 的**已知口径差**：记录描述"引擎看到了什么"，口径差由
//     离线重算与报告负责标注，此处刻意不做任何补偿（补偿会改评分）。
//  2. TS 取**评分时刻**（本进程时间），不是检查的采集时刻 —— 内仓结果类型与
//     model.CheckResult 都没有时间字段。它满足 chain 模型"每个激活因子必须带非零时间戳"
//     的前提；同一场景内的相对顺序由写出顺序保证（= 内仓的因子结果序 = 因子 ID 序）。
//  3. Active == false 的项**不写进链**：它们没有产生任何惩罚，写进去会让离线重算凭空
//     产生惩罚（与"丢弃未建模因子"是同一类纪律）。EF-3FA 正是这一类（CascadeOnly，
//     它的影响已经体现在 EF-002FA 的观测值上）。
//
// TriggerCheck 只从**配置层解析结果**查得（config.ResolveEdgeFactorTriggerMap），而不是
// 重新读一遍 [edge_factors.model] 段：解析结果才是两条评分路径共用的同一张表。
// 解析表里没有该因子时（自定义因子）留空，绝不编造一个检查 ID。
func observeEdgeFactorChain(factors []EdgeFactorResult, triggers map[string]string, at time.Time) []model.EdgeFactorObservation {
	ts := at.UTC().Format(time.RFC3339)
	chain := make([]model.EdgeFactorObservation, 0, len(factors))
	for _, f := range factors {
		if !f.Active {
			continue
		}
		id := NormalizeFactorID(f.ID)
		chain = append(chain, model.EdgeFactorObservation{
			Factor:          id,
			TriggerCheck:    triggers[id],
			CTrigger:        f.TriggerConfidence,
			EffectiveFactor: f.Factor,
			TS:              ts,
		})
	}
	return chain
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
