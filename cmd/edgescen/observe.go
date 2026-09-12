//go:build expr && engine && checks

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/chins-xing/asscor/internal/checks"
	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgeexp"
	"github.com/chins-xing/asscor/internal/edgefactor"
	"github.com/chins-xing/asscor/internal/engine"
	enginessam "github.com/chins-xing/asscor/internal/engine/ssam"
	"github.com/chins-xing/asscor/internal/model"
	ssam "github.com/chins-xing/ssam"
)

// ============================================================================
// 宿主检查：真实结果 + 注入
// ============================================================================

// runHostChecks 取该主机的**真实**检查结果：遍历引擎的检查登记表（`internal/checks`）逐个执行。
//
// 为什么必须"真实结果 + 指定注入"而不是"按场景凭空造检查集"（spec §2.3）：实验要回答的是
// "这套部署在真实状态下的判定行为"，其余检查的通过/失败必须来自目标机的真实观测 ——
// 凭空造一条"只有注入检查失败"的检查集，会让域分与真实部署毫无关系（而报告照常打印）。
//
// 顺序执行：每个场景只跑一次，且引擎侧 `CheckItem.Run()` 会读文件/派生进程，并发只会让
// 诊断信息交错而换不来可观测收益。登记表为空（未带 `checks` tag 构建）时返回空集 ——
// 这时任何注入都无从执行，`collectChecks` 会明确报错而不是产出一条"什么都没失败"的记录。
func runHostChecks() []model.CheckResult {
	items := checks.GetAll()
	out := make([]model.CheckResult, 0, len(items))
	for _, item := range items {
		out = append(out, item.Run())
	}
	return out
}

// injectionPlan 是场景在当前配置下解析出的**可执行**注入计划。
type injectionPlan struct {
	// Phases 与 `scenarioSpec.Inject` 一一对应：每个阶段里要判为失败的检查 ID
	// （已由因子经 `config.ResolveEdgeFactorTriggerMap` 解析而来）。
	Phases [][]string
	// Checks 是阶段顺序扁平的检查 ID 列表（保留重复，例如两个因子共用一个触发检查）。
	Checks []string
	// FactorOf 记录每个检查由哪些因子解析而来（仅用于诊断信息，不参与判定）。
	FactorOf map[string][]string
}

// injectedChecks 返回去重后的注入检查 ID（按首次出现顺序）。
func (p injectionPlan) injectedChecks() []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(p.Checks))
	for _, id := range p.Checks {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// resolveInjections 把"注入哪些因子"解析成"强制失败哪些检查"。
//
// 触发检查**只能**从 `config.ResolveEdgeFactorTriggerMap` 解析（默认表 + `[edge_factors.model]`
// 的 `trigger.<FACTOR-ID>` 覆盖，两条评分路径共用的同一张表）：把出厂表在这里再抄一份，
// 运营者覆盖过的部署就会被注入到错误的检查上，而记录看起来完全正常。
func resolveInjections(cfg *config.Config, spec scenarioSpec) (injectionPlan, error) {
	plan := injectionPlan{FactorOf: map[string][]string{}}
	triggers := config.ResolveEdgeFactorTriggerMap(cfg)
	for _, phase := range spec.Inject {
		ids := make([]string, 0, len(phase))
		for _, raw := range phase {
			id := edgefactor.NormalizeFactorID(raw)
			check := strings.TrimSpace(triggers[id])
			if check == "" {
				return plan, fmt.Errorf("因子 %s 在当前配置里没有解析出触发检查（config.ResolveEdgeFactorTriggerMap）—— 注入无从执行", id)
			}
			ids = append(ids, check)
			plan.FactorOf[check] = appendUnique(plan.FactorOf[check], id)
		}
		plan.Phases = append(plan.Phases, ids)
		plan.Checks = append(plan.Checks, ids...)
	}
	for check := range plan.FactorOf {
		sort.Strings(plan.FactorOf[check])
	}
	return plan, nil
}

func appendUnique(list []string, v string) []string {
	for _, have := range list {
		if have == v {
			return list
		}
	}
	return append(list, v)
}

// collectChecks 取宿主真实检查结果，并把注入计划里的检查**强制判为失败**。
//
// 三条口径（spec §5.1 的"记录构造要求"）：
//
//  1. **delta 逐字取自引擎的检查登记表**（`OT-005 = -15`）—— 注入只翻转 `Passed`，不改
//     `Delta`/`Domain`/`Name`。插件路径的域分公式消费的是 `CheckResult.Delta` 本身，
//     而 `cfg.CheckDeltas` 只被 legacy 路径消费，故这里**不**用它覆盖（写错就是溯源造假）。
//  2. **Confidence 不在这里造**：它由评分链路里的可信度解析（`ssam.ResolveCheckConfidence`
//     → `config.ResolveChecks`）按检查 ID 填，`[confidence]` 未启用时解析器是 no-op、
//     由内仓 `NormalizeConfidence` 兜成 1.0。注入出来的失败与真实失败因此走**同一条**
//     可信度路径，不会出现"注入的检查可信度与真实的不一样"。
//  3. **触发检查必须在本机登记表里**：不在就无法注入，返回错误让调用方拒绝写出 ——
//     "照常评一条没有任何失败的记录"正是要禁止的静默路径（记录看起来像"这个场景没有因子生效"）。
func collectChecks(cfg *config.Config, spec scenarioSpec, host []model.CheckResult) ([]model.CheckResult, injectionPlan, error) {
	plan, err := resolveInjections(cfg, spec)
	if err != nil {
		return nil, plan, err
	}
	out := make([]model.CheckResult, len(host))
	copy(out, host)

	index := make(map[string]int, len(out))
	for i, c := range out {
		index[c.CheckID] = i
	}
	for _, check := range plan.Checks {
		idx, ok := index[check]
		if !ok {
			return nil, plan, fmt.Errorf("触发检查 %s（因子 %s）不在本机的检查登记表里 —— 注入无从执行（登记表由 internal/checks 提供，需带 `checks` tag 构建）",
				check, strings.Join(plan.FactorOf[check], ","))
		}
		out[idx].Passed = false
	}
	return out, plan, nil
}

// verifyInjectionTimes 校验 harness 报出的注入时刻是否足以支撑本次采样的时间结构。
//
// 两条判据（裁定 3）：
//
//  1. **每个被注入的检查都必须有注入时刻**（顺序注入场景）—— 缺一个就只能回落到"评分时刻"，
//     而评分时刻对所有条目是同一个值 ⇒ 顺序注入场景会在数据上**静默退化成同时注入**，
//     C 候选随之退化成 V，且报告里看不出来。
//  2. **顺序注入场景必须真的有两个以上不同时刻**：harness 若把两个阶段都记在同一个瞬间，
//     这条数据同样没有时间结构；宁可响亮地拒绝，也不要产出一条"看起来跑过了"的记录。
//
// 同时注入（单阶段）的场景**不强制**注入时刻：没有时间结构是**如实结果**
// （"无时间结构时 C 不该凭空变好"的反向证据），此时 ts 取引擎的评分时刻（同样如实）。
func verifyInjectionTimes(spec scenarioSpec, plan injectionPlan, injections map[string]time.Time) error {
	if len(plan.Checks) == 0 {
		return nil
	}
	if !spec.sequential() {
		return nil
	}
	var missing []string
	for _, check := range plan.injectedChecks() {
		if injections[check].IsZero() {
			missing = append(missing, check)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("顺序注入场景缺注入时刻：%s（harness 必须报出每个注入检查的时刻；缺失会让本场景静默退化成同时注入、C 退化成 V）",
			strings.Join(missing, ","))
	}
	instants := distinctInstants(plan, injections)
	if len(instants) < len(plan.Phases) {
		return fmt.Errorf("顺序注入场景只有 %d 个不同的注入时刻（%d 个阶段）—— 没有时间结构的顺序注入等于同时注入，C 候选在这条数据上不可分辨",
			len(instants), len(plan.Phases))
	}
	return nil
}

func distinctInstants(plan injectionPlan, injections map[string]time.Time) []time.Time {
	seen := map[int64]bool{}
	var out []time.Time
	for _, check := range plan.injectedChecks() {
		at := injections[check]
		if at.IsZero() || seen[at.UnixNano()] {
			continue
		}
		seen[at.UnixNano()] = true
		out = append(out, at)
	}
	return out
}

// ============================================================================
// 评分：与生产**同一条**装配链
// ============================================================================

// newScoringAssessor 按生产装配口径构造评分器。
//
// 与 `cmd/kernel/main.go` 的接线**逐条对齐**（实验采集器必须复现部署的评分行为，否则
// 记录描述的是另一次评分）：
//   - `[weights] scoring_engine = legacy` ⇒ **不**装配插件引擎，走内置 `DynamicScoringEngine`；
//   - 否则装配 ssam 适配器（`NewEngineAdapter` 在构造期按同一份 cfg 装配合成模型，未配置
//     `[edge_factors.model]` 时零注册 = 内仓默认乘性路径）。
//
// 后者决定了记录能不能写出：**只有装载了合成模型的路径**才会盖上溯源戳并回填观测链
// （`adapter_engine.go` 的同一判据），故"未启用部署"与"legacy 评分模式"都产不出可用的实验
// 记录 —— 那是设计与裁定的结论，不是本工具的缺陷（见 assembleRecord 的拒绝理由）。
func newScoringAssessor(cfg *config.Config) *engine.Assessor {
	assessor := engine.NewAssessor(cfg)
	if cfg != nil && cfg.ScoringEngine != "legacy" {
		assessor.SetPluginEngine(enginessam.NewEngineAdapter(cfg))
	}
	return assessor
}

// ============================================================================
// 装配
// ============================================================================

// buildRecord 采集一个场景并装配成一条 spec §5.1 记录（含全部生产者自检）。
//
// 检查集由 `collectChecksForTarget` 决定来源（Task 4C）：
//   - `target == ""`（默认）⇒ 本机检查登记表，**与今天逐位一致**；
//   - `target != ""` ⇒ 在目标节点内跑同一份二进制取回检查结果；任何失败都**不**退回本机。
//
// 测试与离线复算用 `assembleRecord` 直接给检查集。
func buildRecord(ctx context.Context, scenarioName string, cfg *config.Config, gt groundTruth, run int, target string) (edgeexp.Record, error) {
	host, observationTarget, err := collectChecksForTarget(target)
	if err != nil {
		return edgeexp.Record{}, err
	}
	return assembleRecord(ctx, cfg, scenarioName, gt, run, host, observationTarget)
}

// assembleRecord 是采集器的核心：把"场景 + 配置 + 客观结果 + 宿主检查集"装配成一条记录。
//
// `observationTarget` 说明这份检查集**出自哪台机器**（Task 4C）：空串 = 本机（与今天逐位一致），
// 非空 = 由 `collectChecksForTarget` 给出的节点内自证串（进 `meta.observation_target`）。
// 它不参与任何判据，只解决"记录是宿主采的还是节点采的"这个问题（见 `edgeexp.Meta` 的说明）。
//
// 调用链（brief 指定的顺序，任何一步失败都**不写半条记录**）：
//
//	Validate()（读取层口径：存在性 + 值域）→ ValidateConstruction()（记录构造：规范因子 ID）
//	→ CheckTriggerCrossReference()（**仅插件路径**）→ CheckEffectiveWeightsRecorded()
//	→ 交由 `edgeexp.MarshalRecord` 追加写出。
//
// 失败时返回的记录**带着 `meta.assembly_error`**：拒绝写出的原因必须留痕，否则实验只会
// "少场景而人不知"。返回的 error 与 `meta.assembly_error` 是同一句话的两个出口
// （前者给退出码，后者给记录/日志）。
func assembleRecord(ctx context.Context, cfg *config.Config, scenarioName string, gt groundTruth, run int, host []model.CheckResult, observationTarget string) (edgeexp.Record, error) {
	rec := edgeexp.Record{
		ScenarioID: scenarioID(scenarioName, run),
		Meta: edgeexp.Meta{
			PlaybookHash: gt.PlaybookHash,
			Run:          run,
			Timestamp:    time.Now().UTC().Format(time.RFC3339),
		},
	}
	fail := func(format string, args ...any) (edgeexp.Record, error) {
		reason := fmt.Sprintf(format, args...)
		rec.Meta.AssemblyError = reason
		return rec, fmt.Errorf("edgescen: 场景 %s 装配失败: %s", scenarioName, reason)
	}

	if err := ctx.Err(); err != nil {
		return fail("上下文已取消: %v", err)
	}
	spec, err := lookupScenario(scenarioName)
	if err != nil {
		return fail("%v", err)
	}
	if cfg == nil {
		return fail("配置为空")
	}
	if run <= 0 {
		// 运行号是场景标识的一部分（A-1 的重复样本靠它归因），0/负数没有意义，收敛到 1。
		run = 1
		rec.ScenarioID = scenarioID(scenarioName, run)
		rec.Meta.Run = run
	}

	collectedAt := time.Now().UTC()
	observedChecks, plan, err := collectChecks(cfg, spec, host)
	if err != nil {
		return fail("%v", err)
	}
	if err := verifyInjectionTimes(spec, plan, gt.Injections); err != nil {
		return fail("%v", err)
	}

	// 主机标识只用于评分器内部的缓存键与 SPC/ATT&CK 提供方（本工具不装配后者），
	// 记录本体里没有主机字段；取不到主机名时用固定值，避免把"取不到名字"变成一次失败。
	hostName, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostName) == "" {
		hostName = "edgescen-host"
	}
	result := newScoringAssessor(cfg).AssessFromResults(hostName, hostName, observedChecks)

	// 溯源戳是"引擎到底装载了什么"的唯一判据（Task 1/5 的裁定）：**不得**据链是否为空判断
	// "有没有模型"，两者在 JSON 上因 omitempty 同形。戳记与观测链出自同一处、同一判据
	// （adapter_engine.go），故"戳记在场"同时意味着"链是可信的"。
	stamped := result.EdgeFactors.Model != "" || result.EdgeFactors.ParamsHash != ""
	chain, tsNote := recordChain(result, spec, gt.Injections)
	penalties := len(result.EdgeFactors.ActiveFactors())

	// 裁定 5：拒绝"有惩罚、但链为空"的记录。
	//   链只在**引擎真的装载了模型**时回填，而未装载时内仓默认路径**仍然用六因子乘分**
	//   ⇒ 会产出"有惩罚、但链为空"的记录：离线复算必然失败，而且看起来像"这个场景没有因子生效"。
	//   故先断言戳记存在（"没有模型"与"有模型但没激活"只能靠它区分），再断言"有惩罚就必须有链"。
	//   反过来，**没有惩罚且链为空是合法观测**（S0 基线）：把判据写成"链必须非空"会把基线判死。
	//
	// 两个分支的**可达性**（Fix round 1 / 评审 M2 的更正）：
	//   - `case !stamped` 是**实际拦下"有惩罚但链为空"的那一条**：未装载模型时
	//     `EdgeFactorsToModel` 照常把六个权重填进 `result.EdgeFactors`（所以 `penalties > 0`），
	//     而适配器把链写成 nil ⇒ 两条判据同时为真，按顺序由本分支报错（并且能给出针对性提示）。
	//   - `case penalties > 0 && len(chain) == 0` 因此**今天不可达**：一旦戳记在场（模型真的装载了），
	//     链与六个权重出自**同一份** `output.EdgeFactors` 结果集，任何 `Active` 因子都会上链；
	//     而 `penalties > 0` 至少需要一个内置槽位里的 `Active` 因子 ⇒ 链非空。
	//     它作为**防御**保留：这条不变量的两个端点（戳记判据、链回填判据）分别在
	//     adapter_engine.go 与 observeEdgeFactorChain 里，将来任一处改宽（例如允许"未启用部署"
	//     也盖戳、或按域过滤链）都会让它变成唯一能拦住坏记录的地方，而删掉它不会有任何门禁变红。
	switch {
	case !stamped:
		return fail("引擎没有装载边缘因子合成模型（溯源戳为空）⇒ 观测链不会被回填、记录无法区分"+
			"『未配置模型』与『有模型但没激活』；有惩罚时这条记录还会让离线复算凭空少掉全部因子惩罚。"+
			"实验模板必须显式声明 [edge_factors.model]（M0 基线写 model = legacy：评分与『未配置』逐位一致，"+
			"但只有装载过的路径才盖戳并输出观测链）%s", assemblyHint(cfg))
	case penalties > 0 && len(chain) == 0:
		return fail("引擎实际乘进了 %d 个因子（有惩罚），观测链却是空的 —— 这类记录会让离线复算静默丢掉全部因子惩罚", penalties)
	}

	// 场景的"观测断言"：注入（或真实缺失）声明激活的因子必须真的出现在链上。
	// 链只在装配正确时才回填，故这是"这次注入真的生效了"的唯一证据 —— 少了它，一条
	// 注入失败的记录会以完全正常的语气落盘，之后所有指标都建立在一个没跑对的场景上。
	for _, want := range spec.expectedChainFactors() {
		if !chainHas(chain, want) {
			return fail("场景声明激活的因子 %s 没有出现在观测链上（注入未生效 / 触发映射未覆盖该因子 / 真实缺失没有发生）——链: %s",
				want, chainSummary(chain))
		}
	}

	rec.Injection = spec.injectionKind()
	rec.Factors = chainFactorIDs(chain)
	rec.Observed = edgeexp.Observed{
		DomainScores: domainScoresOf(result, observedChecks),
		// 裁定 4：必须写出引擎**实际生效**的逐域权重（键集 = 参与聚合的域）。
		// 判存在性一律用 len(...) > 0（nil map 会序列化成 null）。
		EffectiveWeights: effectiveWeights(cfg, observedChecks),
		FinalScore:       result.FinalScore,
		Acceptable:       result.Acceptable,
		Threshold:        result.Threshold,
		// spc_score / threat_coeff 的**唯一**正确来源就是引擎传给评分公式的这两个量
		// （`ssam.RiskContext{Exposure: output.SPCScore, Threat: output.ThreatCoeff}`）。
		// 禁止从 `internal/attck` 的 `predictedRisk.EnhancedThreat`（恰好也叫 threat_coeff，
		// 但那是另一个量）取，也禁止自己算 —— 取错会让离线分数整体偏移而所有门禁全绿，
		// 故本行的来源由**同进程内的 round-trip 钉桩**盯住（见本函数末段）。
		SPCScore:    result.SPCScore,
		ThreatCoeff: result.ThreatCoeff,
		// checks[] 必须是引擎的**全部失败检查**（穷尽性），不是"链上提到的那几条"：
		// 它同时是 CheckTriggerCrossReference 能成立的前提。**不得**用 trigger_check 反推它。
		Checks:          checkObservations(cfg, result, gt.Injections, collectedAt),
		EdgeFactorChain: chain,
	}
	// 溯源注记分两个字段写（Task 3B Step 3）：`weight_source` 只讲权重口径（字段本来的语义），
	// 链条目 ts 的基准进 `meta.ts_source`（`internal/edgeexp.Meta.TSSource`，本轮新增）。
	// 此前两件事挤在 `weight_source` 一句里 —— 那是 `Meta.TSSource` 存在之前的既定 stopgap，
	// 代价是"这份生效权重从哪来"的语义被稀释；现在它回到只有一个话题。
	rec.Meta.WeightSource = weightSource
	rec.Meta.TSSource = tsNote
	// 观测主体（Task 4C）：空串 = 本机（默认路径，字段因 omitempty 不出现在 JSON 里 ⇒ 与
	// 今天写出的字节一致）；非空 = 节点内自证串。写在装配点而不是 CLI 里：它是**检查集**
	// 的属性（谁采的），与 `-env`（操作者给的标签）是两回事 —— 把两者混在一个字段里，
	// 将来任何人都无法从记录反推"这份数据到底出自哪台机器"。
	rec.Meta.ObservationTarget = observationTarget
	contract, err := gt.recordGroundTruth()
	if err != nil {
		return fail("%v", err)
	}
	rec.GroundTruth = contract

	// 存在性标记（spc_score / threat_coeff / compromised / c_trigger / effective_factor）是
	// `internal/edgeexp` 的非导出字段，**只由 UnmarshalJSON 设置** —— 直接在 Go 里拼结构体
	// 字面量，无论字段写得多全，`Validate` 都会以「missing」拒绝（契约层刻意要求"显式出现"）。
	// 故生产者必须让自己的载荷走一次编解码。这一步同时把"我们写出什么"与"读取层读到什么"
	// 钉成同一份字节；`sealRecord` 里另有一条"编解码必须无损"的断言（见那里的说明）。
	sealed, err := sealRecord(rec)
	if err != nil {
		return fail("%v", err)
	}
	rec = sealed

	// brief 指定的调用链，逐条执行、任一失败即拒绝写出。
	if err := rec.Validate(); err != nil {
		return fail("读取层契约（Validate）: %v", err)
	}
	if err := rec.ValidateConstruction(); err != nil {
		return fail("记录构造要求（ValidateConstruction）: %v", err)
	}
	// 裁定 1：CheckTriggerCrossReference **必须在装配点之后立刻调用**，且**只对插件路径**成立。
	//
	// 为什么必须在这里：写出口 `MarshalRecord` 无法判断路径（记录里没有路径字段），读取层按设计
	// 也不查 ⇒ 漏调不会有任何下游兜住。而"这条记录出自哪条路径"只有装配点知道。
	//
	// 为什么必须**有条件**：legacy 无模型段路径保留 identity 分支（检查 ID 恰等于因子 ID 时
	// 直接激活）与级联写值，此时链上的 `trigger_check` 是"该因子**登记的**触发检查"、未必是
	// 真正失败的那个检查 ⇒ 那里调用本条会拒掉真实数据。
	//
	// 判据是"插件引擎真的装载了合成模型"（`stamped`，与观测链回填同一判据）—— **不是**
	// "走了插件引擎"这件事本身：装了适配器却没装载模型的部署同样走插件引擎，但它既没有戳记、
	// 也没有链，与 legacy 无模型段路径在数据上同形（评审 M13：名字必须说清它区分的是什么）。
	// 今天这条分支恒为真（未装载的记录已在上面被拒），但条件必须显式存在：判据一旦放宽
	// （例如将来允许写"未启用部署"的记录），无条件调用会立刻把合法记录判死。
	if modelLoaded := stamped; modelLoaded {
		if err := rec.CheckTriggerCrossReference(); err != nil {
			return fail("触发关系交叉校验（CheckTriggerCrossReference，仅插件路径）: %v", err)
		}
	}
	if err := rec.CheckEffectiveWeightsRecorded(); err != nil {
		return fail("生效权重自检（CheckEffectiveWeightsRecorded）: %v", err)
	}
	// round-trip 钉桩（spec §5.1 末段："采集器落地时必须对自采数据做同样的事"）：
	// 用**记录自身的输入**（域分 + 生效权重 + spc_score/threat_coeff + 链上 effective_factor）
	// 复算总分，必须与记录里的 final_score 相等。这条是"spc/threat 取错"、"生效权重写错"、
	// "链上少了一条惩罚"这类**所有其它门禁全绿**的错误的唯一闸门（spec §5.1 明说：字段取错会让
	// 离线分数整体偏移而门禁全绿）。复算走的是内仓同一个公式 `SSAMV20Formula`，且此刻进程里
	// 安装的正是本次评分装配的那套钩子（域级修正 P_d 由钩子内部合成）⇒ 与在线同口径。
	if err := roundTripCheck(rec); err != nil {
		return fail("%v", err)
	}
	return rec, nil
}

// roundTripTolerance 是 round-trip 的容差：引擎的总分是 `math.Round(x*100)/100`（两位小数），
// 故复算只要落在半个取整格内就视为"同一个数"；再放宽就会放过真正的口径错误（量级都是整分）。
const roundTripTolerance = 0.005

// roundTripCheck 用记录自身的输入复算总分并与 `observed.final_score` 对比（见组装点的说明）。
//
// 输入口径逐条对齐离线工具（`cmd/edgecompare/score.go` 的 `offlineFormulaResult`）：
// 域分按权重表的确定性顺序装入切片、只装 `权重 > 0` 的域（公式对 w ≤ 0 本来就会跳过）；
// 权重表用记录自己的 `effective_weights`（键集 = 参与聚合的域）；链条目原样装成
// `EdgeFactorResult`（`Factor` 就是引擎侧那个已衰减一次的观测值，**不再**衰减第二次）。
func roundTripCheck(rec edgeexp.Record) error {
	recomputed := recomputeFinalScore(rec)
	if diff := recomputed - rec.Observed.FinalScore; diff > roundTripTolerance || diff < -roundTripTolerance {
		return fmt.Errorf("round-trip 钉桩未通过：用记录自身输入复算的总分 %.4f 与 observed.final_score %.4f 相差 %.4f（容差 %v）—— "+
			"记录内部不自洽，离线复算（Task 4 门禁②）必然失败。最可能的原因：spc_score/threat_coeff 不是引擎的 "+
			"SSAMV20Formula 入参（即 RiskContext 的 Exposure/Threat）、effective_weights 不是引擎实际聚合的权重表、"+
			"或链上漏了参与惩罚的因子",
			recomputed, rec.Observed.FinalScore, recomputed-rec.Observed.FinalScore, roundTripTolerance)
	}
	return nil
}

// recomputeFinalScore 是 round-trip 的复算本体：只读记录（绝不读配置或引擎内部状态），
// 因而它检验的是"这条记录自己能不能复现自己"。
func recomputeFinalScore(rec edgeexp.Record) float64 {
	weights := rec.Observed.EffectiveWeights
	domains := orderedWeightDomains(weights)
	scores := make([]ssam.DomainScore, 0, len(domains))
	weightConfigs := make([]ssam.WeightConfig, 0, len(domains))
	for _, d := range domains {
		scores = append(scores, ssam.DomainScore{Domain: d, Score: rec.Observed.DomainScores[d]})
		weightConfigs = append(weightConfigs, ssam.WeightConfig{Domain: d, Weight: weights[d]})
	}
	factors := make([]ssam.EdgeFactorResult, 0, len(rec.Observed.EdgeFactorChain))
	for _, ob := range rec.Observed.EdgeFactorChain {
		factors = append(factors, ssam.EdgeFactorResult{
			ID:                edgefactor.NormalizeFactorID(ob.Factor),
			Factor:            ob.EffectiveFactor,
			Active:            true,
			TriggerConfidence: ob.CTrigger,
		})
	}
	return ssam.SSAMV20Formula(scores, weightConfigs,
		ssam.RiskContext{Exposure: rec.Observed.SPCScore, Threat: rec.Observed.ThreatCoeff},
		factors).Total
}

// orderedWeightDomains 给出域分的确定性装入顺序：**按域名升序**（字典序）。
//
// 为什么是字典序而不是 spec 附录 A 的域顺序：复算要与**引擎**逐位同口径，而引擎的域分切片
// 由 `ssam.ComputeDomainScoresBayes` 产出并 **`sort.Slice(results, …results[i].Domain < …)`**
// 排好序，`SSAMV20Formula` 就按那个顺序累加 `sum += score*w`。IEEE754 加法不满足结合律，
// 装入顺序不同会在末位差 1 ulp —— 若基准分恰好落在取整半格上（例如 x.xx5），这一点差异会
// 把 `math.Round` 翻到另一格，让 round-trip 钉桩**误拒**一条完全合法的记录（评审 M7）。
// 离线工具 `cmd/edgecompare` 自 Task 3B Step 2 起**也**按字典序装域分切片（此前是
// `DefaultDomains` 顺序）—— 两侧现在是同一条浮点累加路径，round-trip 门禁才真的在比"同一个量"。
// 本函数与它各自独立实现（互不 import），但**顺序口径必须一致**：一处改、另一处跟着改。
func orderedWeightDomains(weights map[string]float64) []string {
	out := make([]string, 0, len(weights))
	for d, w := range weights {
		if w > 0 {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// assemblyHint 在装配失败时给出**针对性的**提示（`[weights] scoring_engine = legacy`、
// `model = chain` 在线不可执行、λ 一个都没配 …… 这些形态的拒绝理由完全不同，
// 笼统地说"必须声明 [edge_factors.model]"会让操作者去改一行本来就写对了的配置）。
//
// 实现的取巧之处：不去复述引擎内部的判定，而是**再问一次同一个入口**
// （`enginessam.ParamsFromConfig`，与 `newSynthesizePlan` 同源），按它的返回值分派：
//   - 报错 ⇒ 参数不可用，把那句话原样带出来（这是引擎 WARN 日志里那句的真正原因）；
//   - 未启用 ⇒ 段缺席；
//   - 启用了 ⇒ 看装载的是哪个模型（chain 在线不可执行 / V/G 没有 λ 就什么也修正不了）。
//
// 这些提示与 `internal/engine/ssam` 的判定**不构成第二份实现**：分派依据全部来自它的导出面
// （`ParamsFromConfig` 的返回、`edgefactor.RequestedDomains`），没有一条判据是本工具自己重写的。
func assemblyHint(cfg *config.Config) string {
	if cfg != nil && strings.EqualFold(strings.TrimSpace(cfg.ScoringEngine), "legacy") {
		return "。注意：本配置写着 [weights] scoring_engine = legacy —— 生产装配此时走内置 DynamicScoringEngine，" +
			"它**永远**不盖溯源戳；要让 M0 基线也能采集，请改用 [edge_factors.model] 的 model = legacy（评分逐位一致，但会装载并盖戳）"
	}
	if cfg == nil {
		return ""
	}
	params, enabled, err := enginessam.ParamsFromConfig(cfg)
	if err != nil {
		return fmt.Sprintf("。引擎侧装配错误（原样转述）: %v", err)
	}
	if !enabled {
		return "。本配置没有 [edge_factors.model] 段：引擎走内仓默认的乘性路径、不装载参数，故既不盖戳也不回填链" +
			"（注意区分 [weights] scoring_engine = legacy 与这里说的 [edge_factors.model] model = legacy）"
	}
	switch params.Model {
	case edgefactor.ModelChain:
		return "。本配置声明 [edge_factors.model] model = chain —— chain 是**离线专用**模型：" +
			"在线结果类型没有时间字段（`ssam.EdgeFactorResult` 只有 ID/Factor/Active/TriggerConfidence），" +
			"装配期即 fail-fast、不装载也不盖戳；chain 候选由 `cmd/edgecompare` 离线评估。" +
			"在线采集请用 m0-baseline（显式 legacy）/vector/graph 模板"
	case edgefactor.ModelVector, edgefactor.ModelGraph:
		if len(edgefactor.RequestedDomains(params)) == 0 {
			return fmt.Sprintf("。本配置声明 model = %s，但没有声明任何 lambda.<domain>："+
				"一个域都不会被修正 ⇒ 装配期拒绝装载（否则会出现『戳记写着 %s、评分却分毫未变』的假溯源）",
				params.Model, params.Model)
		}
	}
	return "。配置里看似有可装载的模型参数，但引擎仍未装载 —— 这是内部不一致（请连同本轮的引擎 WARN 日志一起上报）"
}

// sealRecord 让记录带上契约的"字段存在性标记"，并断言这次编解码**无损**。
//
// 存在性标记（`spcScoreSet` / `cTriggerSet` / …）是非导出字段、只由 `UnmarshalJSON` 设置，
// 故生产者必须让自己的载荷走一次编解码（见 assembleRecord 的说明）。但这一步同时引入一个
// **静默丢字段**的风险：`Observed` / `ChainObs` / `GroundTruth` 各自的 `UnmarshalJSON` 里有一份
// **第二字段清单**（aux 结构），将来给这些类型加字段却忘了同步 aux，数据就会在密封处被吃掉 ——
// 而密封后的记录才是被自检、被写出的那一份，于是"字段加了但永远到不了磁盘"这件事
// 在所有门禁上都看不见（评审的加固建议）。
//
// 两条断言，缺一不可：
//  1. **切片长度逐项一致**（`edge_factor_chain` / `checks`）：最常见的形态就是整条条目被吃掉，
//     长度断言给出的诊断比字节比较清楚；
//  2. **整个记录逐字节往返**（更强的判据）：长度断言覆盖不到**标量**字段，而
//     `json.Marshal(rec) → Unmarshal → Marshal` 只要丢了任何字段，第二次字节就不同。
//     同一结构体的字段顺序与浮点最短表示都是确定的，故这个比较不会误报。
func sealRecord(rec edgeexp.Record) (edgeexp.Record, error) {
	raw, err := json.Marshal(rec)
	if err != nil {
		return rec, fmt.Errorf("记录编码失败: %w", err)
	}
	var sealed edgeexp.Record
	if err := json.Unmarshal(raw, &sealed); err != nil {
		return rec, fmt.Errorf("记录回读失败（生产者/消费者不同源）: %w", err)
	}
	if got, want := len(sealed.Observed.EdgeFactorChain), len(rec.Observed.EdgeFactorChain); got != want {
		return rec, fmt.Errorf("密封前后观测链条目数不同（%d → %d）—— `edgeexp.ChainObs` 的 UnmarshalJSON 丢了字段，记录会带着残缺的链落盘", want, got)
	}
	if got, want := len(sealed.Observed.Checks), len(rec.Observed.Checks); got != want {
		return rec, fmt.Errorf("密封前后失败检查条目数不同（%d → %d）—— `edgeexp.CheckObs` 的解码丢了字段，记录会带着残缺的 checks[] 落盘", want, got)
	}
	again, err := json.Marshal(sealed)
	if err != nil {
		return rec, fmt.Errorf("密封后编码失败: %w", err)
	}
	if !bytes.Equal(raw, again) {
		return rec, fmt.Errorf("密封前后记录字节不同 —— 契约类型（Observed / ChainObs / GroundTruth）的 UnmarshalJSON 漏了字段，"+
			"该字段会**永远到不了磁盘**且不会被任何门禁发现：\n 密封前: %s\n 密封后: %s", raw, again)
	}
	return sealed, nil
}

// scenarioID 是记录里的场景标识。spec §5.1 的示例写作 `S2-selinux-apparmor-01`（带运行号），
// 而 A-1 的每场景 3 次重复必须能各自归因，故重复样本用 `-02`/`-03` 区分。
// 调用方保证 run ≥ 1（见 assembleRecord 入口的收敛）。
func scenarioID(name string, run int) string {
	return fmt.Sprintf("%s-%02d", name, run)
}

// ============================================================================
// 观测量
// ============================================================================

// recordChain 把引擎输出的观测链装成记录里的链，并按**本次记录唯一的那个时间基准**回填 `ts`，
// 同时返回一行"ts 从哪来"的来源说明（写进记录的溯源注记与自检摘要）。
//
// 裁定 3（Task 1 评审实测的硬要求）：引擎侧链上所有条目的 `ts` 是**同一个评分时刻**
// （`adapter_engine.go`），而 chain 模型用 `from.ts.Before(to.ts)` 做严格时间窗 ⇒ 全同值会让
// **所有有向耦合被跳过**、C 候选退化成 V。harness 知道每个检查的注入/采集时刻，故顺序注入场景
// 要按"该因子触发检查的注入时刻"逐条回填。
//
// **一条记录只用一个基准，绝不混用**（Fix round 1 / 评审 Important 2 实测的真机形态）：
// 此前的实现是"条目命中 harness 就回填、否则沿用评分时刻"，于是在真实主机上（很多检查本就会
// 自然失败）产出过 **11 条里 4 条带注入时刻、7 条带更晚的评分时刻**的链 —— 那个"注入先、自然失败后"
// 的顺序既不是实验设计的（同时注入场景的设计预期恰恰是"没有时间结构 ⇒ C ≡ V"），
// 也没有任何地方报告它。裁定 3 禁止的是**编造**顺序，而混用是**悄悄继承**了一个顺序，同样不可接受。
//
// 故：
//   - **顺序注入场景**（`len(Inject) > 1`）：按 harness 的注入时刻逐条回填 —— 那就是这个场景
//     设计出来的可分辨时间结构；harness 没覆盖到的条目（自然失败激活的因子）取**评估时刻**，
//     它们确实是在评估那一刻才被观测到的，晚于全部注入，故是如实取值而非补出来的顺序。
//   - **同时注入场景**（单阶段）：**一条都不用** harness 时刻，全部取评估时刻 ⇒ 全部同值 ⇒
//     没有时间结构 ⇒ C 与 V 在这条数据上同分。这正是"无时间结构时 C 不该凭空变好"的反向对照。
//     harness 报出的注入时刻仍然照常用于 `checks[].ts`（那里是逐检查的观测时刻，不是模型的入参）。
//
// 另：**链是列表不是映射** —— 同一因子 ID 出现多次时逐条处理，不做任何按 ID 的去重/建 map。
func recordChain(result *model.AssessmentResult, spec scenarioSpec, injections map[string]time.Time) ([]edgeexp.ChainObs, string) {
	useHarness := spec.sequential()
	chain := make([]edgeexp.ChainObs, 0, len(result.EdgeFactorChain))
	covered := 0
	for _, ob := range result.EdgeFactorChain {
		ts := ob.TS
		if useHarness {
			if at, ok := injections[ob.TriggerCheck]; ok && !at.IsZero() {
				ts = at.UTC().Format(time.RFC3339)
				covered++
			}
		}
		chain = append(chain, edgeexp.ChainObs{
			Factor:          ob.Factor,
			TriggerCheck:    ob.TriggerCheck,
			CTrigger:        ob.CTrigger,
			EffectiveFactor: ob.EffectiveFactor,
			TS:              ts,
		})
	}
	return chain, chainTSNote(useHarness, len(spec.Inject), len(injections), len(chain), covered)
}

// chainTSNote 是链条目 ts 来源的一行说明（进记录的溯源注记与自检摘要）。
//
// 为什么必须写出来：混用基准的旧形态"没人报告"正是它最难被发现的地方 —— 数据看起来完全正常，
// 而链上藏着一个没人设计的顺序。故无论走哪个分支，来源都留痕。
func chainTSNote(useHarness bool, phases, reported, total, covered int) string {
	if !useHarness {
		if reported > 0 {
			return fmt.Sprintf("链条目 ts = 全部取评估时刻（同时注入场景：harness 报出的 %d 个注入时刻不用于链条目，只用 checks[]，以免造出没人设计的顺序）", reported)
		}
		return "链条目 ts = 全部取评估时刻（同时注入场景，无时间结构 ⇒ C 与 V 在这条数据上同分）"
	}
	return fmt.Sprintf("链条目 ts = %d/%d 条按 harness 注入时刻（%d 个注入阶段），其余 %d 条取评估时刻",
		covered, total, phases, total-covered)
}

// checkObservations 落盘引擎的**全部失败检查**（穷尽性），并给每条检查一个诚实的时间戳：
// 注入出来的失败取 harness 报的注入时刻，真实失败取本次采集时刻。
//
// `Delta` 原样转写（不重算、不覆盖）：它就是引擎这次真正消费的值。`Confidence` 写的是
// **引擎实际消费的那个数**（`ssam.NormalizeConfidence(原始值, 本配置的可信度策略)`），
// 而不是 `CheckResult` 里那个"还没解析"的原始值：`[confidence]` 未启用时解析器是 no-op，
// 原始值恒为 0，直接落盘会让记录看起来像"这次观测毫无可信度"，而引擎用的其实是 1.0；
// 归一之后记录里还多出一条可校验的不变量 —— 链上 `c_trigger`（同一份可信度）与该检查的
// `confidence` 逐位相等（见 TestChainTriggerConfidenceMatchesChecks）。
func checkObservations(cfg *config.Config, result *model.AssessmentResult, injections map[string]time.Time, collectedAt time.Time) []edgeexp.CheckObs {
	policy := enginessam.ConfigToConfidencePolicy(cfg)
	out := make([]edgeexp.CheckObs, 0, len(result.Checks))
	for _, c := range result.Checks {
		if c.Passed {
			continue
		}
		ts := collectedAt.UTC().Format(time.RFC3339)
		if at, ok := injections[c.CheckID]; ok && !at.IsZero() {
			ts = at.UTC().Format(time.RFC3339)
		}
		out = append(out, edgeexp.CheckObs{
			ID:         c.CheckID,
			Domain:     c.Domain,
			Passed:     c.Passed,
			Delta:      c.Delta,
			Confidence: enginessam.NormalizeConfidence(c.Confidence, policy),
			TS:         ts,
		})
	}
	return out
}

// chainFactorIDs 取链上出现的因子**集合**（按首次出现顺序），用于记录的 `factors` 声明。
//
// 与链本身的区别：链是列表（同一 ID 允许出现多次 —— 出厂配置下引擎确实乘了两次），
// 而 `factors` 是"这条记录建模了哪些因子"的声明集合，重复项没有意义。两者口径不同，
// 不得互相推导：**链绝不去重**，`factors` 才去重。
func chainFactorIDs(chain []edgeexp.ChainObs) []string {
	seen := map[string]bool{}
	var out []string
	for _, ob := range chain {
		if seen[ob.Factor] {
			continue
		}
		seen[ob.Factor] = true
		out = append(out, ob.Factor)
	}
	return out
}

func chainHas(chain []edgeexp.ChainObs, id string) bool {
	for _, ob := range chain {
		if ob.Factor == id {
			return true
		}
	}
	return false
}

// chainSummary 是链的紧凑诊断串（含重复项，重复本身是有信息量的观测）。
func chainSummary(chain []edgeexp.ChainObs) string {
	if len(chain) == 0 {
		return "(空)"
	}
	parts := make([]string, 0, len(chain))
	for _, ob := range chain {
		parts = append(parts, fmt.Sprintf("%s(trigger=%q c=%v f=%v)", ob.Factor, ob.TriggerCheck, ob.CTrigger, ob.EffectiveFactor))
	}
	return strings.Join(parts, " ")
}

// weightSource 说明 `observed.effective_weights` 从哪来（`meta.config_hash` 是它的锚点）。
//
// 它必须是**可归因的**：这份权重不是"从配置里猜的"，而是插件引擎装配时喂给内仓的同一张表
// （`ssam.ConfigToWeights` → `Engine.SetWeights`，见 effectiveWeights 的说明）。
const weightSource = "config:[weights]+[extension_weights] via ssam.ConfigToWeights；键集 = 参与聚合的域（有检查的域 ∩ 权重非零）"

// provenanceNote 已被 Task 3B Step 3 **退役**：它把"权重口径"与"链条目 ts 基准"合成一句写进
// `meta.weight_source`，那只是 `internal/edgeexp.Meta` 只有两个自由文本槽位时的既定 stopgap。
// `Meta.TSSource`（`json:"ts_source,omitempty"`）落地后，两件事各回各自的字段 —— 见组装点里
// 的两行赋值（`rec.Meta.WeightSource = weightSource` / `rec.Meta.TSSource = tsNote`）。
// 两个字段都是**可选**的（读取层不要求），故既有数据集不受影响。

// effectiveWeights 返回引擎**实际生效**的逐域权重，键集 = "参与聚合的域"。
//
// 裁定 4 的两个坑（Task 1 评审实测）：
//
//  1. **配置权重 ≠ 生效权重**：`config.Parse` 末尾会 `cfg.Weights.Normalize()`（四个核心域归一到
//     100），legacy 内在层的 `DynamicScoringEngine` 还会给 0 权重域填默认值再 `Normalize(100)`。
//     本工具读的是**解析之后**的权重表，且来源是插件引擎装配时用的同一个函数调用
//     （`ssam.ConfigToWeights(cfg)` —— `NewEngineAdapter` 就是用它 `SetWeights` 的），
//     而不是把 `[weights]` 原样抄一遍。
//  2. **键集 = 参与聚合的域**：`DomainScores` 的四个核心域字段恒存在（未产出的域读出来是 0），
//     记录**无法**从域分本身区分"参与聚合但值为 0"与"不在聚合里" —— 这正是本字段存在的理由。
//     故键集取"有权重的域 ∩ 引擎真的产出了域分的域"（见 participatingDomains）。
//
// 空表等于没写：`MarshalRecord` 会拒绝，`len(...) > 0` 是全仓统一的存在性判据。
func effectiveWeights(cfg *config.Config, checks []model.CheckResult) map[string]float64 {
	weights := make(map[string]float64)
	for _, w := range enginessam.ConfigToWeights(cfg) {
		weights[w.Domain] = w.Weight
	}
	part := participatingDomains(checks)
	if len(part) == 0 {
		// 没有任何检查 ⇒ 引擎退化为"为全部权重域产出域分"（`ComputeDomainScoresBayes`）。
		for d := range weights {
			part[d] = true
		}
	}
	out := make(map[string]float64, len(weights))
	for domain, weight := range weights {
		if weight > 0 && part[domain] {
			out[domain] = weight
		}
	}
	return out
}

// participatingDomains 报告**哪些域参与了聚合**（= 引擎实际为哪些域产出了域分）。
//
// 判据取自 `ssam.ComputeDomainScoresBayes`（引擎的唯一实现）：它为**每个有检查的域**产出一个
// 域分，一个检查都没有时退化为"全部权重域"。这里刻意复用同一口径而不是另立一条：
// 口径写错会让 `effective_weights` 的键集与引擎实际聚合的域集不一致，而离线复算拿它当真值
// （多一个域就按 0 分加权、总分被系统性压低，且门禁全绿）。
func participatingDomains(checks []model.CheckResult) map[string]bool {
	out := make(map[string]bool, len(checks))
	for _, c := range checks {
		out[c.Domain] = true
	}
	return out
}

// domainScoresOf 取引擎输出的逐域分数。
//
// `model.DomainScores.GetAllDomainScores()` 会把四个核心域字段**无条件**物化（未产出的域是 0），
// 而 `kernel_security` 为 0 时会被 `omitempty` 从 JSON 里省略 —— 那会让一项**参与聚合**的
// 域在记录里彻底消失（`CheckEffectiveWeightsRecorded` 要求权重键 ⊆ 域分键）。故这里把
// 参与者中缺失的域显式补上（值取契约的取值口径，即 0）。
func domainScoresOf(result *model.AssessmentResult, checks []model.CheckResult) map[string]float64 {
	out := result.DomainScores.GetAllDomainScores()
	for domain := range participatingDomains(checks) {
		if _, ok := out[domain]; !ok {
			out[domain] = result.DomainScores.Get(domain)
		}
	}
	return out
}
