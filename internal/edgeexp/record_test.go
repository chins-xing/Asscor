package edgeexp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================================
// 共享 JSONL 契约包（spec §5.1）的契约用例
// ============================================================================
//
// 本文件是 `cmd/edgecompare/load_test.go` 里**校验类**用例的迁移目标（Task 2 Step 1），
// 口径逐条不变：同一条判据、同一句断言、同一个字段路径。原用例**仍留在** `cmd/edgecompare`
// 里不改一字 —— 它们是"搬迁未改变消费者可观测行为"的证据（brief Step 5）。故本项目里
// 同一条判据有两处可执行表述，这不是冗余：
//
//   - `internal/edgeexp`（本文件）：**无 build tag**，`go test ./internal/...` 即跑；
//     生产者（未来的 `cmd/edgescen`）与消费者（`cmd/edgecompare`）共享的契约在这里被钉住；
//   - `cmd/edgecompare`：带 `edgeexp` tag，走真实的 CLI 读取层（含行号、BOM、空行、错误前缀），
//     守住"薄封装没有改变任何一条可观测行为"。
//
// 断言口径的两条要求（评审 I2 的落点，迁移时逐字保留）：
//  1. **错误必须带字段路径**（`observed.spc_score` 之类），否则操作员不知道该改哪一行；
//  2. **"缺失"必须报成"缺失"**（错误串里出现 `missing`），不得只报"值越界" —— 后者会把
//     "这条记录根本没写这个字段"误导成"值写错了"。这两条信息不可互换。

// validRecord 构造一条完全合法的记录（沿用 cmd/edgecompare 夹具的数值与字段）。
//
// **在包内直接构造**是本文件的做法：存在性标记（`spcScoreSet` 等）只在 `UnmarshalJSON` 里
// 被设置，直接构造时必须手动置真 —— 这正是"同一包内部测试"的表达力：可以只翻一个存在性标记，
// 断言"缺失被拒"，而不必拼接 JSON 字符串（那测的其实是解码层）。
func validRecord() Record {
	return Record{
		ScenarioID: "S1-selinux",
		Factors:    []string{"EF-SELINUX"},
		Injection:  "check_fail",
		Observed: Observed{
			DomainScores: map[string]float64{"attack_surface": 90, "operation_trust": 90},
			FinalScore:   74.9,
			Acceptable:   true,
			Threshold:    60,
			SPCScore:     0.8,
			ThreatCoeff:  0.7,
			Checks: []CheckObs{{
				ID: "OT-005", Domain: "operation_trust", Passed: false, Delta: -8, Confidence: 0.9,
			}},
			EdgeFactorChain: []ChainObs{{
				Factor: "EF-SELINUX", TriggerCheck: "OT-005", CTrigger: 0.9, EffectiveFactor: 0.82,
				cTriggerSet: true, effectiveFactorSet: true,
			}},
			spcScoreSet:    true,
			threatCoeffSet: true,
		},
		GroundTruth: GroundTruth{
			Compromised: true, TimeToCompromiseS: 213, TTPsAchieved: 4, NodesAffected: 3,
			compromisedSet: true,
		},
		Meta: Meta{Env: "wsl-clab-14", PlaybookHash: "abc", ConfigHash: "def", Run: 1},
	}
}

// mustReject 断言一条记录被拒，且错误带字段路径与指定的全部关键字。
func mustReject(t *testing.T, r Record, wantFields ...string) {
	t.Helper()
	err := r.Validate()
	if err == nil {
		t.Fatalf("expected the record to be rejected, got nil error: %+v", r)
	}
	msg := err.Error()
	for _, want := range wantFields {
		if !strings.Contains(msg, want) {
			t.Errorf("error must name %q: %v", want, err)
		}
	}
}

// TestValidateAcceptsValidRecord：合法记录必须放行（其余用例的基线）。
func TestValidateAcceptsValidRecord(t *testing.T) {
	if err := validRecord().Validate(); err != nil {
		t.Fatalf("合法记录被拒: %v", err)
	}
}

// TestValidateRejectsMissingScenarioID：缺 scenario_id 的记录无法定位，必须拒绝。
func TestValidateRejectsMissingScenarioID(t *testing.T) {
	r := validRecord()
	r.ScenarioID = ""
	mustReject(t, r, "scenario_id")
}

// TestValidateRejectsNonPositiveThreshold：threshold 缺失 ⇒ 零值 0 ⇒ 任何非负分数都判
// acceptable ⇒ 决策层退化为"全放行"（FNR = 攻陷数/N，FPR ≡ 0），而报告照常打印 —— 必须拒绝。
func TestValidateRejectsNonPositiveThreshold(t *testing.T) {
	r := validRecord()
	r.Observed.Threshold = 0
	mustReject(t, r, "threshold")

	r = validRecord()
	r.Observed.Threshold = -1
	mustReject(t, r, "threshold")
}

// TestValidateRejectsEmptyDomainScores：没有域分就无从重算总分（空 map 与整段缺失同形）。
func TestValidateRejectsEmptyDomainScores(t *testing.T) {
	r := validRecord()
	r.Observed.DomainScores = nil
	mustReject(t, r, "domain_scores")

	r = validRecord()
	r.Observed.DomainScores = map[string]float64{}
	mustReject(t, r, "domain_scores")

	// 域名全空白的条目同样拒绝（它会让域权重表对不上，且无法归因）。
	r = validRecord()
	r.Observed.DomainScores = map[string]float64{"  ": 90}
	mustReject(t, r, "domain_scores")
}

// TestValidateRejectsMissingSPCScore：`spc_score` 缺失 ⇒ 0 ⇒ 按 1.0 计 ⇒ 总分被静默抬到
// 最宽松的一档，直接扭曲决策层判据。
//
// 断言同时要求出现 `missing`：只报字段名的写法抓不到"存在性校验被放宽"
// （`spc_score` 缺失会读成 0，随后被值域检查 `0 ∉ (0,1]` 拦下，错误串里照样有字段名）。
func TestValidateRejectsMissingSPCScore(t *testing.T) {
	r := validRecord()
	r.Observed.spcScoreSet = false // 同包内部测试：直接操作存在性标记
	err := r.Validate()
	if err == nil || !strings.Contains(err.Error(), "spc_score") || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("缺失必须被拒且理由指向『缺失』（只报字段名的写法抓不到存在性校验被放宽）: %v", err)
	}
}

// TestValidateRejectsOutOfRangeSPCScore：`spc_score ∈ (0,1]` 是引擎输出的值域
// （`p_score = max(minPScore, 1−总惩罚)`），0 是引擎的"未设置"哨兵。
func TestValidateRejectsOutOfRangeSPCScore(t *testing.T) {
	for _, v := range []float64{0, 1.5, -0.1} {
		r := validRecord()
		r.Observed.SPCScore = v
		mustReject(t, r, "spc_score")
	}
}

// TestValidateRejectsMissingThreatCoeff：`threat_coeff` 缺失 ⇒ 0 ⇒ 按 1.0 计。
func TestValidateRejectsMissingThreatCoeff(t *testing.T) {
	r := validRecord()
	r.Observed.threatCoeffSet = false
	err := r.Validate()
	if err == nil || !strings.Contains(err.Error(), "threat_coeff") || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("缺失必须被拒且理由指向『缺失』: %v", err)
	}
}

// TestValidateThreatCoeffRange：`threat_coeff > 0` 且**无上界** —— `[threat] coefficient`
// 的既有值域只有下界（ranges.go），实测配置里出现过 1.4。
func TestValidateThreatCoeffRange(t *testing.T) {
	for _, v := range []float64{0, -1} {
		r := validRecord()
		r.Observed.ThreatCoeff = v
		mustReject(t, r, "threat_coeff")
	}
	r := validRecord()
	r.Observed.ThreatCoeff = 1.4
	if err := r.Validate(); err != nil {
		t.Fatalf("threat_coeff = 1.4 是既有合法值（实测配置出现过），却被拒: %v", err)
	}
}

// TestValidateAcceptsCoefficientBoundaries：**合法**边界必须放行 ——
// `spc_score = 1`（无漏洞暴露：总惩罚为 0 时的上限）与 `threat_coeff = 1.4`。
func TestValidateAcceptsCoefficientBoundaries(t *testing.T) {
	r := validRecord()
	r.Observed.SPCScore = 1
	r.Observed.ThreatCoeff = 1.4
	if err := r.Validate(); err != nil {
		t.Fatalf("合法边界值应被接受，却被拒绝：%v", err)
	}
}

// TestValidateRejectsEmptyFactorID：链里没有因子 ID 的条目无法参与合成，必须拒绝。
func TestValidateRejectsEmptyFactorID(t *testing.T) {
	for _, id := range []string{"", "  "} {
		r := validRecord()
		r.Observed.EdgeFactorChain[0].Factor = id
		mustReject(t, r, "factor")
	}
}

// TestValidateRejectsMissingCTrigger：c_trigger 缺失 ⇒ 0 ⇒ EffectiveFactor 返回 1
// ⇒ a_i = 0 ⇒ 该因子的惩罚静默消失。
//
// 断言里要求出现 "missing"：字段缺失必须报"缺失"，而不是报一个看起来像数值越界的错误
// —— 前者告诉操作员"记录不完整"，后者会把人引向"值写错了"。
func TestValidateRejectsMissingCTrigger(t *testing.T) {
	r := validRecord()
	r.Observed.EdgeFactorChain[0].cTriggerSet = false
	err := r.Validate()
	if err == nil || !strings.Contains(err.Error(), "c_trigger") || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("缺失必须被拒且理由指向『缺失』: %v", err)
	}
}

// TestValidateRejectsMissingEffectiveFactor：effective_factor 缺失 ⇒ 0 ⇒ 命中 Synthesize
// 的"未提供"哨兵 ⇒ 静默回落到配置权重（与真实观测值无关）。
func TestValidateRejectsMissingEffectiveFactor(t *testing.T) {
	r := validRecord()
	r.Observed.EdgeFactorChain[0].effectiveFactorSet = false
	err := r.Validate()
	if err == nil || !strings.Contains(err.Error(), "effective_factor") || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("缺失必须被拒且理由指向『缺失』: %v", err)
	}
}

// TestValidateRejectsOutOfRangeChainValues：越界值会让 L/P 失真（eff > 1 时 a < 0 ⇒ P > 1，
// 反向抬高域分），必须拒绝。
func TestValidateRejectsOutOfRangeChainValues(t *testing.T) {
	for _, v := range []float64{1.5, -0.1} {
		r := validRecord()
		r.Observed.EdgeFactorChain[0].CTrigger = v
		mustReject(t, r, "c_trigger")
	}
	for _, v := range []float64{0, 1.5} {
		r := validRecord()
		r.Observed.EdgeFactorChain[0].EffectiveFactor = v
		mustReject(t, r, "effective_factor")
	}
}

// TestValidateAcceptsBoundaryChainValues：`c_trigger = 0` 与 `effective_factor = 1` 是**合法**
// 边界值，必须放行。
//
// c_trigger = 0 不是坏数据：ssam-lib 的 `ApplyEdgeFactorsToChecksPolicy` 在"因子仅由级联激活、
// 自身触发检查未失败"时只把 Active 置真、不动 TriggerConfidence，于是 tc 保持 0
// （spec §5 的 S5 级联组正会产出这种记录）。被拒的是**缺失**，不是这个值本身。
func TestValidateAcceptsBoundaryChainValues(t *testing.T) {
	r := validRecord()
	r.Observed.EdgeFactorChain[0].CTrigger = 0
	r.Observed.EdgeFactorChain[0].EffectiveFactor = 1
	if err := r.Validate(); err != nil {
		t.Fatalf("边界值应被接受，却被拒绝：%v", err)
	}
}

// TestValidateTimestampRules：chain 的时间戳是离线 chain 模型的**唯一**时间来源
// （在线引擎的结果类型没有时间字段），故：空串合法（= 该字段缺席），非空必须 RFC3339，
// 解析不了一律拒绝（`"..."` 这种占位写法会被拒）；`checks[].ts` 同款。
func TestValidateTimestampRules(t *testing.T) {
	r := validRecord()
	r.Observed.EdgeFactorChain[0].TS = ""
	if err := r.Validate(); err != nil {
		t.Fatalf("空 ts 合法（= 缺席），却被拒绝：%v", err)
	}

	r = validRecord()
	r.Observed.EdgeFactorChain[0].TS = "not-a-time"
	mustReject(t, r, "ts")

	r = validRecord()
	r.Observed.EdgeFactorChain[0].TS = "2026-09-08T10:00:03Z"
	r.Observed.Checks[0].TS = "not-a-time"
	mustReject(t, r, "checks", "ts")
}

// TestValidateRejectsMissingCompromised：`ground_truth.compromised` 必须显式出现
// —— 缺失 ⇒ false ⇒ 该场景被静默标成"未攻陷"，直接扭曲漏判率/误阻断率。
func TestValidateRejectsMissingCompromised(t *testing.T) {
	r := validRecord()
	r.GroundTruth.compromisedSet = false
	err := r.Validate()
	if err == nil || !strings.Contains(err.Error(), "compromised") {
		t.Fatalf("缺失必须被拒且理由指向 compromised: %v", err)
	}
}

// TestValidateAcceptsExplicitFalseCompromised：显式 `false` 必须被接受，且如实读成 false
// （不能与"缺失"混为一谈）。
func TestValidateAcceptsExplicitFalseCompromised(t *testing.T) {
	r := validRecord()
	r.GroundTruth.Compromised = false
	r.GroundTruth.compromisedSet = true
	if err := r.Validate(); err != nil {
		t.Fatalf("显式 false 应被接受：%v", err)
	}
}

// ============================================================================
// 本包新增：重复因子条目必须放行（评审 C1）+ 生效权重可选
// ============================================================================

// TestValidateAcceptsDuplicateFactorEntries：**同一条链里出现两条同一个因子 ID 是合法的，
// 且任何消费方都不得去重**（Task 2 评审 C1 的回归测试；被删掉的"大小写折叠冲突即拒绝"规则
// 就是因为违反本条而被撤下）。
//
// 为什么这不是坏数据 —— 出厂部署正会产出它：
//   - `config.ini` / 每个 `configs/*.ini` 除了 `[edge_factors]` 之外，又把**同样七个因子 ID**
//     写进 `[edge_factors.custom]`（带各自的触发检查）；`internal/config` 的 `parseSections`
//     会把配置键小写化，`ConfigToEdgeFactors`（`internal/engine/ssam/adapter.go`）**刻意不去重**
//     地逐条追加；
//   - ssam 按因子 ID 各自保留一份，于是**引擎确实按这个因子乘了两次**；
//   - `observeEdgeFactorChain` 把它们各自归一 ⇒ 链上两条 `factor == "EF-SELINUX"`。
//
// 记录是**列表**语义：两条条目 = 两次惩罚，是引擎的真实行为，不是重复数据。若按 ID 去重，
// 离线重算会**少算一次惩罚**，而分数照样打印出来 —— 这正是"读取层单方面收紧会让实验自己
// 产出的数据集读不回来"的形态（读不进 + 写不出 ⇒ 采集器零记录）。
// 需要拒绝的是**渲染侧身份键的折叠冲突**（仅大小写不同的键在重解析时会静默合并）——
// 那条规则在 `cmd/edgecompare/report.go` 的 `validateRenderable`（`validateCaseFoldCollisions`），
// 与记录的链语义无关。
func TestValidateAcceptsDuplicateFactorEntries(t *testing.T) {
	r := validRecord()
	r.Observed.EdgeFactorChain = append(r.Observed.EdgeFactorChain, ChainObs{
		Factor: "EF-SELINUX", TriggerCheck: "OT-005", CTrigger: 0.9, EffectiveFactor: 0.82,
		cTriggerSet: true, effectiveFactorSet: true,
	})
	r.Factors = []string{"EF-SELINUX"}
	if err := r.Validate(); err != nil {
		t.Fatalf("链上两条同一因子 ID 是出厂部署的真实形态（引擎确实乘了两次），必须放行: %v", err)
	}

	// 生产端同样不得因此拒绝：写出口只做构造自检，不去重、不折叠。
	r.Observed.EffectiveWeights = map[string]float64{"attack_surface": 35, "operation_trust": 25}
	if _, err := MarshalRecord(r); err != nil {
		t.Fatalf("重复因子条目的记录必须可写出（生产者按列表如实落盘）: %v", err)
	}
	if got := len(r.Observed.EdgeFactorChain); got != 2 {
		t.Fatalf("链条目数被改动（%d，应为 2）—— 去重只能发生在消费方的显式决策里，不能在契约层", got)
	}

	// 大小写/空白变体（`"  ef-selinux  "`）与规范 ID 共处一条链：**读取层同样必须放行** ——
	// 它在消费侧装配期被 `NormalizeFactorID` 归一成同一个因子，两条惩罚项都还在，
	// 与上面"两条完全相同的 ID"是同一种列表语义。这条口径原先被删除的折叠规则用例反向覆盖过，
	// 删除后必须由本用例**正面**钉住，否则"读取层重新收紧"会无声无息地溜过去。
	//
	// 注意**读/写不对称**（评审已裁定 accepted）：`Validate` 放行非规范 ID，而写出口
	// `ValidateConstruction` 要求规范 ID —— 故这里只断言读取层；生产者侧的那一半由
	// `TestValidateAcceptsNonCanonicalFactorIDForReader` 钉住。
	r.Observed.EdgeFactorChain = append(r.Observed.EdgeFactorChain, ChainObs{
		Factor: "  ef-selinux  ", TriggerCheck: "OT-005", CTrigger: 0.9, EffectiveFactor: 0.838,
		cTriggerSet: true, effectiveFactorSet: true,
	})
	if err := r.Validate(); err != nil {
		t.Fatalf("规范 ID 与大小写/空白变体共处一条链，读取层必须放行（消费侧归一后是同一因子的两次惩罚）: %v", err)
	}
	if got := len(r.Observed.EdgeFactorChain); got != 3 {
		t.Fatalf("链条目数被改动（%d，应为 3）—— 读取层不得合并或丢弃任何条目", got)
	}
}

// TestValidateTreatsEffectiveWeightsAsOptional：`observed.effective_weights` 在**读取层**
// 是可选字段 —— 既有数据集与夹具里没有它（它们是在这条契约之前产出的），读取层不能因此变红。
//
// 为什么这个字段必须存在（spec §5.1 前提 2）：引擎 legacy 的内在层加权用的是
// `DynamicScoringEngine` 的**动态权重**（0 权重域会被填默认值并 `Normalize(100)`），
// 故"配置权重 ≠ 生效权重"；而 `DomainScores` 的核心域字段恒存在，记录**无法区分**
// "该域参与聚合但值为 0"与"该域不在聚合里"。下游的 round-trip 门禁只能以引擎**实际生效**
// 的逐域权重为准，且**键集即"参与聚合的域"**。写入它是生产者的义务（采集器自检），
// 不是读取层的准入条件。
func TestValidateTreatsEffectiveWeightsAsOptional(t *testing.T) {
	r := validRecord()
	r.Observed.EffectiveWeights = nil
	if err := r.Validate(); err != nil {
		t.Fatalf("缺 effective_weights 的记录必须仍被读取层接受（既有夹具）：%v", err)
	}

	r = validRecord()
	r.Observed.EffectiveWeights = map[string]float64{"attack_surface": 35, "operation_trust": 25}
	if err := r.Validate(); err != nil {
		t.Fatalf("带 effective_weights 的记录必须被接受：%v", err)
	}
}

// TestEffectiveWeightsJSONKey：字段的 JSON 键必须**恰好**是 `effective_weights`
// （离线重算与 round-trip 门禁按这个名字取它；写错会让权重整段静默丢失）。
func TestEffectiveWeightsJSONKey(t *testing.T) {
	r := validRecord()
	r.Observed.EffectiveWeights = map[string]float64{"attack_surface": 35}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"effective_weights":{"attack_surface":35}`)) {
		t.Fatalf("JSON 键不是 effective_weights: %s", raw)
	}

	var back Record
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Observed.EffectiveWeights["attack_surface"] != 35 {
		t.Fatalf("effective_weights 未往返：%+v", back.Observed.EffectiveWeights)
	}
}

// TestMetaTSSourceIsOptionalWithItsOwnJSONKey（Task 3B Step 3）：`meta.ts_source` 是里程碑 B
// 新增的**可选**字段（`omitempty`），读取层不要求它 —— 既有数据集里没有这个键，读取层不得
// 因此变红。
//
// 为什么要有独立字段：链条目 `ts` 的**基准**（全部取评估时刻 vs 按 harness 注入时刻）此前被
// 塞进 `meta.weight_source` 的末段（一个字段讲两件事的临时形态）。混用基准会造出"没人设计、
// 也没人报告"的顺序，而数据看起来完全正常 —— 留痕是必须的，但它得有自己的槽位，否则
// `weight_source` 的语义（这份生效权重从哪来）会被稀释。
func TestMetaTSSourceIsOptionalWithItsOwnJSONKey(t *testing.T) {
	// (a) 没有该字段的记录（既有数据集）必须仍被接受。
	r := validRecord()
	r.Meta.TSSource = ""
	if err := r.Validate(); err != nil {
		t.Fatalf("缺 meta.ts_source 的记录必须仍被读取层接受（既有数据集）：%v", err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(raw, []byte("ts_source")) {
		t.Fatalf("ts_source 是可选字段，空值不得出现在 JSON 里（omitempty）: %s", raw)
	}

	// (b) JSON 键必须**恰好**是 `ts_source`（Go 字段名是 TSSource，缩写全大写 ——
	// 默认的键推导会给出 `TSSource`，故必须显式写 tag）。
	note := "链条目 ts = 3/3 条按 harness 注入时刻（2 个注入阶段），其余 0 条取评估时刻"
	r.Meta.TSSource = note
	r.Meta.WeightSource = "config:[weights]+[extension_weights] via ssam.ConfigToWeights"
	raw, err = json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"ts_source":"`)) {
		t.Fatalf("JSON 键不是 ts_source: %s", raw)
	}
	var back Record
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Meta.TSSource != note {
		t.Fatalf("ts_source 未往返: %q", back.Meta.TSSource)
	}
	if back.Meta.WeightSource != r.Meta.WeightSource {
		t.Fatalf("weight_source 未往返: %q", back.Meta.WeightSource)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("带 ts_source 的记录必须被接受：%v", err)
	}
}

// ============================================================================
// 记录构造要求（spec §5.1）：读取层**不**校验，生产者侧自检
// ============================================================================
//
// spec §5.1 第 234 行明确划了界线：「**这些是"记录构造要求"，不是读取层契约**」——
// 写错不会有任何读取层报错，只会让报告与论文证据失真。故它们以**生产者侧**函数的形式
// 落在这个共享包里（生产者与消费者共用一份实现，而不是各写一份），由采集器（Task 3）调用。

// TestValidateConstructionRejectsNonCanonicalFactorID：`factors` 与
// `edge_factor_chain[].factor` 都必须是**规范因子 ID**（`EF-SELINUX`，不是展示名
// `selinux_disabled`、也不是小写 `ef-selinux`）—— 写错会让离线重算查不到 `Vectors`
// 而静默走"全 1"fallback，**改变 V/G/C 的惩罚强度**（实测 L 由 0.15 变成 0.3）。
func TestValidateConstructionRejectsNonCanonicalFactorID(t *testing.T) {
	for _, id := range []string{"selinux_disabled", "ef-selinux", " EF-SELINUX "} {
		r := validRecord()
		r.Observed.EdgeFactorChain[0].Factor = id
		err := r.ValidateConstruction()
		if err == nil || !strings.Contains(err.Error(), "canonical") {
			t.Errorf("chain 因子 %q 不是规范 ID，生产者自检必须拒绝（实际: %v）", id, err)
		}
	}

	r := validRecord()
	r.Factors = []string{"selinux_disabled"}
	err := r.ValidateConstruction()
	if err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Errorf("factors 列表里的非规范 ID 必须被生产者自检拒绝（实际: %v）", err)
	}

	if err := validRecord().ValidateConstruction(); err != nil {
		t.Fatalf("合法记录的构造自检必须通过：%v", err)
	}
}

// TestValidateAcceptsNonCanonicalFactorIDForReader：**刻意的读写不对称**，有既有用例为证。
//
// 读取层（`Validate`）**不**要求规范 ID：消费侧的归一化发生在装配期
// （`activationsOf` → `edgefactor.NormalizeFactorID`），手写的/历史数据集用小写或带空白的
// ID 仍能被正确消费；`cmd/edgecompare` 的 `TestActivationsOfNormalizesAndConverts`
// 正是用 `"  ef-selinux  "` 这条夹具钉住"消费侧归一"这条既有行为。若读取层在此硬拒，
// 那条既有用例会红 —— 而本任务的验收恰恰是"既有用例一条不改仍全绿"。
//
// 规范 ID 的要求因此落在**生产者侧**（`ValidateConstruction`）：写入侧必须规范，
// 读取侧保持宽容。两边是同一个包里的两个函数，不是两份实现。
func TestValidateAcceptsNonCanonicalFactorIDForReader(t *testing.T) {
	r := validRecord()
	r.Observed.EdgeFactorChain[0].Factor = "  ef-selinux  "
	if err := r.Validate(); err != nil {
		t.Fatalf("读取层必须接受非规范 ID（消费侧归一），却拒绝了：%v", err)
	}
	if err := r.ValidateConstruction(); err == nil {
		t.Fatal("生产者自检必须拒绝非规范 ID，却放行了")
	}
}

// TestCheckTriggerCrossReferenceRejectsMissingFailedCheck：插件路径（V/G/C）的构造要求 ——
// `c_trigger > 0` 的链条目，其 `trigger_check` 必须以 `passed = false` 出现在 `checks[]` 里。
//
// 这条**不是**读取层规则：legacy 无模型段路径保留 *identity 分支*（检查 ID 恰等于因子 ID 时
// 直接激活该因子）与级联写值，此时链上的 `trigger_check` 是"该因子**登记的**触发检查"，
// **未必**是真正失败的那个检查（例：identity 检查 `EF-002FA` 失败时，链上写的是登记值
// `EF-001`）。故只有确知记录来自插件路径的调用方（采集器，Task 3）才能执行它。
//
// **任何消费者都不得用 `trigger_check` 反推 `checks[]`**；`checks[]` 的真实要求是
// "落盘引擎的全部失败检查"（采集器的额外约定），那也是这条交叉校验能成立的前提。
func TestCheckTriggerCrossReferenceRejectsMissingFailedCheck(t *testing.T) {
	r := validRecord()
	r.Observed.Checks = nil // 触发检查没落进 checks[]
	err := r.CheckTriggerCrossReference()
	if err == nil || !strings.Contains(err.Error(), "trigger_check") {
		t.Fatalf("插件路径下 c_trigger > 0 而触发检查未以失败出现，必须被拒（实际: %v）", err)
	}

	// 检查在场但**通过**（passed = true）同样不成立：因子被激活的原因必须可追溯。
	r = validRecord()
	r.Observed.Checks[0].Passed = true
	if err := r.CheckTriggerCrossReference(); err == nil {
		t.Fatal("触发检查出现在 checks[] 里但是 passed=true，不得算作激活依据")
	}
}

// TestCheckTriggerCrossReferenceExemptsZeroCTrigger：`c_trigger = 0` 的纯级联因子豁免 ——
// 它的激活原因本就**不是**某个检查失败（`EF-3FA → EF-002FA` 就是这样）。
func TestCheckTriggerCrossReferenceExemptsZeroCTrigger(t *testing.T) {
	r := validRecord()
	r.Observed.EdgeFactorChain[0] = ChainObs{
		Factor: "EF-3FA", TriggerCheck: "EF-001", CTrigger: 0, EffectiveFactor: 1,
		cTriggerSet: true, effectiveFactorSet: true,
	}
	r.Observed.Checks = nil
	if err := r.CheckTriggerCrossReference(); err != nil {
		t.Fatalf("c_trigger = 0 的纯级联条目必须豁免交叉校验：%v", err)
	}
}

// TestCheckTriggerCrossReferencePassesOnSpecSample：spec §5.1 的示例记录（两条链共用
// OT-005，且 OT-005 以 passed=false 出现）必须通过 —— 这条防止把交叉校验写得过严，
// 反而拒掉规范示例。
func TestCheckTriggerCrossReferencePassesOnSpecSample(t *testing.T) {
	rec := loadDocSample(t)
	if err := rec.CheckTriggerCrossReference(); err != nil {
		t.Fatalf("spec §5.1 示例必须通过插件路径交叉校验：%v", err)
	}
	if err := rec.ValidateConstruction(); err != nil {
		t.Fatalf("spec §5.1 示例必须通过生产者构造自检：%v", err)
	}
}

// TestCheckEffectiveWeightsRecorded：采集器的生产者自检 —— 记录必须写出**引擎实际生效**的
// 逐域权重（spec §5.1 前提 2），否则离线复算拿不到"哪些域参与聚合、各占多少权重"。
//
// 读取层不要求它（见 TestValidateTreatsEffectiveWeightsAsOptional），但生产者必须写。
// 加严的两条（评审 I2）：①非空；②**每个键都必须出现在 `domain_scores` 里** ——
// 只查非空会放行 `{"bogus":1}`，而 Task 4 的门禁把这个字段当**真值**用，
// 错键会让复算按错误的域集加权且**不报错**。
func TestCheckEffectiveWeightsRecorded(t *testing.T) {
	r := validRecord()
	if err := r.CheckEffectiveWeightsRecorded(); err == nil {
		t.Fatal("未写 effective_weights 的记录必须被生产者自检拦下")
	}

	r = validRecord()
	r.Observed.EffectiveWeights = map[string]float64{}
	if err := r.CheckEffectiveWeightsRecorded(); err == nil {
		t.Fatal("空的 effective_weights 等于没写：键集即『参与的域』，不得为空")
	}

	// 未知域：键集必须 ⊆ domain_scores，否则"哪些域参与了聚合"是错的。
	r = validRecord()
	r.Observed.EffectiveWeights = map[string]float64{"bogus": 1}
	err := r.CheckEffectiveWeightsRecorded()
	if err == nil {
		t.Fatal("effective_weights 里的键不在 domain_scores 里，必须被拒绝（键集 = 参与聚合的域，参与聚合的域必然有域分）")
	}
	if !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "domain_scores") {
		t.Errorf("错误必须点名坏键与它应当出现的位置: %v", err)
	}

	// 混合（一个合法、一个未知）同样拒绝 —— 并且坏键的挑选必须**确定**（排序后取第一个），
	// 否则错误信息会随 map 迭代序漂移，测试与人工复现都要看运气。
	r = validRecord()
	r.Observed.EffectiveWeights = map[string]float64{"attack_surface": 35, "zzz": 1, "aaa": 2}
	err = r.CheckEffectiveWeightsRecorded()
	if err == nil || !strings.Contains(err.Error(), "aaa") {
		t.Fatalf("多个坏键时必须确定性地报排序后的第一个（aaa）: %v", err)
	}

	r = validRecord()
	r.Observed.EffectiveWeights = map[string]float64{"attack_surface": 35, "operation_trust": 25}
	if err := r.CheckEffectiveWeightsRecorded(); err != nil {
		t.Fatalf("写全生效权重后自检必须通过：%v", err)
	}
}

// TestMarshalRecordRequiresEffectiveWeights：写出口必须拒绝"没写生效权重"的记录（评审 I2）。
//
// 理由：采集器漏调用自检的代价是记录里 `effective_weights` 变成 `null`，而下游 round-trip
// 门禁以它为**真值** —— 那会表现为一段**静默**偏差（离线按猜的权重复算），比在写出口直接报错
// 贵得多。**唯一的代价**是"把历史数据集原样重写一遍"这类用法也必须先把权重表填出来；
// 本项目里没有这种调用方（生产者是 Task 3 的采集器，它本来就必须填），故从严。
func TestMarshalRecordRequiresEffectiveWeights(t *testing.T) {
	r := validRecord()
	if _, err := MarshalRecord(r); err == nil {
		t.Fatal("缺 effective_weights 的记录不得被写出")
	} else if !strings.Contains(err.Error(), "effective_weights") {
		t.Errorf("错误必须点名 effective_weights: %v", err)
	}

	r = validRecord()
	r.Observed.EffectiveWeights = map[string]float64{"bogus": 1}
	if _, err := MarshalRecord(r); err == nil {
		t.Fatal("effective_weights 含未知域的记录不得被写出（键集必须 ⊆ domain_scores）")
	}

	r = validRecord()
	r.Observed.EffectiveWeights = map[string]float64{"attack_surface": 35, "operation_trust": 25}
	if _, err := MarshalRecord(r); err != nil {
		t.Fatalf("写全生效权重后必须可写出：%v", err)
	}
}

// ============================================================================
// 存在性标记的跨包读取口
// ============================================================================

// TestExistenceAccessorsMirrorJSONPresence：存在性标记是**非导出**字段（只能由
// `UnmarshalJSON` 设置），但跨包的门禁需要读到"这个字段到底写没写" —— `docs_schema_test.go`
// 的反向对照正是靠它区分"缺失被拒"与"值越界被拒"。故这里导出只读访问器，并用本用例钉住
// 它们确实跟着 JSON 的在场情况走（访问器写错会让那条门禁静默失去牙齿）。
func TestExistenceAccessorsMirrorJSONPresence(t *testing.T) {
	const full = `{"scenario_id":"S1","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"EF-SELINUX","c_trigger":0.9,"effective_factor":0.82}]},"ground_truth":{"compromised":false}}`
	var rec Record
	if err := json.Unmarshal([]byte(full), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !rec.Observed.SPCScoreSet() || !rec.Observed.ThreatCoeffSet() {
		t.Errorf("写出来的 spc_score/threat_coeff 必须被标记为在场: %+v", rec.Observed)
	}
	if !rec.Observed.EdgeFactorChain[0].CTriggerSet() || !rec.Observed.EdgeFactorChain[0].EffectiveFactorSet() {
		t.Errorf("写出来的 c_trigger/effective_factor 必须被标记为在场: %+v", rec.Observed.EdgeFactorChain[0])
	}
	if !rec.GroundTruth.CompromisedSet() {
		t.Error("显式写出的 compromised=false 必须被标记为在场（与『没写』区分开）")
	}

	const partial = `{"scenario_id":"S1","observed":{"domain_scores":{"attack_surface":90},"threshold":60},"ground_truth":{}}`
	var bare Record
	if err := json.Unmarshal([]byte(partial), &bare); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if bare.Observed.SPCScoreSet() || bare.Observed.ThreatCoeffSet() || bare.GroundTruth.CompromisedSet() {
		t.Errorf("没写的字段不得被标记为在场: %+v / %+v", bare.Observed, bare.GroundTruth)
	}
}

// ============================================================================
// 生产者/消费者单一来源：读取层（LoadFile）与写出层（MarshalRecord）
// ============================================================================

// mustJSONL 把给定内容写成临时 JSONL 并返回路径。
func mustJSONL(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// sampleJSONL 是 spec §5.1 schema 的一条样例记录（单行；与 cmd/edgecompare 的夹具同源）。
const sampleJSONL = `{"scenario_id":"S1-selinux","factors":["EF-SELINUX"],"injection":"check_fail","observed":{"domain_scores":{"attack_surface":90,"operation_trust":90},"final_score":74.9,"acceptable":true,"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"checks":[{"id":"OT-005","domain":"operation_trust","passed":false,"delta":-8,"confidence":0.9}],"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.82}]},"ground_truth":{"compromised":true,"time_to_compromise_s":213,"ttps_achieved":4,"nodes_affected":3,"block_effective":false},"meta":{"env":"wsl-clab-14","playbook_hash":"abc","config_hash":"def","run":1}}`

// TestLoadFileParsesSchema：读取层解析 spec §5.1 的记录（字段逐项读回）。
func TestLoadFileParsesSchema(t *testing.T) {
	recs, err := LoadFile(mustJSONL(t, "records.jsonl", sampleJSONL+"\n"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.ScenarioID != "S1-selinux" || !r.GroundTruth.Compromised || r.GroundTruth.TTPsAchieved != 4 {
		t.Errorf("unexpected record: %+v", r)
	}
	if r.Observed.EdgeFactorChain[0].EffectiveFactor != 0.82 {
		t.Errorf("chain not parsed: %+v", r.Observed.EdgeFactorChain)
	}
	if r.Observed.Checks[0].ID != "OT-005" || r.Observed.Checks[0].Passed {
		t.Errorf("checks not parsed: %+v", r.Observed.Checks)
	}
	if r.Meta.Env != "wsl-clab-14" || r.Meta.Run != 1 || r.Observed.Threshold != 60 {
		t.Errorf("meta/observed not parsed: %+v / %+v", r.Meta, r.Observed)
	}
}

// TestLoadFileValidatesEveryRecord：读取层对**每一条**记录跑同一个 `Validate`
// （单一来源：写出与读入不是两份判据）。
func TestLoadFileValidatesEveryRecord(t *testing.T) {
	bad := `{"scenario_id":"S0-baseline","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"threat_coeff":0.7},"ground_truth":{"compromised":false}}`
	_, err := LoadFile(mustJSONL(t, "second-bad.jsonl", sampleJSONL+"\n"+bad+"\n"))
	if err == nil {
		t.Fatal("第 2 行的记录缺 spc_score，读取层必须拒绝")
	}
	if !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "spc_score") {
		t.Errorf("错误必须带行号与字段路径: %v", err)
	}
}

// TestLoadFileSkipsBlankLines：空行不产生记录、不报错（JSONL 常见尾部空行）。
func TestLoadFileSkipsBlankLines(t *testing.T) {
	recs, err := LoadFile(mustJSONL(t, "blank.jsonl", sampleJSONL+"\n\n"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
}

// TestLoadFileStripsLeadingBOM：文件首行的 UTF-8 BOM 被剥离；行内的 U+FEFF 仍是坏数据。
//
// 为什么（Task 8 实现者提出的疑虑 5）：本项目的采集器与数据集都在 Windows 上产出，
// 记事本/PowerShell 重定向/Python 的若干写法都会在文件头写 BOM。不剥的话第一条记录会以
// `invalid character 'ï' looking for beginning of value` 失败 —— 那条信息指不到"文件头有
// BOM"，读者会在 JSON 正文里找一个不存在的问题，而整批数据一条都读不进来。
func TestLoadFileStripsLeadingBOM(t *testing.T) {
	recs, err := LoadFile(mustJSONL(t, "bom.jsonl", "\ufeff"+sampleJSONL+"\n"))
	if err != nil {
		t.Fatalf("带 BOM 的文件必须能读（首个 BOM 应被剥离）: %v", err)
	}
	if len(recs) != 1 || recs[0].ScenarioID != "S1-selinux" {
		t.Fatalf("BOM 剥离后记录应完全等价: %+v", recs)
	}

	bad := mustJSONL(t, "bom-inside.jsonl", sampleJSONL+"\n\ufeff"+sampleJSONL+"\n")
	if _, err := LoadFile(bad); err == nil {
		t.Fatal("行内的 U+FEFF 必须让该行失败（它不在文件头，属坏数据）——剥离范围被放宽了")
	}
}

// TestLoadFileReportsBadLine：坏行必须带**行号**报错，绝不静默跳过。
func TestLoadFileReportsBadLine(t *testing.T) {
	_, err := LoadFile(mustJSONL(t, "bad.jsonl", sampleJSONL+"\n{not json}\n"))
	if err == nil {
		t.Fatal("expected an error for a malformed line, got nil")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error must carry the line number: %v", err)
	}
}

// TestLoadFileReportsMissingFile：路径不存在时错误必须含路径（不是裸的 os 错误）。
func TestLoadFileReportsMissingFile(t *testing.T) {
	_, err := LoadFile(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err == nil {
		t.Fatal("expected an error for a missing file, got nil")
	}
	if !strings.Contains(err.Error(), "nope.jsonl") {
		t.Errorf("error must carry the path: %v", err)
	}
}

// TestLoadFileAsPreservesConsumerErrorPrefix：错误前缀由调用方（工具名）决定，
// 消费者 `cmd/edgecompare` 的 `edgecompare: ` 前缀因此**逐字不变** —— 本任务的硬验收是
// "既有用例一条不改仍全绿"，而 CLI 的错误面属于可观测行为，不得因为搬迁而改口径。
func TestLoadFileAsPreservesConsumerErrorPrefix(t *testing.T) {
	path := mustJSONL(t, "bad.jsonl", sampleJSONL+"\n{not json}\n")
	_, err := LoadFileAs("edgecompare", path)
	if err == nil {
		t.Fatal("expected an error for a malformed line, got nil")
	}
	want := "edgecompare: " + path + " line 2: "
	if !strings.HasPrefix(err.Error(), want) {
		t.Errorf("消费者错误前缀/格式必须逐字不变:\n got: %v\nwant: %s…", err, want)
	}
}

// TestLoadFileErrorMessagesAreExact **逐字**钉住整条错误串（含 `<tool>: <path> line N: <原因>` 的形状）。
//
// 为什么需要它（Task 2 Fix round 2 评审指出的覆盖缺口）：本包其余用例断言的是**子串**
// （"错误里必须出现 `spc_score` 与 `missing`"）。子串断言能守住"诊断口径不被改坏"，却守不住
// 两件更细的事：
//  1. **错误信息被重排/改写**（判据顺序、文案措辞）—— 只要子串还在，子串断言照样绿；
//  2. **整条错误的形状**（工具名前缀、路径、行号的位置与分隔符）—— 消费者 CLI 直接把它打给
//     操作员，它是可观测行为的一部分。
//
// 上一轮靠"与 Task 2 之前的 worktree 做 A/B 探针"证明过逐字不变，但那个探针是一次性的
// （worktree 用完即删，无法阻止**将来**的漂移）。本用例把同样的逐字口径固化成**常驻**门禁：
// 任何一次改写都会在这里响亮地失败，而不需要旧版本在场。
//
// 期望值**逐字**照抄实现里的 `fmt.Errorf` 文案 —— 改文案就必须同时改这里（这正是目的）。
// 临时目录的随机部分用 `<dir>` 归一，避免断言随环境漂移。
func TestLoadFileErrorMessagesAreExact(t *testing.T) {
	const good = sampleJSONL
	cases := []struct {
		name    string
		content string
		line    int
		cause   string
	}{
		{
			name:    "missing-threshold",
			content: `{"scenario_id":"S0-baseline","observed":{"domain_scores":{"attack_surface":90},"spc_score":0.8,"threat_coeff":0.7},"ground_truth":{"compromised":true}}`,
			line:    1,
			cause:   "observed.threshold = 0 must be > 0 — 缺失会被当成 0，任何非负分数都会判 acceptable，决策层退化为『全放行』",
		},
		{
			// **判据顺序的钉子**（brief 的加固项）：这条记录**同时**缺 `threshold` 与
			// `spc_score`，期望报的是**先检查**的那条（threshold）。本层只报第一个问题，故
			// 把 spc_score 的检查挪到 threshold 之前会改变既有输入的错误信息 —— 与消费者的
			// 逐字契约就此破裂。没有这条时，顺序可以被静默改写而整张表照样绿。
			name:    "missing-threshold-and-spc-score",
			content: `{"scenario_id":"S0-baseline","observed":{"domain_scores":{"attack_surface":90},"threat_coeff":0.7},"ground_truth":{"compromised":true}}`,
			line:    1,
			cause:   "observed.threshold = 0 must be > 0 — 缺失会被当成 0，任何非负分数都会判 acceptable，决策层退化为『全放行』",
		},
		{
			// `ground_truth` 是**最后**一类判据：前面每一项都写全、只有 `compromised` 缺席时，
			// 报的必须是它（而不是被任何别的字段问题顶掉）。`ground_truth.compromised` 不是
			// 普通的必填项 —— 它是"存在性"判据（缺失会被静默当成"未攻陷"），是这一层里唯一
			// 一个**不靠值域**就能出错的字段，故单独钉一遍。
			name:    "missing-compromised-only",
			content: `{"scenario_id":"S1-selinux","factors":["EF-SELINUX"],"injection":"check_fail","observed":{"domain_scores":{"attack_surface":90,"operation_trust":82},"final_score":74.9,"acceptable":true,"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"checks":[{"id":"OT-005","domain":"operation_trust","passed":false,"delta":-15,"confidence":0.9}],"edge_factor_chain":[{"factor":"EF-SELINUX","trigger_check":"OT-005","c_trigger":0.9,"effective_factor":0.82}]},"ground_truth":{"time_to_compromise_s":213,"ttps_achieved":4,"nodes_affected":3,"block_effective":false}}`,
			line:    1,
			cause:   "ground_truth.compromised: missing — 必须显式写出 true/false；缺失会被当成 false，该场景被静默标成『未攻陷』并直接扭曲漏判率/误阻断率",
		},
		{
			name:    "missing-spc-score",
			content: `{"scenario_id":"S1-selinux","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"threat_coeff":0.7},"ground_truth":{"compromised":true}}`,
			line:    1,
			cause:   "observed.spc_score: missing — 引擎的判定线需要它（总分 = round2(0.5·base + 30·E + 20·T)）；缺失会被当成 0，而 0 是引擎的『未设置』哨兵（按 1.0 计），总分被静默抬到最宽松的一档",
		},
		{
			name:    "missing-c-trigger",
			content: `{"scenario_id":"S1-selinux","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"EF-SELINUX","effective_factor":0.82}]},"ground_truth":{"compromised":true}}`,
			line:    1,
			cause:   "observed.edge_factor_chain[0].c_trigger: missing — 缺失会被当成 0（= 无可信度）并让该因子的惩罚静默消失",
		},
		{
			name:    "unparsable-chain-ts",
			content: `{"scenario_id":"S5-cascade","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"EF-3FA","c_trigger":1.0,"effective_factor":0.82,"ts":"not-a-time"}]},"ground_truth":{"compromised":true}}`,
			line:    1,
			cause:   `observed.edge_factor_chain[0].ts: not an RFC3339 timestamp: "not-a-time"`,
		},
		{
			name:    "empty-chain-factor",
			content: `{"scenario_id":"S1-selinux","observed":{"domain_scores":{"attack_surface":90},"threshold":60,"spc_score":0.8,"threat_coeff":0.7,"edge_factor_chain":[{"factor":"  ","c_trigger":1.0,"effective_factor":0.82}]},"ground_truth":{"compromised":true}}`,
			line:    1,
			cause:   "observed.edge_factor_chain[0].factor: missing",
		},
		{
			// 坏行（解码失败）钉住"行号与 JSON 语法错误同处一条消息"，且行号 > 1：
			// 第 1 行必须是**完全合法**的记录，否则先报的会是第 1 行的字段问题。
			//
			// 注意这条 cause 钉的是 **stdlib** `encoding/json` 的原文（"invalid character 'n'
			// looking for beginning of object key string"）—— 它是这张表里**唯一**不属于本仓的
			// 消息：其余各条都写在我们自己的 `fmt.Errorf` 里，改文案就必须改表；而这一条会在
			// Go 升级（或改用第三方 JSON 库）时由编译器/上游负责，届时**在这里**确认新文案即可。
			name:    "malformed-line-two",
			content: good + "\n{not json}",
			line:    2,
			cause:   "invalid character 'n' looking for beginning of object key string",
		},
	}

	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".jsonl")
			if err := os.WriteFile(path, []byte(tc.content+"\n"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := LoadFileAs("edgecompare", path)
			if err == nil {
				t.Fatal("expected the record to be rejected, got nil error")
			}
			// 临时目录逐机不同：把它的字面量归一，断言只对"形状 + 文案"敏感。
			got := strings.ReplaceAll(err.Error(), dir, "<dir>")
			want := "edgecompare: " + filepath.Join("<dir>", tc.name+".jsonl") + fmt.Sprintf(" line %d: ", tc.line) + tc.cause
			if got != want {
				t.Errorf("错误串已漂移：\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// TestMarshalLoadRoundTrip：同一份记录，`MarshalRecord` → `LoadFile` 必须逐位往返
// （生产者的写出与消费者的读入不是两份实现，而是同一个 `Validate` 的两端）。
//
// 夹具直接用 **spec §5.1 的示例正文**（从设计文档里提取，而不是在本文件里再抄一份）：
// 本项目已经因为"规范示例与读取层各写各的"被咬过一次，再抄一份等于把那个失败模式
// 搬进契约包自己。
//
// 示例正文里**没有** `effective_weights`（它是本轮才加进来的字段，读取层刻意不要求它），
// 故这里按**生产者**的身份补上"参与聚合的域"的权重后再写出 —— 这正是采集器必须做的事
// （`MarshalRecord` 会拒绝没写权重的记录，见 TestMarshalRecordRequiresEffectiveWeights）。
func TestMarshalLoadRoundTrip(t *testing.T) {
	first := loadDocSample(t)
	first.Observed.EffectiveWeights = map[string]float64{
		"attack_surface": 1, "business_continuity": 1, "operation_trust": 1,
		"resilience": 1, "kernel_security": 1,
	}

	raw, err := MarshalRecord(first)
	if err != nil {
		t.Fatalf("MarshalRecord: %v", err)
	}
	if n := bytes.Count(raw, []byte("\n")); n != 1 {
		t.Fatalf("JSONL 必须一行一条记录（只有结尾换行），实际有 %d 个换行: %q", n, raw)
	}
	if bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) {
		t.Fatal("写出不得带 UTF-8 BOM")
	}
	if !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatalf("写出必须以 \\n 结尾: %q", raw)
	}

	again, err := LoadFile(mustJSONL(t, "roundtrip.jsonl", string(raw)))
	if err != nil {
		t.Fatalf("读回自己写出的记录失败（生产者/消费者不同源）: %v\n%s", err, raw)
	}
	if len(again) != 1 {
		t.Fatalf("got %d records, want 1", len(again))
	}
	if !recordsDeepEqual(first, again[0]) {
		t.Fatalf("往返不逐位相等:\nfirst: %+v\nagain: %+v", first, again[0])
	}
}

// recordsDeepEqual 比较两条记录的**可序列化内容**（存在性标记是解码产物，不参与比较；
// 它们的口径已由 TestExistenceAccessorsMirrorJSONPresence 单独钉住）。
func recordsDeepEqual(a, b Record) bool {
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	var ma, mb map[string]any
	if err := json.Unmarshal(ra, &ma); err != nil {
		return false
	}
	if err := json.Unmarshal(rb, &mb); err != nil {
		return false
	}
	na, _ := json.Marshal(ma)
	nb, _ := json.Marshal(mb)
	return bytes.Equal(na, nb)
}

// TestMarshalRecordRejectsUnconstructibleRecord：写出前做**生产者自检**（构造要求）——
// 规范因子 ID 不满足时宁可拒绝，也不落盘一条"读取层照样接受、但离线重算会静默走
// 全 1 fallback"的记录（那正是本任务要根治的漂移形态）。
//
// 夹具带上合法的 `effective_weights`，让拒绝的**唯一**理由就是那个非规范 ID
// （否则本条会被"缺权重"那条自检兜住，测不到构造自检本身）。
func TestMarshalRecordRejectsUnconstructibleRecord(t *testing.T) {
	r := validRecord()
	r.Observed.EffectiveWeights = map[string]float64{"attack_surface": 35, "operation_trust": 25}
	r.Observed.EdgeFactorChain[0].Factor = "selinux_disabled"
	_, err := MarshalRecord(r)
	if err == nil {
		t.Fatal("非规范因子 ID 的记录不得被写出")
	}
	if !strings.Contains(err.Error(), "canonical") {
		t.Errorf("拒绝理由必须指向规范 ID（而不是被别的自检兜住）: %v", err)
	}
}

// ============================================================================
// spec §5.1 示例记录的提取（与 cmd/edgecompare/docs_schema_test.go 同款，但这里只取正文）
// ============================================================================

// designDocPath 从本包目录（internal/edgeexp）相对定位设计文档。
const designDocPath = "../../docs/EDGE_FACTOR_COUPLING_DESIGN_2026-09-08.md"

// loadDocSample 取 §5.1 标题之后第一个 ```json 围栏的内容，压成 JSONL 的真实形态后读入。
//
// 原始示例为了可读性做了缩进；JSONL 里必须压成单行（一行一条记录）。
func loadDocSample(t *testing.T) Record {
	t.Helper()
	recs, err := LoadFile(mustJSONL(t, "spec51.jsonl", docSampleLine(t)+"\n"))
	if err != nil {
		t.Fatalf("spec §5.1 的示例记录被读取层拒绝 —— 文档与契约包已漂移，采集器照此实现会一条都读不进来:\n%v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("期望 1 条记录，得到 %d 条", len(recs))
	}
	return recs[0]
}

// docSampleLine 返回 §5.1 示例的**单行**形态。
func docSampleLine(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(designDocPath)
	if err != nil {
		t.Fatalf("读设计文档: %v", err)
	}
	doc := string(raw)
	sec := strings.Index(doc, "### 5.1 ")
	if sec < 0 {
		t.Fatalf("%s: 找不到 §5.1 标题（文档结构变了？）", designDocPath)
	}
	rest := doc[sec:]
	open := strings.Index(rest, "```json")
	if open < 0 {
		t.Fatalf("%s §5.1: 找不到 ```json 围栏", designDocPath)
	}
	rest = rest[open+len("```json"):]
	closeIdx := strings.Index(rest, "```")
	if closeIdx < 0 {
		t.Fatalf("%s §5.1: json 围栏没有闭合", designDocPath)
	}
	sample := strings.TrimSpace(rest[:closeIdx])
	var compacted bytes.Buffer
	if err := json.Compact(&compacted, []byte(sample)); err != nil {
		t.Fatalf("§5.1 的示例不是合法 JSON（连读取层之前的解析都过不了）: %v", err)
	}
	return compacted.String()
}
