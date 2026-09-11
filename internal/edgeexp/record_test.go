package edgeexp

import (
	"bytes"
	"encoding/json"
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
// 本包新增：大小写折叠冲突 + 生效权重可选
// ============================================================================

// TestValidateRejectsCaseFoldCollision：两个只差大小写的因子 ID 会在消费侧被
// `NormalizeFactorID`（ToUpper+TrimSpace）**静默合并**成一个因子 —— 链上少一个惩罚项，
// 而报告照常打印。故读取层直接拒绝这种记录（正常情况下写入侧根本产不出它）。
func TestValidateRejectsCaseFoldCollision(t *testing.T) {
	r := validRecord()
	r.Observed.EdgeFactorChain = append(r.Observed.EdgeFactorChain, ChainObs{
		Factor: "ef-selinux", TriggerCheck: "OT-005", CTrigger: 0.9, EffectiveFactor: 0.82,
		cTriggerSet: true, effectiveFactorSet: true,
	})
	mustReject(t, r, "edge_factor_chain", "collides")

	// 前后空白同样被 NormalizeFactorID 吃掉，属同一种折叠。
	r = validRecord()
	r.Observed.EdgeFactorChain = append(r.Observed.EdgeFactorChain, ChainObs{
		Factor: " EF-SELINUX ", TriggerCheck: "OT-005", CTrigger: 0.9, EffectiveFactor: 0.82,
		cTriggerSet: true, effectiveFactorSet: true,
	})
	mustReject(t, r, "edge_factor_chain", "collides")

	// 反向对照：**不同**的因子不得被误报（否则这条检查会拒掉合法数据集）。
	r = validRecord()
	r.Observed.EdgeFactorChain = append(r.Observed.EdgeFactorChain, ChainObs{
		Factor: "EF-APPARMOR", TriggerCheck: "OT-005", CTrigger: 0.9, EffectiveFactor: 0.838,
		cTriggerSet: true, effectiveFactorSet: true,
	})
	if err := r.Validate(); err != nil {
		t.Fatalf("不同因子被误判为折叠冲突：%v", err)
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

	r = validRecord()
	r.Observed.EffectiveWeights = map[string]float64{"attack_surface": 35, "operation_trust": 25}
	if err := r.CheckEffectiveWeightsRecorded(); err != nil {
		t.Fatalf("写全生效权重后自检必须通过：%v", err)
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

// TestMarshalLoadRoundTrip：同一份记录，`MarshalRecord` → `LoadFile` 必须逐位往返
// （生产者的写出与消费者的读入不是两份实现，而是同一个 `Validate` 的两端）。
//
// 夹具直接用 **spec §5.1 的示例正文**（从设计文档里提取，而不是在本文件里再抄一份）：
// 本项目已经因为"规范示例与读取层各写各的"被咬过一次，再抄一份等于把那个失败模式
// 搬进契约包自己。
func TestMarshalLoadRoundTrip(t *testing.T) {
	first := loadDocSample(t)

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
func TestMarshalRecordRejectsUnconstructibleRecord(t *testing.T) {
	r := validRecord()
	r.Observed.EdgeFactorChain[0].Factor = "selinux_disabled"
	if _, err := MarshalRecord(r); err == nil {
		t.Fatal("非规范因子 ID 的记录不得被写出")
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
