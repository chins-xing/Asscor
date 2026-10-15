//go:build expr && engine && checks

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chins-xing/asscor/internal/edgeexp"
)

// harnessReport 是攻击 harness 产物的**输入格式**（本工具解析的契约）。
//
// 谁写它：Task 4 的 `edge_attack.sh <scenario> <out.json>`（固定剧本 + agent 心跳轮询判定
// compromised + 逐检查记录注入时刻）。**字段一律显式**：JSON 的"没写"与零值在 Go 结构体里
// 同形，而这里的每个字段缺失都会被静默读成 0/false 并扭曲决策层或严重度（spec §5.1 的
// 记录构造要求同款纪律），故全部用指针解码，缺任何一个都报错并指名道姓。
type harnessReport struct {
	// Scenario 是 harness 自己报的场景名。可选，但**报了就必须与 --scenario 一致**：
	// 把 A 场景的产物 join 到 B 场景上是最容易发生、也最难发现的错误
	// （记录照常写出、只是标签全错，所有指标都建立在错位的标签上）。
	Scenario string `json:"scenario"`

	// 客观结果（spec §5.1 的 ground_truth 对象，扁平写在 harness 产物顶层）。
	Compromised       *bool    `json:"compromised"`
	TimeToCompromiseS *float64 `json:"time_to_compromise_s"`
	TTPsAchieved      *int     `json:"ttps_achieved"`
	NodesAffected     *int     `json:"nodes_affected"`
	BlockEffective    *bool    `json:"block_effective"`

	// Basis 是标签依据（`targeted_ttp` / `recon_playbook`，Task 4D Step 3B / 用户 L2 裁定）。
	//
	// **指针解码：缺失 ⇒ 记录里也缺席**（不写一个猜出来的默认值）。为什么不做"缺省填
	// recon_playbook"：那会把"这份产物没声明依据"伪装成"它是侦察剧本"，而记录一旦落盘就
	// 无法再区分 —— 依据是**标签的语义**，不是可以补的默认值。写错（非两个合法值）在
	// `edgeexp.Validate` 处被拒（值域校验不是"要求"，是"不许写错"）。
	Basis *string `json:"basis"`
	// TargetTTP 是 harness 产物的目标 TTP 段（`{ability_id, ability_name, …}`，Task 4D Step 4）。
	//
	// 记录里只取"**谁**是目标"（id/name）—— 成功与否已经在 `compromised` 里了，再抄一份就是
	// 两个可能漂移的真源。而"谁"必须留痕：没有它，报告里那句"compromised = 目标 TTP 是否成功"
	// 事后**不可复核**（同一个剧本里可能有多条 ability，实测对照 ability 的成功与目标成功同形）。
	TargetTTP *harnessTargetTTP `json:"target_ttp"`

	// PlaybookHash / TopologyHash 是溯源（拓扑与剧本入档，spec §5.3）。
	// `PlaybookHash` 进 `meta.playbook_hash`；`TopologyHash` **不进记录**（spec §5.1 的 schema
	// 没有这个槽位，它归 Task 4 的 run.json）。这里声明它只为让"harness 产物的格式"在这份结构体
	// 上有一处完整的声明面。
	//
	// **刻意不启用 `DisallowUnknownFields`**（评审 M4 问过）：`json.Unmarshal` 默认忽略未知键，
	// 所以"键拼错了"这件事在这里**不是**靠字段清单发现的，而是靠上面那组**必填字段的指针解码**
	// 发现的（键拼错 ⇒ 目标字段缺席 ⇒ 报出具体缺了哪个）。而一旦开了 DisallowUnknownFields，
	// Task 4 的脚本往产物里多写任何一个字段（拓扑细节、时间线、退出码……）都会让**采集器直接
	// 失败**——那是把"如实采集"换成了"格式洁癖"，代价远大于收益。真需要"格式只此一份"的话，
	// 做法是给产物加版本号并在解析处校验它，而不是禁用未知键。
	PlaybookHash string `json:"playbook_hash"`
	TopologyHash string `json:"topology_hash"`

	// Injections 是**每个被注入检查的注入/采集时刻**（RFC3339）。它是链上 `ts` 的唯一来源
	// （裁定 3）：引擎侧链上所有条目的 ts 是同一个评分时刻，而 chain 模型要求相邻观测严格
	// 递增，全部同值会让所有有向耦合被跳过、C 候选退化成 V。
	Injections []harnessInjection `json:"injections"`

	// 声明面（Task 8 Step ④）：`expected_chain_factors` 是 harness 声明的**注入集**，
	// `expected_baseline_factors` / `..._source` 是**按基质**声明的**基线活跃集**与它的来源。
	// 三者一起决定采集侧相等断言的右边（`声明面 = 基线活跃集 ∪ 注入集`）。
	//
	// 这里**不做指针解码**（与上面那组必填字段不同）：声明面是**证据**，不是判据的输入 ——
	// 缺了它记录照样合法（历史记录与手写夹具都没有这三个键）。采集侧该拒的情形已经由
	// `edge_collect.sh` 的相等断言负责，采集器不在这里替它做决定。
	ExpectedChainFactors          []string `json:"expected_chain_factors"`
	ExpectedBaselineFactors       []string `json:"expected_baseline_factors"`
	ExpectedBaselineFactorsSource string   `json:"expected_baseline_factors_source"`

	// SubstrateIdentity 是 harness 产物里"这批数据在什么基质/什么实例/什么策略状态"下采的那一段
	// （`edge_attack.sh` 写出：`{substrate, instance, policy_on}`）。
	//
	// 采集器**只取 `policy_on` 一个字段**（Task 10 / 用户裁定「甲」：矩阵新增一条"策略在"的臂，
	// 同一场景两个臂必须只靠记录本身就能分开）。`substrate`/`instance` 不进记录：前者由
	// `meta.observation_target` 的 `substrate=` 承载，后者已经写在 `observation_target` 里 ——
	// 再抄一份就是第二个真源。同样**不做指针解码**：老产物没有这一段，记录照样合法。
	SubstrateIdentity *harnessSubstrateIdentity `json:"substrate_identity"`

	// RepeatIndex 是**重复轴**（Task 11）：`edge_attack.sh` 在 `EDGEEXP_REPEAT_INDEX` 被显式给出
	// （重复号 >1）时才写这个键。采集器把它落进 `meta.repeat`；缺席 = 第 1 遍（不写该键）。
	RepeatIndex *string `json:"repeat_index"`
}

// harnessSubstrateIdentity 是 harness 产物的 `substrate_identity` 段（只声明本工具消费的字段）。
type harnessSubstrateIdentity struct {
	PolicyOn string `json:"policy_on"`
}

// harnessInjection 是一次注入观测：哪个检查、什么时候。
type harnessInjection struct {
	Check string `json:"check"`
	At    string `json:"at"`
}

// harnessTargetTTP 是 harness 产物里"目标 TTP"那一段（Task 4D Step 4）。
//
// 只声明本工具真正消费的两个字段：`ability_id` / `ability_name`。其余（`links`/`success_links`/
// `status_counts`/`note`…）留在产物里供人看，采集器**不解释**它们 —— 那是 harness 的判据，
// 在这里再抄一遍就等于两份真源（判据漂移时记录与产物会各说各话）。
type harnessTargetTTP struct {
	AbilityID   string `json:"ability_id"`
	AbilityName string `json:"ability_name"`
}

// groundTruth 是采集器内部的客观结果（与任何模型无关）。
//
// 为什么不是直接复用 `edgeexp.GroundTruth`：契约类型的"字段存在性标记"（`compromised` 是否
// 显式出现）只由 `UnmarshalJSON` 设置，而本工具需要**先**用指针解码把"没写"拦在解析处
// （错误信息才能指到 harness 产物的具体行）。进记录时经 `recordGroundTruth` 回填。
type groundTruth struct {
	Compromised       bool    `json:"compromised"`
	TimeToCompromiseS float64 `json:"time_to_compromise_s"`
	TTPsAchieved      int     `json:"ttps_achieved"`
	NodesAffected     int     `json:"nodes_affected"`
	BlockEffective    bool    `json:"block_effective"`

	// Basis 是标签依据（空 = harness 没说 ⇒ 记录里也缺席，见 harnessReport.Basis）。
	Basis string `json:"basis,omitempty"`
	// TargetAbility 是"哪条 ability 是目标"（空 = 未声明；见 harnessReport.TargetTTP）。
	TargetAbility *edgeexp.TargetAbility `json:"target_ability,omitempty"`

	PlaybookHash string               `json:"playbook_hash"`
	Injections   map[string]time.Time `json:"injections"`

	// 声明面（Task 8 Step ④）：随记录落盘，让**只看数据集**的人也能看出这批数据做过哪种基线声明
	// （见 `edgeexp.Meta` 那三个字段的说明）。此处**不参与任何判据**。
	ExpectedChainFactors          []string `json:"expected_chain_factors,omitempty"`
	ExpectedBaselineFactors       []string `json:"expected_baseline_factors,omitempty"`
	ExpectedBaselineFactorsSource string   `json:"expected_baseline_factors_source,omitempty"`

	// PolicyOn 是**实验条件**（策略在/不在）在记录里的显式痕迹（Task 10 / 用户裁定「甲」）。
	// 取自 harness 产物的 `substrate_identity.policy_on`（`edge_attack.sh:547` 写出、`:933` 落盘）
	// ⇒ 它是**攻击那一刻**真实的策略状态，不是采集期的猜测。空 = 产物没写（老产物）⇒ 记录里缺席。
	// 与声明面三键同路数：**证据，不是判据输入**（不进评分、不影响阈值、不进 `Validate`）。
	PolicyOn string `json:"policy_on,omitempty"`

	// RepeatIndex 同 `Meta.Repeat`（重复轴）；空 = 产物没写 ⇒ 记录里缺席。
	RepeatIndex string `json:"repeat_index,omitempty"`
}

// loadGroundTruth 解析攻击 harness 产物。
//
// M3：`time_to_compromise_s` 缺失即报错 —— 它是严重度（`severityOf`）与"多久被攻陷"的唯一
// 客观来源，缺失会被静默读成 0 并让该场景在排序层证据里变成"几乎是瞬时攻陷"。
func loadGroundTruth(path, scenario string) (groundTruth, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return groundTruth{}, fmt.Errorf("edgescen: 读攻击 harness 产物 %s: %w", path, err)
	}
	var rep harnessReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return groundTruth{}, fmt.Errorf("edgescen: 解析攻击 harness 产物 %s: %w", path, err)
	}
	if rep.Scenario != "" && rep.Scenario != scenario {
		return groundTruth{}, fmt.Errorf("edgescen: harness 产物 %s 报的场景是 %q，而 --scenario 是 %q —— 场景与客观结果错位会让所有指标建立在错误的标签上",
			path, rep.Scenario, scenario)
	}
	var missing []string
	if rep.Compromised == nil {
		missing = append(missing, "compromised")
	}
	if rep.TimeToCompromiseS == nil {
		missing = append(missing, "time_to_compromise_s")
	}
	if rep.TTPsAchieved == nil {
		missing = append(missing, "ttps_achieved")
	}
	if rep.NodesAffected == nil {
		missing = append(missing, "nodes_affected")
	}
	if rep.BlockEffective == nil {
		missing = append(missing, "block_effective")
	}
	if len(missing) > 0 {
		return groundTruth{}, fmt.Errorf("edgescen: harness 产物 %s 缺字段 %s —— 缺失会被静默读成 0/false 并直接扭曲漏判率与严重度（compromised 缺失会让该场景被标成『未攻陷』）",
			path, strings.Join(missing, ", "))
	}

	injections := make(map[string]time.Time, len(rep.Injections))
	for i, inj := range rep.Injections {
		check := strings.TrimSpace(inj.Check)
		if check == "" {
			return groundTruth{}, fmt.Errorf("edgescen: harness 产物 %s 的 injections[%d] 缺 check", path, i)
		}
		at, err := time.Parse(time.RFC3339, strings.TrimSpace(inj.At))
		if err != nil {
			return groundTruth{}, fmt.Errorf("edgescen: harness 产物 %s 的 injections[%d]（%s）的 at = %q 不是 RFC3339：%v", path, i, check, inj.At, err)
		}
		if prev, dup := injections[check]; dup {
			return groundTruth{}, fmt.Errorf("edgescen: harness 产物 %s 给检查 %s 报了两个注入时刻（%s 与 %s）—— 哪个才是该因子观测的 ts 无从判断，必须唯一",
				path, check, prev.Format(time.RFC3339), at.Format(time.RFC3339))
		}
		injections[check] = at.UTC()
	}

	basis := ""
	if rep.Basis != nil {
		basis = strings.TrimSpace(*rep.Basis)
	}
	var targetAbility *edgeexp.TargetAbility
	if rep.TargetTTP != nil {
		id := strings.TrimSpace(rep.TargetTTP.AbilityID)
		if id != "" {
			targetAbility = &edgeexp.TargetAbility{ID: id, Name: strings.TrimSpace(rep.TargetTTP.AbilityName)}
		}
	}

	return groundTruth{
		Compromised:       *rep.Compromised,
		TimeToCompromiseS: *rep.TimeToCompromiseS,
		TTPsAchieved:      *rep.TTPsAchieved,
		NodesAffected:     *rep.NodesAffected,
		BlockEffective:    *rep.BlockEffective,
		Basis:             basis,
		TargetAbility:     targetAbility,
		PlaybookHash:      rep.PlaybookHash,
		Injections:        injections,
		// 声明面原样带上（含空基线的显式来源串：空必须是被**声明出来的**空）。
		ExpectedChainFactors:          trimAll(rep.ExpectedChainFactors),
		ExpectedBaselineFactors:       trimAll(rep.ExpectedBaselineFactors),
		ExpectedBaselineFactorsSource: strings.TrimSpace(rep.ExpectedBaselineFactorsSource),
		// 策略状态原样带上（"0"/"1"；产物没这一段就是空 ⇒ 记录里 `meta.policy_on` 缺席）。
		PolicyOn: substratePolicyOn(rep.SubstrateIdentity),
		// 重复轴（Task 11）：产物写了才带（空 ⇒ 记录里 `meta.repeat` 缺席 = 第 1 遍）。
		RepeatIndex: repeatIndexOf(rep.RepeatIndex),
	}, nil
}

// repeatIndexOf 归一 harness 产物里的重复号：非空且是正整数才带（否则空 ⇒ 记录里缺席）。
//
// 为什么归一而不是原样透传：这一列要在数据集里能被**比较**（第几遍重复），
// 而产物里的取值来自环境变量（可能带空白、可能是 `01`）。非法/缺失一律归空 ⇒ 字段缺席（不猜）。
func repeatIndexOf(p *string) string {
	if p == nil {
		return ""
	}
	s := strings.TrimSpace(*p)
	if s == "" {
		return ""
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return ""
	}
	return strconv.Itoa(n)
}

// substratePolicyOn 从 harness 产物的 `substrate_identity` 段取策略状态，并**归一成 "0"/"1"**。
//
// 为什么归一而不是原样透传：这一列要能被**只靠记录**判读"哪个臂"，而产物里的取值来自环境变量
// （`EDGEEXP_POLICY_ON`，可能是 `0`/`1`/`true`/`false`/带空白的串）。原样透传会让同一件事在数据集里
// 有多个写法（`"0"` 与 `""` 与 `"false"` 各占一种），而"读的人要自己猜哪种写法算关"正是本字段
// 要消灭的东西。非法/缺失取值一律归空 ⇒ 字段缺席（不猜）。
func substratePolicyOn(id *harnessSubstrateIdentity) string {
	if id == nil {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(id.PolicyOn)) {
	case "1", "true", "on", "yes":
		return "1"
	case "0", "false", "off", "no":
		return "0"
	default:
		return ""
	}
}

// trimAll 去掉每一项两侧空白并丢掉空串（与 `edge_collect.sh` 的 `norm` 同一个口径：
// 多一个空项会让"链上因子集 == 声明面"这条等式在两边都看起来正常的情况下判错）。
func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// recordGroundTruth 把客观结果转成契约类型。
//
// **必须**经一次 JSON 编解码：`edgeexp.GroundTruth` 的 `compromised` 存在性标记是非导出字段、
// 只由 `UnmarshalJSON` 设置 —— 直接写结构体字面量，无论字段写得多全，`Validate` 都会以
// 「ground_truth.compromised: missing」拒掉**每一条**记录。而"harness 根本没写这个字段"
// 这件事已在 `loadGroundTruth` 处以指针解码 + 明确错误拦住了，故这里不会把缺失伪装成在场。
func (g groundTruth) recordGroundTruth() (edgeexp.GroundTruth, error) {
	payload := struct {
		Compromised       bool                   `json:"compromised"`
		TimeToCompromiseS float64                `json:"time_to_compromise_s"`
		TTPsAchieved      int                    `json:"ttps_achieved"`
		NodesAffected     int                    `json:"nodes_affected"`
		BlockEffective    bool                   `json:"block_effective"`
		Basis             string                 `json:"basis,omitempty"`
		TargetAbility     *edgeexp.TargetAbility `json:"target_ability,omitempty"`
	}{
		Compromised:       g.Compromised,
		TimeToCompromiseS: g.TimeToCompromiseS,
		TTPsAchieved:      g.TTPsAchieved,
		NodesAffected:     g.NodesAffected,
		BlockEffective:    g.BlockEffective,
		Basis:             strings.TrimSpace(g.Basis),
		TargetAbility:     g.TargetAbility,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return edgeexp.GroundTruth{}, fmt.Errorf("客观结果编码失败: %w", err)
	}
	var out edgeexp.GroundTruth
	if err := json.Unmarshal(raw, &out); err != nil {
		return edgeexp.GroundTruth{}, fmt.Errorf("客观结果回读失败: %w", err)
	}
	return out, nil
}

// injectionSummary 是给自检摘要用的注入时刻一览（按检查 ID 排序，输出必须可复现）。
func (g groundTruth) injectionSummary() string {
	if len(g.Injections) == 0 {
		return "(无)"
	}
	ids := make([]string, 0, len(g.Injections))
	for id := range g.Injections {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, id+"@"+g.Injections[id].UTC().Format(time.RFC3339))
	}
	return strings.Join(parts, " ")
}
