//go:build edgeexp

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// 读取层：实验 JSONL（spec §5.1 schema）→ []Record。
//
// 本层做两件事，缺一不可：
//
//  1. **结构可解析性**：坏行必须以**行号** fail-fast，绝不静默跳过（静默跳过会让报告里的
//     样本量与实验规模对不上，而无人察觉）。
//  2. **必需字段的存在性与值域**（Fix round 2 / 评审 I2）：JSON 的"零值"与"没写"在 Go 结构体
//     里无法区分，而本任务的**主判据**恰恰建立在这些字段上 —— 缺失会被静默读成零值并直接
//     扭曲决策层：
//     - `observed.threshold` 缺失 ⇒ 0 ⇒ 任何非负分数都判 `acceptable` ⇒ 决策层退化为"全放行"
//       （漏判率变成"攻陷数 / N"、误阻断率恒为 0），而报告照常打印；
//     - `observed.spc_score` / `observed.threat_coeff` 缺失 ⇒ 0 ⇒ 被引擎公式的
//       `<= 0 ⇒ 1.0` 兜底成"无暴露面/无威胁"，总分被静默抬到最宽松的一档（C1 裁定新增的
//       两个必填项：引擎的总分是 `round2(0.5·base + 30·E + 20·T)`，缺了 E/T 就复现不出
//       部署判定线）；
//     - 链条目 `c_trigger` 缺失 ⇒ 0 ⇒ `EffectiveFactor` 返回 1 ⇒ `a_i = 0` ⇒ 该因子的惩罚
//       静默消失；
//     - 链条目 `effective_factor` 缺失 ⇒ 0 ⇒ 命中 `Synthesize` 的"未提供"哨兵 ⇒ 静默回落到
//       配置权重（与记录里的真实观测值无关）；
//     - `ground_truth.compromised` 缺失 ⇒ false ⇒ 标签被静默当成"未攻陷"。
//
// 故下面用**指针解码 + 存在性标记**把"缺失"与"合法零值"区分开：`c_trigger = 0` 是 ssam-lib
// 对"仅由级联激活、自身触发检查未失败"的因子的既有取值（见 validateRecord 的说明），必须放行；
// 而"字段根本没写"一律拒绝。语义校验（λ 覆盖、向量覆盖、因子有效性）仍由
// `edgefactor.Params.Validate` 与 `edgefactor.Synthesize` 在重算时负责 —— 与在线同一份实现。

type Record struct {
	ScenarioID  string      `json:"scenario_id"`
	Factors     []string    `json:"factors"`
	Injection   string      `json:"injection"`
	Observed    Observed    `json:"observed"`
	GroundTruth GroundTruth `json:"ground_truth"`
	Meta        Meta        `json:"meta"`
}

type Observed struct {
	DomainScores    map[string]float64 `json:"domain_scores"`
	FinalScore      float64            `json:"final_score"`
	Acceptable      bool               `json:"acceptable"`
	Threshold       float64            `json:"threshold"`
	SPCScore        float64            `json:"spc_score"`
	ThreatCoeff     float64            `json:"threat_coeff"`
	Checks          []CheckObs         `json:"checks"`
	EdgeFactorChain []ChainObs         `json:"edge_factor_chain"`

	spcScoreSet    bool
	threatCoeffSet bool
}

// UnmarshalJSON 记录 spc_score / threat_coeff 是否**显式出现**（口径同 ChainObs 与 GroundTruth）。
//
// 这两个字段是 C1 裁定新增的**必填项**：引擎的总分是
// `round2(0.5·base + 30·E + 20·T)`（`ssam.SSAMV20Formula`），缺了 E/T 就复现不出部署判定线。
// 而 JSON 的"零值"与"没写"在 Go 结构体里同形：缺失会被静默读成 0，随后被公式的
// `<= 0 ⇒ 1.0` 兜底成"无暴露/无威胁"，把总分抬到最宽松的一档 —— 报告照常打印，
// 决策层判据却全部失真。故与 `threshold`/`compromised` 同款处理：用指针解码区分两者。
func (o *Observed) UnmarshalJSON(data []byte) error {
	aux := struct {
		DomainScores    map[string]float64 `json:"domain_scores"`
		FinalScore      float64            `json:"final_score"`
		Acceptable      bool               `json:"acceptable"`
		Threshold       float64            `json:"threshold"`
		SPCScore        *float64           `json:"spc_score"`
		ThreatCoeff     *float64           `json:"threat_coeff"`
		Checks          []CheckObs         `json:"checks"`
		EdgeFactorChain []ChainObs         `json:"edge_factor_chain"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	o.DomainScores, o.FinalScore, o.Acceptable, o.Threshold = aux.DomainScores, aux.FinalScore, aux.Acceptable, aux.Threshold
	o.Checks, o.EdgeFactorChain = aux.Checks, aux.EdgeFactorChain
	if aux.SPCScore != nil {
		o.SPCScore, o.spcScoreSet = *aux.SPCScore, true
	}
	if aux.ThreatCoeff != nil {
		o.ThreatCoeff, o.threatCoeffSet = *aux.ThreatCoeff, true
	}
	return nil
}

type CheckObs struct {
	ID         string  `json:"id"`
	Domain     string  `json:"domain"`
	Passed     bool    `json:"passed"`
	Delta      float64 `json:"delta"`
	Confidence float64 `json:"confidence"`
	TS         string  `json:"ts"`
}

// ChainObs 是一条边缘因子链记录。
//
// 字段口径（决定离线重算能不能与在线逐位一致，改动前先读 spec §10.2）：
//   - `effective_factor` 是**在线观测到的因子值**，即已经过 ssam-lib 策略路径可信度衰减
//     一次的值（`ApplyEdgeFactorsToChecksPolicy`：factor = 1−(1−f)·c）；
//   - `c_trigger` 是触发检查的可信度；
//   - 离线重算必须再走一次**在线装配层**的换算（`ActivationFromResult` 的
//     `edgefactor.EffectiveFactor(effective_factor, c_trigger)`），合计口径为 1−(1−f)·c²
//     —— 这就是 spec §10.2 记为「可信度被衰减两次、标定前需裁定的已知问题」的那条口径。
//     本工具**复用**它，不修正（修正属独立决策，会改变评分）。
//   - `ts` 是 chain 模型（离线专用，在线因引擎结果类型无时间字段而 fail-fast）的唯一
//     时间来源。
//
// `cTriggerSet` / `effectiveFactorSet` 是**非导出的字段存在性标记**（不参与序列化），只用来
// 区分"写了 0"与"没写" —— 见本文件顶部说明与 validateRecord。
type ChainObs struct {
	Factor          string  `json:"factor"`
	TriggerCheck    string  `json:"trigger_check"`
	CTrigger        float64 `json:"c_trigger"`
	EffectiveFactor float64 `json:"effective_factor"`
	TS              string  `json:"ts"`

	cTriggerSet        bool
	effectiveFactorSet bool
}

// UnmarshalJSON 记录 c_trigger / effective_factor 是否**显式出现**。
//
// 用指针解码是为了拿到"字段存在"这一位信息：不加这层的话，缺失与合法零值在 `float64` 上完全
// 同形，而下层会把缺失当成 0 并静默算出一个"看起来正常"的分数（评审 I2）。
func (c *ChainObs) UnmarshalJSON(data []byte) error {
	aux := struct {
		Factor          string   `json:"factor"`
		TriggerCheck    string   `json:"trigger_check"`
		CTrigger        *float64 `json:"c_trigger"`
		EffectiveFactor *float64 `json:"effective_factor"`
		TS              string   `json:"ts"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.Factor, c.TriggerCheck, c.TS = aux.Factor, aux.TriggerCheck, aux.TS
	if aux.CTrigger != nil {
		c.CTrigger, c.cTriggerSet = *aux.CTrigger, true
	}
	if aux.EffectiveFactor != nil {
		c.EffectiveFactor, c.effectiveFactorSet = *aux.EffectiveFactor, true
	}
	return nil
}

// GroundTruth 是客观实验结果（与任何模型无关）。
//
// `Compromised` 保持 `bool`（下游 Task 9/10 直接消费该字段，不动接口），但**必须显式出现**：
// 用 `compromisedSet` 标记区分"写了 false"与"没写"。两者若不加区分，缺失会被读成 false，
// 该场景就被静默标成"未攻陷"，直接扭曲漏判率（分子分母同时被动）。
type GroundTruth struct {
	Compromised       bool    `json:"compromised"`
	TimeToCompromiseS float64 `json:"time_to_compromise_s"`
	TTPsAchieved      int     `json:"ttps_achieved"`
	NodesAffected     int     `json:"nodes_affected"`
	BlockEffective    bool    `json:"block_effective"`

	compromisedSet bool
}

// UnmarshalJSON 记录 `compromised` 是否显式出现（理由见类型注释与 validateRecord）。
func (g *GroundTruth) UnmarshalJSON(data []byte) error {
	aux := struct {
		Compromised       *bool   `json:"compromised"`
		TimeToCompromiseS float64 `json:"time_to_compromise_s"`
		TTPsAchieved      int     `json:"ttps_achieved"`
		NodesAffected     int     `json:"nodes_affected"`
		BlockEffective    bool    `json:"block_effective"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.Compromised != nil {
		g.Compromised, g.compromisedSet = *aux.Compromised, true
	}
	g.TimeToCompromiseS = aux.TimeToCompromiseS
	g.TTPsAchieved = aux.TTPsAchieved
	g.NodesAffected = aux.NodesAffected
	g.BlockEffective = aux.BlockEffective
	return nil
}

type Meta struct {
	Env          string `json:"env"`
	PlaybookHash string `json:"playbook_hash"`
	ConfigHash   string `json:"config_hash"`
	Run          int    `json:"run"`
	Timestamp    string `json:"timestamp"`
}

// LoadRecords 读取实验 JSONL（spec §5.1 schema）。
func LoadRecords(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("edgecompare: open %s: %w", path, err)
	}
	defer f.Close()

	var out []Record
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
	line := 0
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		// 空行（含只含空白的行）不携带记录，跳过；它们不可能是"被截断的记录"——
		// 截断的行一定带内容，会在下面按坏行报错。
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("edgecompare: %s line %d: %w", path, line, err)
		}
		if err := validateRecord(rec); err != nil {
			return nil, fmt.Errorf("edgecompare: %s line %d: %w", path, line, err)
		}
		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("edgecompare: read %s: %w", path, err)
	}
	return out, nil
}

// validateRecord 做「必需字段存在性 + 值域」校验（评审 I2 的落点），错误信息一律带字段路径。
//
// 检查顺序按 schema 的自然阅读顺序（scenario_id → observed.threshold → observed.domain_scores
// → observed.spc_score / threat_coeff → 因子链 → checks → ground_truth），且**只报第一个问题**：
// 一条坏行给一个可执行的修复指令，比堆一串错误更有用。
//
// 值域口径：
//   - `threshold > 0`：阈值必须是正数，否则 `score >= threshold` 恒真（决策层退化为全放行）。
//   - `spc_score ∈ (0,1]`：它是引擎的 `AssessmentOutput.SPCScore`（SPC 姿态分 p_score =
//     max(minPScore, 1 − 总惩罚)，归一化到 (0,1]，见 internal/spc/spc.go:604）。**0 是引擎的
//     "未设置"哨兵**（engine.go: `if output.SPCScore == 0 { output.SPCScore = 1.0 }`），
//     而缺失同样读成 0 ⇒ 两条路径都会静默变成"无暴露面惩罚"，把总分抬到最宽松的一档，
//     直接扭曲决策层判据。故缺失与 ≤ 0 都要拒绝。
//   - `threat_coeff > 0`：`[threat] coefficient` 的既有值域只有下界（ranges.go: `must be > 0`），
//     实测配置里出现过 1.4，故**不设上界**；0（缺失/未设置）同样被引擎兜底成 1.0。
//   - `effective_factor ∈ (0,1]`：合法因子值域（`EffectiveFactor` 的输出域）。0 是
//     `Synthesize` 里"未提供、回落到配置权重"的哨兵，越界值则会让 `a = (1−eff)·v` 变负。
//   - `c_trigger ∈ [0,1]`：**下界取 0 而不是 (0,1]** —— `c_trigger = 0` 是 ssam-lib 对
//     「仅由级联激活、自身触发检查未失败」的因子的既有取值
//     （`ApplyEdgeFactorsToChecksPolicy` 的 cascade 分支只把 Active 置真、不动 TriggerConfidence），
//     spec §5 的 S5 级联组正会产出这种记录；硬拒会拒掉真实数据集。被拒的是**缺失**
//     （字段根本不存在），那才是评审 I2 指出的静默路径。
//   - `ground_truth.compromised` 必须显式出现（缺失 ⇒ 静默变成"未攻陷"）。
//
// 域覆盖性不在这里校验：本层看不到"评估时用了哪些域"（权重是 `Evaluate` 的入参），
// 该检查落在 `Evaluate`（见 metrics.go:validateDomainsCovered）；本层只保证域分**非空**。
func validateRecord(rec Record) error {
	if rec.ScenarioID == "" {
		return fmt.Errorf("missing scenario_id")
	}
	if rec.Observed.Threshold <= 0 {
		return fmt.Errorf("observed.threshold = %v must be > 0 — 缺失会被当成 0，任何非负分数都会判 acceptable，决策层退化为『全放行』", rec.Observed.Threshold)
	}
	if len(rec.Observed.DomainScores) == 0 {
		return fmt.Errorf("observed.domain_scores: missing or empty — 没有域分就无从重算总分")
	}
	for d := range rec.Observed.DomainScores {
		if strings.TrimSpace(d) == "" {
			return fmt.Errorf("observed.domain_scores: contains an empty domain name")
		}
	}
	if !rec.Observed.spcScoreSet {
		return fmt.Errorf("observed.spc_score: missing — 引擎的判定线需要它（总分 = round2(0.5·base + 30·E + 20·T)）；缺失会被当成 0，而 0 是引擎的『未设置』哨兵（按 1.0 计），总分被静默抬到最宽松的一档")
	}
	if rec.Observed.SPCScore <= 0 || rec.Observed.SPCScore > 1 {
		return fmt.Errorf("observed.spc_score = %v out of (0,1] — 它是引擎输出的 SPC 姿态分（p_score = max(minPScore, 1−总惩罚)），0 是引擎的『未设置』哨兵", rec.Observed.SPCScore)
	}
	if !rec.Observed.threatCoeffSet {
		return fmt.Errorf("observed.threat_coeff: missing — 引擎的判定线需要它（总分 = round2(0.5·base + 30·E + 20·T)）；缺失会被当成 0，而 0 是引擎的『未设置』哨兵（按 1.0 计），总分被静默抬到最宽松的一档")
	}
	if rec.Observed.ThreatCoeff <= 0 {
		return fmt.Errorf("observed.threat_coeff = %v must be > 0（[threat] coefficient 的既有值域只有下界）— 0 是引擎的『未设置』哨兵", rec.Observed.ThreatCoeff)
	}
	for i, c := range rec.Observed.EdgeFactorChain {
		if strings.TrimSpace(c.Factor) == "" {
			return fmt.Errorf("observed.edge_factor_chain[%d].factor: missing", i)
		}
		if !c.cTriggerSet {
			return fmt.Errorf("observed.edge_factor_chain[%d].c_trigger: missing — 缺失会被当成 0（= 无可信度）并让该因子的惩罚静默消失", i)
		}
		if !c.effectiveFactorSet {
			return fmt.Errorf("observed.edge_factor_chain[%d].effective_factor: missing — 缺失会被当成 0（= Synthesize 的『未提供』哨兵）并静默回落到配置权重", i)
		}
		if c.CTrigger < 0 || c.CTrigger > 1 {
			return fmt.Errorf("observed.edge_factor_chain[%d].c_trigger = %v out of [0,1]", i, c.CTrigger)
		}
		if c.EffectiveFactor <= 0 || c.EffectiveFactor > 1 {
			return fmt.Errorf("observed.edge_factor_chain[%d].effective_factor = %v out of (0,1]", i, c.EffectiveFactor)
		}
		if _, err := parseTS(c.TS); err != nil {
			return fmt.Errorf("observed.edge_factor_chain[%d].ts: %w", i, err)
		}
	}
	for i, c := range rec.Observed.Checks {
		if _, err := parseTS(c.TS); err != nil {
			return fmt.Errorf("observed.checks[%d].ts: %w", i, err)
		}
	}
	if !rec.GroundTruth.compromisedSet {
		return fmt.Errorf("ground_truth.compromised: missing — 必须显式写出 true/false；缺失会被当成 false，该场景被静默标成『未攻陷』并直接扭曲漏判率/误阻断率")
	}
	return nil
}

// parseTS 解析 RFC3339 时间戳。空串合法（= 该字段缺席），非空但解析不了即坏值。
func parseTS(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	ts, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("not an RFC3339 timestamp: %q", v)
	}
	return ts, nil
}
