// Package edgeexp 是边缘因子实验记录（JSONL，spec §5.1）的**共享契约包**：
// 生产者（未来的 `cmd/edgescen` 采集器）与消费者（`cmd/edgecompare` 离线重算工具）
// 共用这里的类型、存在性口径与校验实现。
//
// **为什么必须共享**：本项目已经被这个契约漂移咬过一次 —— spec §5.1 的示例记录当时被自己的
// 读取层拒绝，因为文档与读取层是两份分别写成的实现（示例缺了 C1 裁定新增的 `spc_score` /
// `threat_coeff`）。生产者的写出与消费者的读入若各写一份，下一次漂移会以同一种形态出现：
// 一边接受、一边拒绝，或两边对"缺失"的理解不同，而**报告照常打印**。
//
// 本包**不带 build tag**：`internal/edgefactor` 也是无 tag 的纯计算包，故两侧（在线装配、
// 离线重算）都能 import 它 —— 这是"同一份判据只有一处实现"的前提。
//
// 本包的判据分三层，边界是 spec §5.1 划的，改动前先读清楚：
//
//  1. **读取层契约**（`Record.Validate` + `LoadFile`）：必需字段的**存在性**与**值域**，
//     以及大小写折叠冲突 —— 这些一旦缺失就会被静默读成零值并直接扭曲决策层，故 fail-fast。
//  2. **记录构造要求**（`ValidateConstruction` / `CheckTriggerCrossReference` /
//     `CheckEffectiveWeightsRecorded`）：**生产者侧**自检。spec §5.1 明说
//     「这些是"记录构造要求"，不是读取层契约」—— 写错不会有任何读取层报错，只会让报告与
//     论文证据失真。它们由采集器调用（见各函数注释里的路径限制）。
//  3. **写出口**（`MarshalRecord`）：写之前先做第 2 层里与路径无关的自检，绝不落盘一条
//     "读取层照样接受、但离线重算会静默改分"的记录。
package edgeexp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/chins-xing/asscor/internal/edgefactor"
)

// Record 是一条实验记录（spec §5.1 schema）。
type Record struct {
	ScenarioID  string      `json:"scenario_id"`
	Factors     []string    `json:"factors"`
	Injection   string      `json:"injection"`
	Observed    Observed    `json:"observed"`
	GroundTruth GroundTruth `json:"ground_truth"`
	Meta        Meta        `json:"meta"`
}

type Observed struct {
	DomainScores map[string]float64 `json:"domain_scores"`

	// EffectiveWeights 是引擎**实际生效**的逐域权重（键集 = "参与聚合的域"）。
	//
	// 为什么记录里必须有它（spec §5.1 前提 2）：离线重算必须知道"哪些域参与聚合、各占多少
	// 权重"，而从配置里读不出来 —— 引擎 legacy 的内在层加权用的是 `DynamicScoringEngine` 的
	// **动态权重**（0 权重域会被填默认值并 `Normalize(100)`），故"配置权重 ≠ 生效权重"，
	// 只凭配置复算会有系统偏差。`DomainScores` 也补不上这个信息：四个核心域字段恒存在，
	// 记录**无法区分**"该域参与聚合但值为 0"与"该域不在聚合里"，多域加权的浮点顺序因此
	// 不可完全复现。
	//
	// 在**读取层是可选**的（既有夹具与历史数据集里没有它，读取层不得因此变红）；写它是
	// **生产者**的义务，由 `CheckEffectiveWeightsRecorded` 自检、由离线的 round-trip 门禁消费。
	EffectiveWeights map[string]float64 `json:"effective_weights"`

	FinalScore      float64    `json:"final_score"`
	Acceptable      bool       `json:"acceptable"`
	Threshold       float64    `json:"threshold"`
	SPCScore        float64    `json:"spc_score"`
	ThreatCoeff     float64    `json:"threat_coeff"`
	Checks          []CheckObs `json:"checks"`
	EdgeFactorChain []ChainObs `json:"edge_factor_chain"`

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
		DomainScores     map[string]float64 `json:"domain_scores"`
		EffectiveWeights map[string]float64 `json:"effective_weights"`
		FinalScore       float64            `json:"final_score"`
		Acceptable       bool               `json:"acceptable"`
		Threshold        float64            `json:"threshold"`
		SPCScore         *float64           `json:"spc_score"`
		ThreatCoeff      *float64           `json:"threat_coeff"`
		Checks           []CheckObs         `json:"checks"`
		EdgeFactorChain  []ChainObs         `json:"edge_factor_chain"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	o.DomainScores, o.EffectiveWeights = aux.DomainScores, aux.EffectiveWeights
	o.FinalScore, o.Acceptable, o.Threshold = aux.FinalScore, aux.Acceptable, aux.Threshold
	o.Checks, o.EdgeFactorChain = aux.Checks, aux.EdgeFactorChain
	if aux.SPCScore != nil {
		o.SPCScore, o.spcScoreSet = *aux.SPCScore, true
	}
	if aux.ThreatCoeff != nil {
		o.ThreatCoeff, o.threatCoeffSet = *aux.ThreatCoeff, true
	}
	return nil
}

// SPCScoreSet 报告 `spc_score` 是否**显式出现**在记录里。
//
// 存在性标记本身是非导出字段（只由 UnmarshalJSON 设置），跨包的门禁需要在"缺失被拒"与
// "值越界被拒"之间做出区分 —— 那是两种不可互换的诊断（前者是"记录不完整"，后者会把人引向
// "值写错了"）。故这里只读导出。
func (o Observed) SPCScoreSet() bool { return o.spcScoreSet }

// ThreatCoeffSet 报告 `threat_coeff` 是否**显式出现**在记录里（口径同 SPCScoreSet）。
func (o Observed) ThreatCoeffSet() bool { return o.threatCoeffSet }

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
// 区分"写了 0"与"没写" —— 见本文件顶部说明与 Validate。
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

// CTriggerSet 报告 `c_trigger` 是否**显式出现**在记录里（`c_trigger = 0` 是合法值，见 Validate）。
func (c ChainObs) CTriggerSet() bool { return c.cTriggerSet }

// EffectiveFactorSet 报告 `effective_factor` 是否**显式出现**在记录里。
func (c ChainObs) EffectiveFactorSet() bool { return c.effectiveFactorSet }

// GroundTruth 是客观实验结果（与任何模型无关）。
//
// `Compromised` 保持 `bool`（下游直接消费该字段），但**必须显式出现**：用 `compromisedSet`
// 标记区分"写了 false"与"没写"。两者若不加区分，缺失会被读成 false，
// 该场景就被静默标成"未攻陷"，直接扭曲漏判率（分子分母同时被动）。
type GroundTruth struct {
	Compromised       bool    `json:"compromised"`
	TimeToCompromiseS float64 `json:"time_to_compromise_s"`
	TTPsAchieved      int     `json:"ttps_achieved"`
	NodesAffected     int     `json:"nodes_affected"`
	BlockEffective    bool    `json:"block_effective"`

	compromisedSet bool
}

// UnmarshalJSON 记录 `compromised` 是否显式出现（理由见类型注释与 Validate）。
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

// CompromisedSet 报告 `compromised` 是否**显式出现**（`false` 与"没写"必须区分开）。
func (g GroundTruth) CompromisedSet() bool { return g.compromisedSet }

// Meta 是记录的溯源信息。
//
// `WeightSource` / `AssemblyError` 是里程碑 B 新增的**可选**字段（`omitempty`），读取层
// 不要求它们：
//   - `WeightSource` 说明 `observed.effective_weights` 是从哪来的（以 `config_hash` 为锚点），
//     供 round-trip 门禁与论文证据链归因；
//   - `AssemblyError` 记录装配期的非致命异常（例如某域权重被动态补齐），
//     让"这份记录的权重口径不是纯配置值"这件事**留下痕迹**，而不是只在离线复算时表现为偏差。
type Meta struct {
	Env          string `json:"env"`
	PlaybookHash string `json:"playbook_hash"`
	ConfigHash   string `json:"config_hash"`
	Run          int    `json:"run"`
	Timestamp    string `json:"timestamp"`

	WeightSource  string `json:"weight_source,omitempty"`
	AssemblyError string `json:"assembly_error,omitempty"`
}

// LoadFile 读取实验 JSONL（spec §5.1 schema），错误前缀为本包名。
//
// 它做两件事，缺一不可：
//
//  1. **结构可解析性**：坏行必须以**行号** fail-fast，绝不静默跳过（静默跳过会让报告里的
//     样本量与实验规模对不上，而无人察觉）。
//  2. **必需字段的存在性与值域**（Fix round 2 / 评审 I2）：JSON 的"零值"与"没写"在 Go 结构体
//     里无法区分，而本任务的**主判据**恰恰建立在这些字段上 —— 缺失会被静默读成零值并直接
//     扭曲决策层：
//     - `observed.threshold` 缺失 ⇒ 0 ⇒ 任何非负分数都判 `acceptable` ⇒ 决策层退化为"全放行"
//     （漏判率变成"攻陷数 / N"、误阻断率恒为 0），而报告照常打印；
//     - `observed.spc_score` / `observed.threat_coeff` 缺失 ⇒ 0 ⇒ 被引擎公式的
//     `<= 0 ⇒ 1.0` 兜底成"无暴露面/无威胁"，总分被静默抬到最宽松的一档（C1 裁定新增的
//     两个必填项：引擎的总分是 `round2(0.5·base + 30·E + 20·T)`，缺了 E/T 就复现不出
//     部署判定线）；
//     - 链条目 `c_trigger` 缺失 ⇒ 0 ⇒ `EffectiveFactor` 返回 1 ⇒ `a_i = 0` ⇒ 该因子的惩罚
//     静默消失；
//     - 链条目 `effective_factor` 缺失 ⇒ 0 ⇒ 命中 `Synthesize` 的"未提供"哨兵 ⇒ 静默回落到
//     配置权重（与记录里的真实观测值无关）；
//     - `ground_truth.compromised` 缺失 ⇒ false ⇒ 标签被静默当成"未攻陷"。
//
// 故下面用**指针解码 + 存在性标记**把"缺失"与"合法零值"区分开：`c_trigger = 0` 是 ssam-lib
// 对"仅由级联激活、自身触发检查未失败"的因子的既有取值（见 Validate 的说明），必须放行；
// 而"字段根本没写"一律拒绝。语义校验（λ 覆盖、向量覆盖、因子有效性）仍由
// `edgefactor.Params.Validate` 与 `edgefactor.Synthesize` 在重算时负责 —— 与在线同一份实现。
func LoadFile(path string) ([]Record, error) { return LoadFileAs("edgeexp", path) }

// LoadFileAs 同 LoadFile，但错误前缀的工具名由调用方给出。
//
// 为什么要有它：错误信息里的 `edgecompare: ` 前缀是**消费者 CLI 的可观测行为**，搬迁到共享包
// 后必须逐字不变（本任务的验收是"既有用例一条不改仍全绿"，其中包含错误面的断言）；
// 而采集器（`cmd/edgescen`）希望前缀是自己的工具名。前缀因此是调用方的参数，
// 不是本包写死的常量 —— 格式（`<tool>: <path> line <n>: <原因>`）仍只有这一处实现。
func LoadFileAs(tool, path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: open %s: %w", tool, path, err)
	}
	defer f.Close()

	var out []Record
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
	line := 0
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		// 文件首个字节若是 UTF-8 BOM，先剥掉（Task 8 实现者提出的疑虑 5）。
		//
		// 剥离是**刻意**的而不是"宽容"：本项目的采集器与数据集都在 Windows 上产出，
		// 而记事本/PowerShell 重定向/Python 的部分写法都会在文件头写 BOM；不剥的话
		// 第一条记录会以 `invalid character 'ï' looking for beginning of value` 报错 ——
		// 那条信息指不到"文件头有 BOM"，读者会在 JSON 正文里找一个根本不存在的问题，
		// 而整批数据一条都读不进来。BOM 只在**文件首行行首**剥离（行内的 U+FEFF 仍是数据，
		// 不静默改写）。
		if line == 1 {
			raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
		}
		// 空行（含只含空白的行）不携带记录，跳过；它们不可能是"被截断的记录"——
		// 截断的行一定带内容，会在下面按坏行报错。
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("%s: %s line %d: %w", tool, path, line, err)
		}
		if err := rec.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %s line %d: %w", tool, path, line, err)
		}
		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%s: read %s: %w", tool, path, err)
	}
	return out, nil
}

// Validate 做「必需字段存在性 + 值域」校验（评审 I2 的落点），错误信息一律带字段路径。
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
// 该检查落在 `Evaluate`（`cmd/edgecompare/metrics.go:validateDomainsCovered`）；本层只保证
// 域分**非空**。
//
// **本层刻意不校验的东西**（spec §5.1 的记录构造要求，见 ValidateConstruction 等）：
//   - 因子 ID 是否**规范**（大小写/空白）：消费侧的归一化发生在装配期
//     （`edgefactor.NormalizeFactorID`），手写的或历史的数据集用小写 ID 仍能被正确消费，
//     读取层不得因此拒收（`cmd/edgecompare` 的 `TestActivationsOfNormalizesAndConverts`
//     正钉着这条既有行为）。规范 ID 是**生产者**的义务。
//   - `c_trigger > 0` 的链条目，其 `trigger_check` 是否以 `passed = false` 出现在 `checks[]`
//     里：legacy 无模型段路径保留 *identity 分支* 与级联写值，此时链上的 `trigger_check`
//     是"该因子**登记的**触发检查"，未必是真正失败的那个检查（例：identity 检查 `EF-002FA`
//     失败时链上写的是登记值 `EF-001`）。故这条交叉校验只对**插件路径**（V/G/C）成立，
//     由知道该记录由哪条路径产出的调用方执行（`CheckTriggerCrossReference`）。
//     **任何消费者都不得用 `trigger_check` 反推 `checks[]`**。
//   - `observed.effective_weights` 是否存在（既有夹具里没有它）。
func (r Record) Validate() error {
	if r.ScenarioID == "" {
		return fmt.Errorf("missing scenario_id")
	}
	if r.Observed.Threshold <= 0 {
		return fmt.Errorf("observed.threshold = %v must be > 0 — 缺失会被当成 0，任何非负分数都会判 acceptable，决策层退化为『全放行』", r.Observed.Threshold)
	}
	if len(r.Observed.DomainScores) == 0 {
		return fmt.Errorf("observed.domain_scores: missing or empty — 没有域分就无从重算总分")
	}
	for d := range r.Observed.DomainScores {
		if strings.TrimSpace(d) == "" {
			return fmt.Errorf("observed.domain_scores: contains an empty domain name")
		}
	}
	if !r.Observed.spcScoreSet {
		return fmt.Errorf("observed.spc_score: missing — 引擎的判定线需要它（总分 = round2(0.5·base + 30·E + 20·T)）；缺失会被当成 0，而 0 是引擎的『未设置』哨兵（按 1.0 计），总分被静默抬到最宽松的一档")
	}
	if r.Observed.SPCScore <= 0 || r.Observed.SPCScore > 1 {
		return fmt.Errorf("observed.spc_score = %v out of (0,1] — 它是引擎输出的 SPC 姿态分（p_score = max(minPScore, 1−总惩罚)），0 是引擎的『未设置』哨兵", r.Observed.SPCScore)
	}
	if !r.Observed.threatCoeffSet {
		return fmt.Errorf("observed.threat_coeff: missing — 引擎的判定线需要它（总分 = round2(0.5·base + 30·E + 20·T)）；缺失会被当成 0，而 0 是引擎的『未设置』哨兵（按 1.0 计），总分被静默抬到最宽松的一档")
	}
	if r.Observed.ThreatCoeff <= 0 {
		return fmt.Errorf("observed.threat_coeff = %v must be > 0（[threat] coefficient 的既有值域只有下界）— 0 是引擎的『未设置』哨兵", r.Observed.ThreatCoeff)
	}
	for i, c := range r.Observed.EdgeFactorChain {
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
		if _, err := ParseTS(c.TS); err != nil {
			return fmt.Errorf("observed.edge_factor_chain[%d].ts: %w", i, err)
		}
	}
	// 大小写折叠冲突：两个只差大小写（或前后空白）的因子 ID 会被消费侧的 `NormalizeFactorID`
	// **静默合并**成一个因子 —— 链上少一个惩罚项、V/G/C 的强度也随之变化，而报告照常打印。
	// 放在所有既有判据**之后**是刻意的：只报第一个问题的口径不变，既有输入的错误信息逐字不变。
	seen := make(map[string]int, len(r.Observed.EdgeFactorChain))
	for i, c := range r.Observed.EdgeFactorChain {
		key := edgefactor.NormalizeFactorID(c.Factor)
		if j, dup := seen[key]; dup {
			return fmt.Errorf("observed.edge_factor_chain[%d].factor = %q collides with observed.edge_factor_chain[%d].factor = %q after normalization (%q) — 消费侧会把它静默合并成一个因子，链上少一个惩罚项", i, c.Factor, j, r.Observed.EdgeFactorChain[j].Factor, key)
		}
		seen[key] = i
	}
	for i, c := range r.Observed.Checks {
		if _, err := ParseTS(c.TS); err != nil {
			return fmt.Errorf("observed.checks[%d].ts: %w", i, err)
		}
	}
	if !r.GroundTruth.compromisedSet {
		return fmt.Errorf("ground_truth.compromised: missing — 必须显式写出 true/false；缺失会被当成 false，该场景被静默标成『未攻陷』并直接扭曲漏判率/误阻断率")
	}
	return nil
}

// ValidateConstruction 是**生产者侧**的记录构造要求自检（spec §5.1）：在读取层契约之上，
// 追加那些"写错不会有任何读取层报错、只会让报告与论文证据失真"的判据。
//
// 当前只有一条：`factors` 与 `edge_factor_chain[].factor` 必须是**规范因子 ID**
// （`EF-SELINUX`，不是展示名 `selinux_disabled`、也不是小写 `ef-selinux`）。
// 为什么它不在读取层：消费侧的归一化发生在装配期（`edgefactor.NormalizeFactorID`），
// 手写/历史数据集用小写 ID 仍能被正确消费 —— 硬拒会让既有用例
// （`cmd/edgecompare` 的 `TestActivationsOfNormalizesAndConverts`）变红。写错代价是：
// 离线重算查不到 `Vectors` 而**静默**走"作用于全部域、强度 1"的 fallback，
// 实测 L 由 0.15 变成 0.3，直接改变 V/G/C 的惩罚强度。
func (r Record) ValidateConstruction() error {
	if err := r.Validate(); err != nil {
		return err
	}
	for i, id := range r.Factors {
		if canonical := edgefactor.NormalizeFactorID(id); canonical != id {
			return fmt.Errorf("factors[%d] = %q is not a canonical factor ID (规范形 %q) — 写展示名会让离线查表落空并静默回落到『全 1』向量，改变惩罚强度（spec §5.1 记录构造要求）", i, id, canonical)
		}
	}
	for i, c := range r.Observed.EdgeFactorChain {
		if canonical := edgefactor.NormalizeFactorID(c.Factor); canonical != c.Factor {
			return fmt.Errorf("observed.edge_factor_chain[%d].factor = %q is not a canonical factor ID (规范形 %q) — 写展示名会让离线查表落空并静默回落到『全 1』向量，改变惩罚强度（spec §5.1 记录构造要求）", i, c.Factor, canonical)
		}
	}
	return nil
}

// CheckTriggerCrossReference 是**只对插件路径（V/G/C）成立**的记录构造要求（spec §5.1）：
// 每个 `c_trigger > 0` 的链条目，其 `trigger_check` 必须以 `passed = false` 出现在 `checks[]` 里。
//
// 为什么它不是读取层规则（Task 1 实现者实测）：legacy 无模型段路径保留 *identity 分支*
// （检查 ID 恰等于因子 ID 时直接激活该因子）与级联写值，此时链上的 `trigger_check` 是
// "该因子**登记的**触发检查"，**未必**是真正失败的那个检查（例：identity 检查 `EF-002FA`
// 失败时，链上写的是登记值 `EF-001`）。硬把它做成读取层规则会拒掉真实数据集。
// 故只有**确知该记录由插件路径产出**的调用方（采集器，Task 3）才可调用它。
//
// `c_trigger = 0` 的条目豁免：那是"未被自身触发检查匹配到失败检查"的既有形态，
// 纯级联因子（`EF-3FA → EF-002FA`）就靠它，这类因子的激活原因**不是**某个检查失败。
//
// **任何消费者都不得用 `trigger_check` 反推 `checks[]`**：`checks[]` 的真实要求是
// "落盘引擎的**全部失败检查**"（采集器的额外约定，读取层不校验），那也是本条交叉校验
// 能成立的前提 —— 本函数只是把这个前提**检出来**，不替它兜底。
func (r Record) CheckTriggerCrossReference() error {
	failed := make(map[string]bool, len(r.Observed.Checks))
	for _, ck := range r.Observed.Checks {
		if !ck.Passed {
			failed[ck.ID] = true
		}
	}
	for i, c := range r.Observed.EdgeFactorChain {
		if c.CTrigger <= 0 {
			continue
		}
		if c.TriggerCheck == "" {
			return fmt.Errorf("observed.edge_factor_chain[%d].trigger_check: missing — c_trigger = %v > 0（%s），但没写触发检查，因子被激活的原因不可追溯", i, c.CTrigger, c.Factor)
		}
		if !failed[c.TriggerCheck] {
			return fmt.Errorf("observed.edge_factor_chain[%d].trigger_check = %q 未以 passed=false 出现在 checks[] 里（c_trigger = %v > 0，%s）— 因子被激活的原因不可追溯；仅插件路径（V/G/C）适用，legacy 的 identity/级联路径请勿调用本检查", i, c.TriggerCheck, c.CTrigger, c.Factor)
		}
	}
	return nil
}

// CheckEffectiveWeightsRecorded 是**采集器**的生产者自检：记录必须写出引擎**实际生效**的
// 逐域权重（`observed.effective_weights`，键集 = "参与聚合的域"）。
//
// 读取层不要求它（历史数据集与既有夹具里没有这个字段），但**生产者必须写**：没有它，
// 离线重算就只能靠 `-weights` 猜，而配置权重 ≠ 生效权重（`DynamicScoringEngine` 会给 0 权重
// 域填默认值并 `Normalize(100)`），round-trip 门禁因此没有定义（spec §5.1 前提 2）。
// 空 map 等于没写：键集即"参与的域"，为空说明装配期没拿到权重表。
func (r Record) CheckEffectiveWeightsRecorded() error {
	if len(r.Observed.EffectiveWeights) == 0 {
		return fmt.Errorf("observed.effective_weights: missing or empty — 记录必须写出引擎实际生效的逐域权重（键集 = 参与聚合的域），否则离线复算拿不到权重口径（spec §5.1 前提 2）")
	}
	return nil
}

// MarshalRecord 把一条记录序列化成 JSONL 的一行（含结尾 `\n`，无 BOM）。
//
// 写之前先做**生产者自检**（`ValidateConstruction`）：一条能被读取层接受、却会让离线重算
// 静默改分的记录（例如非规范因子 ID）绝不落盘 —— 这个项目已经因为"两边各写各的"被咬过一次，
// 写出口宁可在源头拒绝。
//
// **路径相关的构造要求不在这里**：`CheckTriggerCrossReference`（仅插件路径）与
// `CheckEffectiveWeightsRecorded`（采集器义务）由采集器在调用本函数前自行执行 ——
// 它们是否适用取决于该记录由哪条评分路径产出，写出口无从判断。
func MarshalRecord(r Record) ([]byte, error) {
	if err := r.ValidateConstruction(); err != nil {
		return nil, fmt.Errorf("edgeexp: refuse to marshal an unconstructible record: %w", err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("edgeexp: marshal record: %w", err)
	}
	return append(raw, '\n'), nil
}

// ParseTS 解析 RFC3339 时间戳。空串合法（= 该字段缺席），非空但解析不了即坏值。
func ParseTS(v string) (time.Time, error) {
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
