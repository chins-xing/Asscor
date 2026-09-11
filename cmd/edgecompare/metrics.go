//go:build edgeexp

package main

import (
	"fmt"
	"math"
	"sort"

	"github.com/chins-xing/asscor/internal/edgefactor"
)

// 重算层 + 三层指标（spec §2.1 / §5.2 第 2–3 步）。
//
// 对比范式是「离线重算为主」：真实攻防实验只记录**原始观测与客观结果**，四候选
// （legacy / vector / graph / chain）在同一份真实数据上用 `internal/edgefactor` 的
// **同一份 Synthesize** 重算分数与决策。评分本身（含总分公式）在 `score.go`：
// 离线分数 == `ssam.SSAMV20Formula` 的总分（主控裁定 C1），本文件只负责把 JSONL 的观测
// 装进合成层、按在线口径裁剪域、再按 spec §2.1 的三层指标汇总。
//
// 三层指标（定义处见 Evaluate / severityOf / auc）：
//
//	决策层（主判据）：DecisionAgreement / FalseNegativeRate / FalsePositiveRate
//	排序层（辅助）  ：Spearman / Kendall（模型分数 vs 客观严重度）
//	数值层（辅助）  ：AUC（以 100−score 为危险度，compromised 为正类）
//
// **判定口径（C1 报告头要求，必须与在线一致）**：离线分数 = 引擎总分（同一公式
// `SSAMV20Formula`），阈值 = 引擎决策线（`Acceptable = Total >= threshold`）。

type Metrics struct {
	DecisionAgreement float64 `json:"decision_agreement"`
	FalseNegativeRate float64 `json:"false_negative_rate"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
	Spearman          float64 `json:"spearman"`
	Kendall           float64 `json:"kendall"`
	AUC               float64 `json:"auc"`
	N                 int     `json:"n"`
}

// activationsOf 把 JSONL 的因子链换算成合成层的输入项（Task 10 的拟合也用它）。
//
// 这里就是 mandate 口径 2 的落点：**复用在线装配层 `ActivationFromResult` 的换算**——
// 对记录里已经过 ssam-lib 策略层衰减一次的 `effective_factor` 再衰减一次
// （`EffectiveFactor(value, c_trigger)`），合计 `1−(1−f)·c²`。spec §10.2 把这条口径记为
// 「可信度被衰减两次」的已知问题，并要求 Task 8–10 的离线重算**复用**它、在标定报告中标注，
// 而不是在此处修正（修正会改变评分，属独立决策）。
//
// **这条换算只属于 V/G/C 的合成层**：`score.go:activationsFromResults` 用它把"已衰减一次"
// 的观测值再衰减一次（与在线 `ssam.activationsFromResults` 同口径）。legacy 走的是另一条路
// —— 引擎的默认策略直接乘 `EdgeFactorResult.Factor`（= 记录里的 `effective_factor`，
// 单次衰减），故 legacy 的重算**不得**经过本函数（C1 裁定后由 `engineEdgeFactors` 承担）。
//
// 本函数同时供拟合器（fit.go 的设计矩阵）使用：拟合的列口径是
// `a_i = (1−eff_i)·Σ_d v_i[d]`，其中 eff_i 就是装配层换算后的值。
//
// 因子 ID 一并做**消费侧**归一（唯一实现：`internal/edgefactor.NormalizeFactorID`）：
// 合成层的 Vectors / Factors / Coupling 三处查表都以规范大写键进行，不归一会查表落空并
// 静默回落到"全强度"默认向量。
func activationsOf(rec Record) []edgefactor.FactorActivation {
	out := make([]edgefactor.FactorActivation, 0, len(rec.Observed.EdgeFactorChain))
	for _, c := range rec.Observed.EdgeFactorChain {
		ts, _ := parseTS(c.TS) // 坏值已在 LoadRecords 处按行拒绝
		out = append(out, edgefactor.FactorActivation{
			FactorID:        edgefactor.NormalizeFactorID(c.Factor),
			TriggerCheck:    c.TriggerCheck,
			CTrigger:        c.CTrigger,
			EffectiveFactor: edgefactor.EffectiveFactor(c.EffectiveFactor, c.CTrigger),
			TS:              ts,
		})
	}
	return out
}

// modelActivations 在 activationsOf 之上丢弃**候选模型未建模**的因子。
//
// 口径与在线消费者 `ssam.activationsFromResults` 一致（Task 7 评审的接线要求）：归一后的 ID
// 必须能在 Params.Factors 里查到，查不到说明该因子不在这个候选模型的因子集合里（例如只作
// 级联入口、从不 Active 的 EF-3FA，或配置改坏后的孤儿 ID）。放它进去会让 Params.Vectors
// 查表落空并**静默**按"作用于全部域、强度 1"计入惩罚——一个未建模的因子凭空产生比配置
// 更强的惩罚。
//
// 代价（须在报告中如实标注）：候选模型漏配一个真实激活的因子时，离线不会报错，而是"该因子
// 不产生惩罚"。这不是静默失效的隐蔽路径——它的后果直接体现在决策层指标上（漏判率偏高），
// 也正是四个候选要比出来的东西。
func modelActivations(p edgefactor.Params, rec Record) []edgefactor.FactorActivation {
	acts := activationsOf(rec)
	out := make([]edgefactor.FactorActivation, 0, len(acts))
	for _, a := range acts {
		if _, known := p.Factors[a.FactorID]; !known {
			continue
		}
		out = append(out, a)
	}
	return out
}

// orderedDomains 返回权重键的确定顺序：默认域在前（按 DefaultDomains 的顺序），其余键按字典序
// 追加。只返回**实际出现在 weights 里**的键，故不改变"哪些域参与聚合"的语义。
//
// 确定性契约（本方向的核心门禁「离线重算 ↔ 在线评分逐位一致」依赖它）：**同一输入必须给出
// 逐位相同的结果**。Go 的 map 迭代序是随机的，直接 `range` 会让域分切片在末位抖动 1 ulp ——
// 门禁于是"偶然绿、偶然红"，这不是精度问题而是**不可复现**问题（同一份数据两次跑出不同判定
// 时，报告里的数字无法归因）。
//
// 顺序的消费者是 `score.go:engineDomainScores`：内仓 `SSAMV20Formula` 按域分切片顺序累加
// `sum += ds.Score * w`（加法交换律保证数学语义不变，定序只把浮点舍入路径钉死）。
func orderedDomains(weights map[string]float64) []string {
	out := make([]string, 0, len(weights))
	known := make(map[string]bool, len(weights))
	for _, d := range edgefactor.DefaultDomains() {
		if _, ok := weights[d]; ok {
			out = append(out, d)
			known[d] = true
		}
	}
	rest := make([]string, 0, len(weights))
	for d := range weights {
		if !known[d] {
			rest = append(rest, d)
		}
	}
	// 先收集再排序：map 迭代序只影响收集顺序，不影响排序后的结果。
	sort.Strings(rest)
	return append(out, rest...)
}

// validateDomainsCovered 校验记录**覆盖了本次评估用到的每个域**（评审 I2 的另一半）。
//
// 为什么这条检查在 Evaluate 而不在读取层：读取层看不到"评估时用了哪些域"——域权重是
// `Evaluate` 的入参（读取层只能保证 `domain_scores` 非空，见 load.go:validateRecord）。
// 缺域的危险是**静默压低**：引擎公式对缺失域取到 0，却仍把它那份额度计入分母（
// `engineDomainScores` 会为该域装入一个 0 分），于是总分被无理由拉低、`acceptable` 判定随之
// 翻转，而报告里看不出任何异常。
// 记录里的域分是评估的输入证据，缺一项就意味着这份记录不能配这张权重表 —— 直接拒绝。
func validateDomainsCovered(rec Record, weights map[string]float64) error {
	for _, d := range orderedDomains(weights) {
		if weights[d] <= 0 {
			continue
		}
		if _, ok := rec.Observed.DomainScores[d]; !ok {
			return fmt.Errorf(
				"edgecompare: scenario %s: domain %q has weight %v but no observed domain score — 缺失域会被当成 0 参与聚合（仍占一份权重），静默压低总分并扭曲决策层指标",
				rec.ScenarioID, d, weights[d])
		}
	}
	return nil
}

// Evaluate 在同一份真实数据上重算并计算三层指标（spec §2.1）。
//
// 决策层对齐规则（模型判定 ↔ 客观结果）：
//   - 模型判定：`acceptable = 重算分数 ≥ 记录阈值`。阈值取自观测记录，四个候选共用同一根
//     判定线 —— 比较的是"同一份真实数据 + 同一判定线下谁的决定更接近现实"；
//   - 客观结果：`compromised` 来自 `ground_truth`（真实攻防实验的客观结论，与任何模型无关）；
//   - 一致：`acceptable == !compromised`（判"可接受" ⇔ 客观未被攻陷）；
//   - 漏判 FN：`acceptable && compromised`（模型放行、实际被攻陷）—— 主判据之一；
//   - 误阻断 FP：`!acceptable && !compromised`（模型阻断、实际没被攻陷）—— 主判据之二；
//   - 两个率按 brief 给定定义取 `计数 / N`（占样本比，不是条件率）。四个候选共用同一个 N，
//     故占样本比在候选之间可比。
//
// 排序层用「模型分数 vs 客观严重度」，数值层用「危险度 (100−score) vs compromised」，
// 两层都只是辅助证据，不参与选优（选优在 Task 9 的 Compare）。
func Evaluate(records []Record, p edgefactor.Params, weights map[string]float64) (Metrics, error) {
	var m Metrics
	if len(records) == 0 {
		return m, nil
	}
	m.N = len(records)
	scores := make([]float64, 0, len(records))
	severity := make([]float64, 0, len(records))
	labels := make([]bool, 0, len(records))
	agree, fn, fp := 0, 0, 0

	for _, rec := range records {
		// 先校验域覆盖（评审 I2）：缺域会被当作 0 聚合、静默扭曲主判据，必须在算分之前拒绝。
		if err := validateDomainsCovered(rec, weights); err != nil {
			return Metrics{}, err
		}
		score, err := OfflineScoreWithWeights(p, rec, weights)
		if err != nil {
			// 返回零值 Metrics（而不是半填的 m）：错误必须让调用方无法把结果当成有效报告。
			return Metrics{}, fmt.Errorf("edgecompare: scenario %s: %w", rec.ScenarioID, err)
		}
		acceptable := score >= rec.Observed.Threshold
		compromised := rec.GroundTruth.Compromised
		scores = append(scores, score)
		severity = append(severity, severityOf(rec.GroundTruth))
		labels = append(labels, compromised)
		if acceptable == !compromised {
			agree++
		}
		if acceptable && compromised {
			fn++
		}
		if !acceptable && !compromised {
			fp++
		}
	}
	m.DecisionAgreement = float64(agree) / float64(m.N)
	m.FalseNegativeRate = float64(fn) / float64(m.N)
	m.FalsePositiveRate = float64(fp) / float64(m.N)
	m.Spearman = spearman(scores, severity)
	m.Kendall = kendall(scores, severity)
	m.AUC = auc(scores, labels)
	return m, nil
}

// severityOf 把客观受损程度折成单调严重度：攻陷越快、TTP 越多、节点越多越严重。
// 未被攻陷 ⇒ 0（与"分数越高越安全"的模型分数应呈负相关，故 Spearman/Kendall 期望为负）。
func severityOf(gt GroundTruth) float64 {
	if !gt.Compromised {
		return 0
	}
	return 1000.0/(gt.TimeToCompromiseS+1) + float64(gt.TTPsAchieved)*10 + float64(gt.NodesAffected)
}

// ranks 返回平均秩（并列取平均），用于 Spearman。
func ranks(values []float64) []float64 {
	idx := make([]int, len(values))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return values[idx[a]] < values[idx[b]] })
	out := make([]float64, len(values))
	for i := 0; i < len(idx); {
		j := i
		for j+1 < len(idx) && values[idx[j+1]] == values[idx[i]] {
			j++
		}
		avg := float64(i+j)/2 + 1
		for k := i; k <= j; k++ {
			out[idx[k]] = avg
		}
		i = j + 1
	}
	return out
}

func spearman(a, b []float64) float64 {
	if len(a) < 2 {
		return 0
	}
	ra, rb := ranks(a), ranks(b)
	return pearson(ra, rb)
}

func pearson(a, b []float64) float64 {
	n := float64(len(a))
	var sa, sb, saa, sbb, sab float64
	for i := range a {
		sa += a[i]
		sb += b[i]
		saa += a[i] * a[i]
		sbb += b[i] * b[i]
		sab += a[i] * b[i]
	}
	num := n*sab - sa*sb
	den := math.Sqrt((n*saa - sa*sa) * (n*sbb - sb*sb))
	if den == 0 {
		return 0
	}
	return num / den
}

func kendall(a, b []float64) float64 {
	if len(a) < 2 {
		return 0
	}
	concordant, discordant := 0, 0
	for i := 0; i < len(a); i++ {
		for j := i + 1; j < len(a); j++ {
			da, db := a[i]-a[j], b[i]-b[j]
			switch {
			case da*db > 0:
				concordant++
			case da*db < 0:
				discordant++
			}
		}
	}
	total := concordant + discordant
	if total == 0 {
		return 0
	}
	return float64(concordant-discordant) / float64(total)
}

// auc 以 compromised 为正类、以"越危险分越低"的模型分数为排序依据。
// 使用 (100 − score) 作为危险度；未攻陷样本为负类。
//
// 100 是评分量纲上的上界（域分/总分按百分制）：这里的位移只影响数值，不影响顺序，
// 故 AUC 与位移量无关。
func auc(scores []float64, labels []bool) float64 {
	var pos, neg []float64
	for i, l := range labels {
		danger := 100 - scores[i]
		if l {
			pos = append(pos, danger)
		} else {
			neg = append(neg, danger)
		}
	}
	if len(pos) == 0 || len(neg) == 0 {
		return 0
	}
	wins := 0.0
	for _, p := range pos {
		for _, n := range neg {
			switch {
			case p > n:
				wins++
			case p == n:
				wins += 0.5
			}
		}
	}
	return wins / float64(len(pos)*len(neg))
}
