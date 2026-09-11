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
// 本层只做「结构 + 可解析性」校验，不做语义推断：坏行必须以**行号**fail-fast，
// 绝不静默跳过（静默跳过会让报告里的样本量与实验规模对不上，而无人察觉）。
// 语义校验（λ 覆盖、向量覆盖、因子有效性、时间戳存在性）分别由 edgefactor.Params.Validate
// 与 edgefactor.Synthesize 在重算时负责 —— 与在线同一份实现。

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
	Checks          []CheckObs         `json:"checks"`
	EdgeFactorChain []ChainObs         `json:"edge_factor_chain"`
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
type ChainObs struct {
	Factor          string  `json:"factor"`
	TriggerCheck    string  `json:"trigger_check"`
	CTrigger        float64 `json:"c_trigger"`
	EffectiveFactor float64 `json:"effective_factor"`
	TS              string  `json:"ts"`
}

type GroundTruth struct {
	Compromised       bool    `json:"compromised"`
	TimeToCompromiseS float64 `json:"time_to_compromise_s"`
	TTPsAchieved      int     `json:"ttps_achieved"`
	NodesAffected     int     `json:"nodes_affected"`
	BlockEffective    bool    `json:"block_effective"`
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

// validateRecord 做「结构性可解析」校验：字段缺失/时间戳写坏都必须当场报错。
//
// 为什么时间戳要在读取层解析一次（而不是留给合成层）：chain 模型对零值时间戳 fail-fast，
// 若坏字符串一路带到那里，报出来的是"缺时间戳"——分不清是**数据写坏了**还是**记录本就没有**
// 时间戳，且丢失行号。在这里解析一次，两类问题都能被定位到具体行与字段。
func validateRecord(rec Record) error {
	if rec.ScenarioID == "" {
		return fmt.Errorf("missing scenario_id")
	}
	for i, c := range rec.Observed.EdgeFactorChain {
		if strings.TrimSpace(c.Factor) == "" {
			return fmt.Errorf("observed.edge_factor_chain[%d]: missing factor", i)
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
