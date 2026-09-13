//go:build expr && engine && checks

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
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
}

// harnessInjection 是一次注入观测：哪个检查、什么时候。
type harnessInjection struct {
	Check string `json:"check"`
	At    string `json:"at"`
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

	PlaybookHash string               `json:"playbook_hash"`
	Injections   map[string]time.Time `json:"injections"`
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

	return groundTruth{
		Compromised:       *rep.Compromised,
		TimeToCompromiseS: *rep.TimeToCompromiseS,
		TTPsAchieved:      *rep.TTPsAchieved,
		NodesAffected:     *rep.NodesAffected,
		BlockEffective:    *rep.BlockEffective,
		Basis:             basis,
		PlaybookHash:      rep.PlaybookHash,
		Injections:        injections,
	}, nil
}

// recordGroundTruth 把客观结果转成契约类型。
//
// **必须**经一次 JSON 编解码：`edgeexp.GroundTruth` 的 `compromised` 存在性标记是非导出字段、
// 只由 `UnmarshalJSON` 设置 —— 直接写结构体字面量，无论字段写得多全，`Validate` 都会以
// 「ground_truth.compromised: missing」拒掉**每一条**记录。而"harness 根本没写这个字段"
// 这件事已在 `loadGroundTruth` 处以指针解码 + 明确错误拦住了，故这里不会把缺失伪装成在场。
func (g groundTruth) recordGroundTruth() (edgeexp.GroundTruth, error) {
	payload := struct {
		Compromised       bool    `json:"compromised"`
		TimeToCompromiseS float64 `json:"time_to_compromise_s"`
		TTPsAchieved      int     `json:"ttps_achieved"`
		NodesAffected     int     `json:"nodes_affected"`
		BlockEffective    bool    `json:"block_effective"`
		Basis             string  `json:"basis,omitempty"`
	}{
		Compromised:       g.Compromised,
		TimeToCompromiseS: g.TimeToCompromiseS,
		TTPsAchieved:      g.TTPsAchieved,
		NodesAffected:     g.NodesAffected,
		BlockEffective:    g.BlockEffective,
		Basis:             strings.TrimSpace(g.Basis),
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
