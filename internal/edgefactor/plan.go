package edgefactor

import "strings"

// 本文件是**裁剪口径与因子 ID 归一化的唯一实现**（主控 I2 裁定）。
//
// 为什么这三个纯函数必须住在无 build tag 的本包里：
//
// 在线装配期（internal/engine/ssam，带 tag engine）与离线重算（cmd/edgecompare，带 tag edgeexp）
// 各自都 import 本包，却都**不能** import 对方（tag 不同）。此前两侧各抄了一份等价实现
// （`newSynthesizePlan` 的内联裁剪 + `pruneToDomains` + `NormalizeFactorID` 对
// `offlinePlan` 的内联裁剪 + `pruneToDomains` + `normalizeFactorID`，`fit.go` 的
// `fitDomains` 是第三份），于是"离线重算 ↔ 在线评分逐位一致"这条主门禁随时可能被一处
// 单边改动悄悄破坏 —— 而两侧都不会报错，只会算出不同的分数。
//
// 本包同时是两侧共同依赖的合成层（`Synthesize`），因此它就是这批口径唯一自然的归属地。

// NormalizeFactorID 把因子 ID 归一为规范拼写（引擎的 FactorID 约定：全大写）。
//
// 消费侧口径（产出侧不改 ID，只在查表前归一）：
//   - `internal/config` 的 `parseSections` 会把配置键小写化，故 `[edge_factors.custom]`
//     的条目以**小写 ID** 产出；
//   - 合成层的 Vectors / Factors / Coupling 三处查表都以规范大写键进行，不归一会让查表落空
//     并**静默**回落到"作用于全部域、强度 1"的默认向量（实测 L 由 0.15 变成 0.3）。
//
// `internal/config` 的 `canonicalFactorID` 保持独立（该包刻意不依赖合成层，见其注释中的
// 审计 F6 裁定），它是**解析层**的同义实现；本函数是**引擎与离线工具**两侧的唯一实现。
func NormalizeFactorID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

// RequestedDomains 返回本次合成请求的域集合 = `DefaultDomains ∩ p.Lambda`。
//
// 为什么是交集而不是"全部默认域"：内仓 `Validate`/`Synthesize` 以**传入的域列表**为准，
// 配置里出现请求域之外的 λ 或向量键会被直接拒绝，而配置层允许只声明部分 λ。取交集意味着
// **未配置 λ 的域不做域级修正**（而不是整次失败后静默退回默认乘性）。
//
// 顺序固定为 `DefaultDomains` 的顺序：合成层按该顺序逐域累加 L/P，
// 顺序若随 map 迭代序漂移，"逐位一致"就只是偶然。
//
// 返回空切片表示一个默认域都没覆盖到 —— 调用方必须据此 fail-fast（能装配出来的东西必须
// 真的能算），本函数不替调用方兜底成"全部默认域"。
func RequestedDomains(p Params) []string {
	all := DefaultDomains()
	out := make([]string, 0, len(all))
	for _, d := range all {
		if _, ok := p.Lambda[d]; ok {
			out = append(out, d)
		}
	}
	return out
}

// PruneToDomains 返回 p 在给定域集合上的**一致裁剪副本**：新 map，绝不改动调用方的 map
// （Params 的 Lambda/Vectors 与 config 段共享同一批 map）。
//
// 只裁 λ 与向量分量（唯一与域相关的两个字段），模型/下限/耦合/窗口/因子权重原样保留。
// **不生成**未声明的向量：它们由 `Synthesize` 走文档化的"全 1"fallback；在这里补一个
// 全 1 向量会静默改变强度口径（fallback 不参与 `Σ_d v_i[d] ≤ 1` 约束）。
//
// 裁剪安全性（调用方的前提）：请求域已由 `Validate`（在完整参数上）保证是默认域的子集，
// 取子集后 `Σ_d v_i[d] ≤ 1` 仍成立，且已声明的向量裁剪后仍覆盖请求域。
func PruneToDomains(p Params, domains []string) Params {
	keep := make(map[string]bool, len(domains))
	for _, d := range domains {
		keep[d] = true
	}
	pruned := p
	pruned.Lambda = make(map[string]float64, len(domains))
	for d := range keep {
		if l, ok := p.Lambda[d]; ok {
			pruned.Lambda[d] = l
		}
	}
	pruned.Vectors = make(map[string]map[string]float64, len(p.Vectors))
	for id, vec := range p.Vectors {
		trimmed := make(map[string]float64, len(domains))
		for d := range keep {
			if v, ok := vec[d]; ok {
				trimmed[d] = v
			}
		}
		pruned.Vectors[id] = trimmed
	}
	return pruned
}
