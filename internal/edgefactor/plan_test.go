package edgefactor

import (
	"math"
	"reflect"
	"testing"
)

// ============================================================================
// 单一实现（I2）：裁剪口径与因子 ID 归一
// ============================================================================
//
// 这三个纯函数此前在四处各有一份抄写：
//
//	internal/engine/ssam/edgefactor.go  —— newSynthesizePlan 的内联裁剪 + pruneToDomains + NormalizeFactorID
//	cmd/edgecompare/metrics.go          —— offlinePlan 的内联裁剪 + pruneToDomains + normalizeFactorID
//	cmd/edgecompare/fit.go              —— fitDomains 的内联裁剪（逐条复刻）
//	internal/config/edgefactor.go       —— canonicalFactorID
//
// 抄写的代价不是"代码重复"这么轻：任一处漂移都会让**离线重算与在线评分算出不同的分数**
// （本方向的主门禁正是"逐位一致"），而接口上没有任何东西会报错。故把纯函数下沉到本包
// （无 build tag，engine 与 cmd/edgecompare 都能 import），让两侧只调用唯一实现。

func TestNormalizeFactorIDIsTrimUpper(t *testing.T) {
	cases := map[string]string{
		"ef-selinux":     "EF-SELINUX",
		"  EF-SELINUX  ": "EF-SELINUX",
		"\tef-3fa\n":     "EF-3FA",
		"EF-SELINUX":     "EF-SELINUX",
		"":               "",
		"   ":            "",
	}
	for in, want := range cases {
		if got := NormalizeFactorID(in); got != want {
			t.Errorf("NormalizeFactorID(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRequestedDomainsKeepsDefaultOrderIntersectLambda：请求域 = DefaultDomains ∩ λ，
// 顺序取 DefaultDomains 的顺序（不是 map 迭代序，也不是 λ 的书写顺序）——
// 顺序决定合成层逐域累加的顺序，随机化会让"逐位一致"变成偶然。
func TestRequestedDomainsKeepsDefaultOrderIntersectLambda(t *testing.T) {
	p := Params{
		Model:  ModelVector,
		PFloor: 0.5,
		Lambda: map[string]float64{
			"kernel_security": 2.0,
			"attack_surface":  1.0,
			"not_a_domain":    3.0, // 非默认域：不在 DefaultDomains 里，必须被排除
		},
	}
	want := []string{"attack_surface", "kernel_security"}
	for i := 0; i < 50; i++ {
		if got := RequestedDomains(p); !reflect.DeepEqual(got, want) {
			t.Fatalf("第 %d 次 RequestedDomains = %v, want %v（顺序必须钉死在 DefaultDomains 上）", i+1, got, want)
		}
	}
	// 一个 λ 都没覆盖到默认域 ⇒ 空切片（调用方据此 fail-fast，绝不返回"全部默认域"）。
	if got := RequestedDomains(Params{Model: ModelVector, Lambda: map[string]float64{"zzz": 1}}); len(got) != 0 {
		t.Errorf("λ 未覆盖任何默认域时应返回空切片，实得 %v", got)
	}
	if got := RequestedDomains(Params{Model: ModelLegacy}); len(got) != 0 {
		t.Errorf("无 λ 时返回空切片，实得 %v", got)
	}
	// 全部 5 个默认域都声明 λ ⇒ 结果就是 DefaultDomains 本身（逐位相同）。
	all := Params{Model: ModelVector, Lambda: map[string]float64{}}
	for _, d := range DefaultDomains() {
		all.Lambda[d] = 1
	}
	if got := RequestedDomains(all); !reflect.DeepEqual(got, DefaultDomains()) {
		t.Errorf("RequestedDomains(全默认域) = %v, want %v", got, DefaultDomains())
	}
}

// TestPruneToDomainsTrimsAndNeverMutates：裁剪副本必须
//   - 只保留给定域上的 λ 与向量分量；
//   - **不生成**未声明的向量（它们由 Synthesize 走文档化的"全 1"fallback）；
//   - 绝不改动调用方的 map（Params 与配置段共享同一批 map）。
func TestPruneToDomainsTrimsAndNeverMutates(t *testing.T) {
	p := Params{
		Model:  ModelGraph,
		PFloor: 0.5,
		Lambda: map[string]float64{"attack_surface": 1.0, "operation_trust": 2.0, "kernel_security": 3.0},
		Vectors: map[string]map[string]float64{
			"A": {"attack_surface": 0.4, "operation_trust": 0.6, "kernel_security": 0.1},
		},
		Coupling: map[string]map[string]float64{"A": {"B": 0.5}},
		Factors:  map[string]float64{"A": 0.8, "B": 0.9},
	}
	domains := []string{"attack_surface", "operation_trust"}

	got := PruneToDomains(p, domains)
	if !reflect.DeepEqual(got.Lambda, map[string]float64{"attack_surface": 1.0, "operation_trust": 2.0}) {
		t.Errorf("Lambda = %v", got.Lambda)
	}
	if !reflect.DeepEqual(got.Vectors["A"], map[string]float64{"attack_surface": 0.4, "operation_trust": 0.6}) {
		t.Errorf("Vectors[A] = %v", got.Vectors["A"])
	}
	// 耦合/因子/模型/下限这些与域无关的字段原样保留（裁剪只动 λ 与向量）。
	if !reflect.DeepEqual(got.Coupling, p.Coupling) || !reflect.DeepEqual(got.Factors, p.Factors) ||
		got.Model != p.Model || got.PFloor != p.PFloor {
		t.Errorf("与域无关的字段被改动了：%+v", got)
	}
	// 调用方的 map 必须原封不动（共享 map 的原地裁剪会污染配置段与指纹）。
	if !reflect.DeepEqual(p.Lambda, map[string]float64{"attack_surface": 1.0, "operation_trust": 2.0, "kernel_security": 3.0}) {
		t.Errorf("调用方的 Lambda 被就地改动了：%v", p.Lambda)
	}
	if !reflect.DeepEqual(p.Vectors["A"], map[string]float64{"attack_surface": 0.4, "operation_trust": 0.6, "kernel_security": 0.1}) {
		t.Errorf("调用方的 Vectors[A] 被就地改动了：%v", p.Vectors["A"])
	}

	// 裁剪后必须能通过"该域集合上"的 Validate（在线的可执行性前提）。
	if err := got.Validate(domains); err != nil {
		t.Errorf("裁剪后的参数应能在裁剪域上通过 Validate：%v", err)
	}

	// 未声明的向量不得被生成：裁剪一个没有向量的 Params，Vectors 仍是空（非 nil 也必须是空）。
	noVec := Params{Model: ModelVector, PFloor: 0.5, Lambda: map[string]float64{"attack_surface": 1}}
	if got := PruneToDomains(noVec, []string{"attack_surface"}); len(got.Vectors) != 0 {
		t.Errorf("未声明的向量不得在裁剪时凭空生成：%v", got.Vectors)
	}
	// 空域集合 ⇒ λ 与每个向量的分量都为空（调用方在此之前已经 fail-fast）。
	if got := PruneToDomains(p, nil); len(got.Lambda) != 0 || len(got.Vectors["A"]) != 0 {
		t.Errorf("空域集合应裁成空表：%v / %v", got.Lambda, got.Vectors["A"])
	}
}

// TestPruneToDomainsIsTheOnlineAndOfflineContract 钉住"同一份实现"的可观测后果：
// 裁剪后的参数在裁剪域上合成出来的 P_d，与不裁剪（只在域列表上取子集）时逐位相同 ——
// 这正是"离线重算 == 在线评分"能成立的前提（裁剪只是把多余的键拿掉，不改变任何被消费的值）。
func TestPruneToDomainsIsTheOnlineAndOfflineContract(t *testing.T) {
	p := Params{
		Model:   ModelVector,
		PFloor:  0.4,
		Lambda:  map[string]float64{"attack_surface": 2.0, "operation_trust": 1.0},
		Vectors: map[string]map[string]float64{"A": {"attack_surface": 0.5, "operation_trust": 0.5}},
		Factors: map[string]float64{"A": 0.75},
	}
	domains := RequestedDomains(p)
	in := Input{
		DomainScores: map[string]float64{"attack_surface": 80, "operation_trust": 60},
		Factors:      []FactorActivation{{FactorID: "A", CTrigger: 1, EffectiveFactor: 0.6}},
	}
	pruned, err := Synthesize(PruneToDomains(p, domains), domains, in)
	if err != nil {
		t.Fatalf("Synthesize(pruned): %v", err)
	}
	// 不裁剪调用会被拒（λ 覆盖的是默认域的子集、向量不覆盖其余默认域），这正说明裁剪不可省。
	if _, err := Synthesize(p, DefaultDomains(), in); err == nil {
		t.Fatal("未裁剪的完整默认域调用本应被拒")
	}
	// 逐位复核 P_d：P = p_floor + (1−p_floor)·exp(−λ_d·L_d)，L_d = (1−0.6)·0.5 = 0.2。
	for _, tc := range []struct {
		domain string
		lambda float64
	}{{"attack_surface", 2.0}, {"operation_trust", 1.0}} {
		want := 0.4 + 0.6*math.Exp(-tc.lambda*0.2)
		if got := pruned.P[tc.domain]; got != want {
			t.Errorf("P[%s] = %v, want %v", tc.domain, got, want)
		}
	}
}
