//go:build engine

package ssam

import (
	"os"
	"testing"

	"github.com/chins-xing/asscor/internal/config"
	ssam "github.com/chins-xing/ssam"
)

// ============================================================================
// Task 18：同名双条目（内置大写 + custom 小写）在合成层的折叠钉子（在线侧）
// ============================================================================
//
// **真机事实**（详见 task-18 报告 §1）：`configs/edgeexp/*.ini` 的 `[edge_factors.custom]`
// **刻意**复制了内置六因子的同名条目（设计文档 §5.4.3 明写不得删 —— 门禁⓪ 要观测的正是
// 这个现象）。解析层把配置键**小写化**，而 `ssam-lib` 的 `ApplyEdgeFactorsToChecksPolicy`
// 用 **`efMap[f.ID]`（原始大小写）** 建键 ⇒ 同一个逻辑因子产出**两条** `EdgeFactorResult`
// （`EF-APPARMOR` 与 `ef-apparmor`），并因为 `sort.Slice(by ID)` 的 ASCII 序
// （大写 0x45 < 小写 0x65）在输出里呈现为**两块各自的字典序**。`observeEdgeFactorChain`
// 随后 `NormalizeFactorID`，两条在链上长得一模一样。
//
// **为什么合成层必须折叠**：`edgefactor.Params` 的参数空间是**因子级**的 ——
// `Factors`（`factorWeights` 按归一 ID 建 map）、`Vectors[id]`、`Coupling[i][j]` 全部按因子
// ID 建键。把「条目级」观测喂进「因子级」模型 ⇒ 主效应按条目累加、耦合项按**条目对**累加。
func TestActivationsFromResultsCollapsesSameFactorEntries(t *testing.T) {
	cfg := task18BaselineConfig(t)
	results := task18ApparmorResults(t, cfg)

	// 先钉住"根因还在"这一前提：配置真的产出两条同名条目、且都激活。
	active := map[string]int{}
	for _, r := range results {
		if r.Active {
			active[NormalizeFactorID(r.ID)]++
		}
	}
	for _, id := range []string{"EF-APPARMOR", "EF-SELINUX", "EF-NO-IDS"} {
		if active[id] != 2 {
			t.Fatalf("前提不成立：%s 的 Active 条目数 = %d, want 2（配置的双条目形态变了，"+
				"本用例的判据必须重新核对而不是直接删）", id, active[id])
		}
	}

	p, enabled, err := ParamsFromConfig(cfg)
	if err != nil || !enabled {
		t.Fatalf("ParamsFromConfig: err=%v enabled=%v", err, enabled)
	}
	acts := activationsFromResults(p, results)
	seen := map[string]int{}
	for _, a := range acts {
		seen[a.FactorID]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("合成层输入里因子 %s 出现了 %d 次 —— 参数空间是因子级的"+
				"（Factors/Vectors/Coupling 全按归一 ID 建键），输入项必须每因子至多一项；"+
				"折叠点只能是『条目→因子』的换算层（`edgefactor.CollapseToFactors`），"+
				"不得在求和处打补丁，也不得改动链", id, n)
		}
	}
	if len(acts) != 3 {
		t.Errorf("折叠后条目数 = %d, want 3（EF-APPARMOR / EF-SELINUX / EF-NO-IDS）: %+v", len(acts), acts)
	}
}

// TestSynthesizeCountsEachFactorOnceOnRealChain 是**端到端**的分数钉子：用**真实记录**
// S1-apparmor-01 的链值（两组逐字段相同的条目）与真实候选参数（`vector.ini` / `graph.ini`），
// 断言 `L_d` 等于「每因子一次」的值。
//
// 手算（域 attack_surface；两组条目数值相同 ⇒ 折叠取该值本身）：
//
//	a_APPARMOR = (1−0.82)·0.15 = 0.027
//	a_SELINUX  = (1−0.80)·0.15 = 0.030
//	a_NO_IDS   = (1−0.88)·0.20 = 0.024
//	Σa         = 0.081                       ← vector 的 L
//	耦合（graph：coupling.EF-SELINUX.EF-APPARMOR = 0.35）= 0.35·0.027·0.030 = 0.0002835
//	L          = 0.0812835                   ← graph 的 L
//
// 修复前实测：vector L = 0.162（**恰好 2 倍**），graph L = 0.163134（主效应 2 倍 + 耦合 **4 倍**）。
func TestSynthesizeCountsEachFactorOnceOnRealChain(t *testing.T) {
	cfg := task18BaselineConfig(t)
	results := task18ApparmorResults(t, cfg)

	cases := []struct {
		file  string
		wantL float64
	}{
		{"vector.ini", 0.081},
		{"graph.ini", 0.0812835},
	}
	// 容差只用来吸收浮点求和顺序（三个 `(1−eff)·v` 的加法顺序与手写字面量不同，末位可差
	// 1 ulp）；要判的差异是 0.081 vs 0.162（**2 倍**），容差 1e-9 绰绰有余。
	const tol = 1e-9
	for _, tc := range cases {
		cand := task18Config(t, "../../../configs/edgeexp/"+tc.file)
		p, enabled, err := ParamsFromConfig(cand)
		if err != nil || !enabled {
			t.Fatalf("%s: err=%v enabled=%v", tc.file, err, enabled)
		}
		plan, err := newSynthesizePlan(p)
		if err != nil {
			t.Fatal(err)
		}
		res, err := synthesizeWithModel(plan, results)
		if err != nil {
			t.Fatal(err)
		}
		got := res.L["attack_surface"]
		if diff := got - tc.wantL; diff > tol || diff < -tol {
			t.Errorf("%s: L[attack_surface] = %.12f, want %.12f（差 %.12f）—— 合成层把同名双条目"+
				"各计了一次：主效应 ×2、耦合项 ×4（条目对）。折叠点只能是『条目→因子』的换算层",
				tc.file, got, tc.wantL, diff)
		}
	}
}

// task18BaselineConfig 装载采集用的 M0 模板（含 `[edge_factors]` + `[edge_factors.custom]`
// 的双条目形态）。
func task18BaselineConfig(t *testing.T) *config.Config {
	t.Helper()
	return task18Config(t, "../../../configs/edgeexp/m0-baseline.ini")
}

func task18Config(t *testing.T, path string) *config.Config {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// task18ApparmorResults 用真实配置复现 S1-apparmor 场景的引擎因子结果：失败检查集是
// `OT-005`（EF-SELINUX 与 EF-APPARMOR 共用）与 `RS-006`（EF-NO-IDS）—— 取自真实记录
// `records-t17-qemu.jsonl` 的 `checks[]`。
func task18ApparmorResults(t *testing.T, cfg *config.Config) []ssam.EdgeFactorResult {
	t.Helper()
	efs := ConfigToEdgeFactors(cfg)
	custom := map[string]float64{}
	for _, e := range efs {
		custom[e.ID] = e.Factor
	}
	checks := []CheckInput{
		{CheckID: "OT-005", Domain: "operation_trust", Passed: false, Delta: -15, Confidence: 1},
		{CheckID: "RS-006", Domain: "resilience", Passed: false, Delta: -12, Confidence: 1},
	}
	return ssam.ApplyEdgeFactorsToChecksPolicy(efs, checks, custom, DefaultConfidencePolicy())
}
