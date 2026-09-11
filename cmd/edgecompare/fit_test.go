//go:build edgeexp

package main

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/edgefactor"
)

// ============================================================================
// Task 10 夹具：合成数据（真值已知）+ 基准参数
// ============================================================================
//
// 真值模型（与 design 的**列口径**逐项对齐，故系数可辨识）：
//
//	z = β0 + βA·a_A + βB·a_B + c·a_A·a_B ,  P(compromised) = σ(z)
//	a_i = (1 − eff_i)·Σ_d v_i[d]
//
// β0/βA/βB 与 c 都是**已知真值**；`c` 正是拟合器应当还原的耦合系数。三条对齐要点：
//
//  1. `c_trigger` 恒取 1.0 ⇒ 装配层换算 `EffectiveFactor(f,1) = f` 与生成口径一致（可信度
//     衰减不进入本测试的可辨识范围；c ≠ 1 的口径差由 consistency_test.go 的门禁显式标注）；
//  2. 只声明 attack_surface 的 λ 与向量 ⇒ 裁剪后 a_i = (1−eff_i)·1.0，与 design 列逐位相同；
//  3. β 取 (0,1)：mandate 的「β_i > 0 ⇒ Factors[i] = clip(1−β_i, 1e-3, 1)」于是落在**不饱和**
//     区间，回填段里的 f_i 是正常值（β ≥ 1 会被 clip 到 1e-3 —— 那是规则的字面语义，见报告
//     §拟合器设计的近似性标注）。
const (
	fitTruthBeta0 = -0.85
	fitTruthBetaA = 0.8
	fitTruthBetaB = 0.8
	// fitN 是合成数据集的样本量。
	//
	// **Task 10 实现者修正（原值 3000）**：±0.25 这条容差必须按**估计量自身的抽样标准误**来设，
	// 否则"还原成功"只反映种子挑得好。实测（每组 12–40 个独立种子，真值 c = 0.4、L2 = 0.01）：
	//
	//	n = 3000  ⇒ sd(ĉ) = 0.272～0.314（±0.25 ≈ 0.8σ！）
	//	n = 20000 ⇒ sd(ĉ) = 0.109
	//	n = 40000 ⇒ sd(ĉ) = 0.102
	//	n = 60000 ⇒ sd(ĉ) = 0.066（±0.25 ≈ 3.8σ）
	//
	// 估计量本身无系统偏置（相对 L2 下偏置 +0.03 量级，见 fit.go 的求解器注释），
	// 故 sd ∝ 1/√n。原值 3000 下 ±0.25 是**亚 1σ** 断言：三个固定种子是过是不过取决于运气，
	// 这正是该测试注释里想避免的"一次偶然"。取 60000 让容差回到 3σ 以上 —— 代价是
	// 每个 Fit 约 0.9s（热启动后；全量套件约 15s），这是把可恢复性测成可恢复性的必要成本。
	fitN = 60000
)

// syntheticRecords 生成 fitN 条**标签由已知真值模型产生**的合成记录。
//
// 偏离 brief 的三处（均在报告 §自行决策中记录）：
//   - 多一个 `seed` 参数：可恢复性只用一个数据集证明是「一次偶然」，故用多组独立种子交叉验证；
//   - 样本量由 `fitN` 决定而不是 hardcode 在函数里（偏置测试需要别处复用同一生成器）；
//   - 不返回 `*testing.T` 之外的随机夹具：真实 c 由调用方给出（brief 的 `syntheticRecords(t, 0.4)`）。
func syntheticRecords(t *testing.T, c float64, seed int64) []Record {
	t.Helper()
	return generateSyntheticRecords(t, c, seed, fitN)
}

// generateSyntheticRecords 是样本量可变版本的生成器（唯一实现，`syntheticRecords` 只是包一层）。
func generateSyntheticRecords(t *testing.T, c float64, seed int64, n int) []Record {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	base := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	out := make([]Record, 0, n)
	for i := 0; i < n; i++ {
		rec := Record{
			ScenarioID: fmt.Sprintf("SYN-%04d", i),
			Observed: Observed{
				DomainScores: map[string]float64{"attack_surface": 60},
				Threshold:    50,
			},
		}
		aA, aB := 0.0, 0.0
		if rng.Float64() < 0.8 {
			eff := 0.05 + 0.90*rng.Float64()
			aA = 1 - eff
			rec.Observed.EdgeFactorChain = append(rec.Observed.EdgeFactorChain, ChainObs{
				Factor: "A", TriggerCheck: "OT-005", CTrigger: 1,
				EffectiveFactor: eff, TS: base.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			})
		}
		if rng.Float64() < 0.8 {
			eff := 0.05 + 0.90*rng.Float64()
			aB = 1 - eff
			rec.Observed.EdgeFactorChain = append(rec.Observed.EdgeFactorChain, ChainObs{
				Factor: "B", TriggerCheck: "OT-005", CTrigger: 1,
				EffectiveFactor: eff, TS: base.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			})
		}
		z := fitTruthBeta0 + fitTruthBetaA*aA + fitTruthBetaB*aB + c*aA*aB
		rec.GroundTruth.Compromised = rng.Float64() < 1/(1+math.Exp(-z))
		if rec.GroundTruth.Compromised {
			rec.GroundTruth.TTPsAchieved = 3
			rec.GroundTruth.NodesAffected = 2
		}
		out = append(out, rec)
	}
	return out
}

// fitBaseParams 是合成夹具配套的基准参数：graph 模型、只声明 attack_surface。
// 它同时是「裁剪口径」的夹具 —— 向量只覆盖 attack_surface，故**只有**在
// `DefaultDomains ∩ λ` 的裁剪下才过得了 `Validate`（不裁剪会被拒：向量不覆盖其余四域）。
func fitBaseParams() edgefactor.Params {
	return edgefactor.Params{
		Model:   edgefactor.ModelGraph,
		PFloor:  0.5,
		Lambda:  map[string]float64{"attack_surface": 1.0},
		Vectors: map[string]map[string]float64{"A": {"attack_surface": 1.0}, "B": {"attack_surface": 1.0}},
		Factors: map[string]float64{"A": 0.5, "B": 0.5},
	}
}

// fitEdgeOpts 是默认拟合选项 + 先验边 A|B（合成数据里唯一真实存在的耦合）。
func fitEdgeOpts(seed int64) FitOptions {
	return FitOptions{PriorEdges: [][2]string{{"A", "B"}}, L2: 0.01, Folds: 3, Seed: seed}
}

// syntheticRecordsN 是 syntheticRecords 的样本量可调版本（只给需要"更便宜的数据集"的用例用）。
func syntheticRecordsN(t *testing.T, c float64, seed int64, n int) []Record {
	t.Helper()
	return generateSyntheticRecords(t, c, seed, n)
}

// estimateCouplingForTest 走 `buildFitDesign` + `pointEstimate`（与 `Fit` 写入 Coefficients
// 的**同一批函数**），但跳过 k 折交叉验证与 100 次自助法 —— 那一部分占单次 Fit 九成以上耗时，
// 且与"估计量是否有偏"无关。偏置测试要跑几十组独立数据集，只能走这条便宜路径。
func estimateCouplingForTest(t *testing.T, records []Record, base edgefactor.Params, opts FitOptions) float64 {
	t.Helper()
	d, err := buildFitDesign(records, base, opts)
	if err != nil {
		t.Fatalf("buildFitDesign: %v", err)
	}
	beta := d.pointEstimate()
	for i, name := range d.names {
		if name == "A|B" {
			return beta[i]
		}
	}
	t.Fatalf("设计矩阵里没有边列 A|B：%v", d.names)
	return 0
}

// ============================================================================
// 可恢复性：已知 c_ij 必须能被近似还原（mandate 口径 1 的验收面）
// ============================================================================

// TestFitRecoversKnownCoupling 是 brief 的核心验收：真值 c(A,B) = 0.4 应被近似还原。
//
// 为什么用多组种子：单个数据集上的「还原成功」可能只是该样本的一次偶然。三组独立数据集
// 各自落在 ±0.25 容差内，才说明拟合器真的有可恢复性（实测误差见报告 §可恢复性证据）。
func TestFitRecoversKnownCoupling(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    float64
		seed int64
	}{
		{"c=0.4 seed=7", 0.4, 7},
		{"c=0.4 seed=20260912", 0.4, 20260912},
		{"c=0.4 seed=88", 0.4, 88},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recs := syntheticRecords(t, tc.c, tc.seed)
			p, rep, err := Fit(recs, fitBaseParams(), fitEdgeOpts(tc.seed))
			if err != nil {
				t.Fatalf("Fit: %v", err)
			}
			got := p.Coupling["A"]["B"]
			if math.Abs(got-tc.c) > 0.25 {
				t.Errorf("还原出的耦合 c(A,B) = %v, want ≈ %v（±0.25 容差）", got, tc.c)
			}
			if _, ok := rep.EdgeCoefficients["A|B"]; !ok {
				t.Errorf("报告必须含边系数 A|B：%+v", rep.EdgeCoefficients)
			}
			if _, ok := rep.Bootstrap["A|B"]; !ok {
				t.Errorf("报告必须含边的自助法区间：%+v", rep.Bootstrap)
			}
			// 无耦合真值（c = 0）时边系数应显著更小 —— 这一层断言挡住「估计器整体有偏但
			// 对任何输入都给同一个数」这种伪还原（只看单点容差是抓不住的）。
			weak, _, err := Fit(syntheticRecords(t, 0.0, tc.seed), fitBaseParams(), fitEdgeOpts(tc.seed))
			if err != nil {
				t.Fatalf("Fit(c=0): %v", err)
			}
			if weak.Coupling["A"]["B"] >= got {
				t.Errorf("c=0 数据集还原出的耦合 %v 不应 ≥ c=%v 数据集还原出的 %v",
					weak.Coupling["A"]["B"], tc.c, got)
			}
		})
	}
}

// TestFitCouplingScalesWithTrueCoupling：还原值必须**随真值单调**变化，而不是常数近似。
func TestFitCouplingScalesWithTrueCoupling(t *testing.T) {
	low, _, err := Fit(syntheticRecords(t, 0.1, 7), fitBaseParams(), fitEdgeOpts(7))
	if err != nil {
		t.Fatalf("Fit(c=0.1): %v", err)
	}
	high, _, err := Fit(syntheticRecords(t, 0.7, 7), fitBaseParams(), fitEdgeOpts(7))
	if err != nil {
		t.Fatalf("Fit(c=0.7): %v", err)
	}
	lo, hi := low.Coupling["A"]["B"], high.Coupling["A"]["B"]
	if !(lo < hi) {
		t.Errorf("c=0.1 ⇒ %v 必须 < c=0.7 ⇒ %v", lo, hi)
	}
	if math.Abs(lo-0.1) > 0.25 {
		t.Errorf("c=0.1 还原为 %v，超出 ±0.25 容差", lo)
	}
	if math.Abs(hi-0.7) > 0.25 {
		t.Errorf("c=0.7 还原为 %v，超出 ±0.25 容差", hi)
	}
}

// ============================================================================
// 系数 → 参数的映射规则（写死在实现里，边界必须逐条钉住）
// ============================================================================

// TestFitCoefficientMappingRules 钉住 mandate 给定的映射规则（含边界）：
//
//	主效应 β_i > 0 ⇒ Factors[i] = clip(1 − β_i, 1e-3, 1)；β_i ≤ 0 ⇒ Factors[i] = 1（不惩罚）
//	交互   β_ij > 0 ⇒ Coupling[i][j] = min(β_ij, 1)；      β_ij ≤ 0 ⇒ 不写（保持 0）
func TestFitCoefficientMappingRules(t *testing.T) {
	for _, tc := range []struct {
		beta float64
		want float64
	}{
		{-3, 1},    // β ≤ 0：不惩罚（1，而不是 clip 到上界以外的怪值）
		{-1e-9, 1}, // 边界：任意负数一律 1
		{0, 1},     // β == 0 ⇒ 1（规则里 β ≤ 0 的分支）
		{0.3, 0.7},
		// 修正（Task 10 实现者注）：原表这里是 {0.999, 1 - 0.999}。Go 的**无类型常量**
		// 表达式 `1 - 0.999` 是精确算术（= 0.001），而实现里的 `1 - β` 是 float64 运行时减法
		// （β = float64(0.999) 的最近双精度值 ⇒ 1 − β = 0.0010000000000000009，比 0.001 大 1 ulp，
		// 于是 math.Max 取到后者）。断言的**意图**是"β 略小于 1 ⇒ 结果落在不饱和区间"，
		// 用二进制精确可表示的 0.875 保留该意图，并消除这个编译期/运行期的 1 ulp 陷阱；
		// 真正的饱和边界由下面的 {1, 1e-3} 与 {2.5, 1e-3} 钉住。
		{0.875, 0.125},
		{1, 1e-3},   // β == 1 ⇒ clip 下界
		{2.5, 1e-3}, // β > 1 ⇒ 饱和在 1e-3
	} {
		if got := factorFromCoefficient(tc.beta); got != tc.want {
			t.Errorf("factorFromCoefficient(%v) = %v, want %v", tc.beta, got, tc.want)
		}
	}
	for _, tc := range []struct {
		beta  float64
		want  float64
		write bool
	}{
		{-1, 0, false},
		{0, 0, false},
		{0.4, 0.4, true},
		{1, 1, true},
		{1.7, 1, true}, // min(β,1)
	} {
		got, write := couplingFromCoefficient(tc.beta)
		if write != tc.write || got != tc.want {
			t.Errorf("couplingFromCoefficient(%v) = (%v,%v), want (%v,%v)", tc.beta, got, write, tc.want, tc.write)
		}
	}
}

// ============================================================================
// 确定性与无副作用
// ============================================================================

// TestFitIsDeterministic：固定种子 ⇒ 逐位相同（含参数、报告与自助法区间）。
// 拟合产物要进论文/配置，抖动即不可归因。
func TestFitIsDeterministic(t *testing.T) {
	recs := syntheticRecords(t, 0.4, 7)
	p1, r1, err := Fit(recs, fitBaseParams(), fitEdgeOpts(7))
	if err != nil {
		t.Fatalf("Fit #1: %v", err)
	}
	p2, r2, err := Fit(recs, fitBaseParams(), fitEdgeOpts(7))
	if err != nil {
		t.Fatalf("Fit #2: %v", err)
	}
	if !reflect.DeepEqual(p1, p2) {
		t.Errorf("两次拟合的参数不同：\n%+v\n%+v", p1, p2)
	}
	if !reflect.DeepEqual(r1, r2) {
		t.Errorf("两次拟合的报告不同（自助法必须固定种子）：\n%+v\n%+v", r1, r2)
	}
	if p1.Hash() != p2.Hash() {
		t.Errorf("参数指纹不同：%s vs %s", p1.Hash(), p2.Hash())
	}
}

// TestFitDoesNotMutateBase：基准参数是调用方的财产（CLI 从配置装载、随后可能还要用），
// 拟合必须返回**独立副本** —— 就地改 map 会让「基准」与「拟合结果」静默变成同一份。
// map 别名只能这样测：比对返回值，改不动调用方的 map 才算真的复制过。
func TestFitDoesNotMutateBase(t *testing.T) {
	base := fitBaseParams()
	p, _, err := Fit(syntheticRecords(t, 0.4, 7), base, fitEdgeOpts(7))
	if err != nil {
		t.Fatalf("Fit: %v", err)
	}
	if base.Factors["A"] != 0.5 {
		t.Errorf("Fit 就地改写了基准的 Factors：%v", base.Factors)
	}
	if base.Coupling != nil {
		t.Errorf("Fit 就地写入了基准的 Coupling：%v", base.Coupling)
	}
	// 反向：改拟合结果也不能影响基准（同一张 map 的两个名字）。
	p.Factors["A"] = 0.123456
	p.Coupling["A"]["B"] = 0.654321
	if base.Factors["A"] != 0.5 {
		t.Errorf("拟合结果与基准共用同一张 Factors map：%v", base.Factors)
	}
	if _, ok := base.Coupling["A"]; ok {
		t.Errorf("拟合结果与基准共用同一张 Coupling map：%v", base.Coupling)
	}
}

// TestFitRejectsDuplicatePriorEdge：同一条边写两次会造出两个完全相同的列
// （设计矩阵奇异、边系数无意义），必须在拟合前拒绝。
func TestFitRejectsDuplicatePriorEdge(t *testing.T) {
	_, _, err := Fit(syntheticRecords(t, 0.4, 7), fitBaseParams(), FitOptions{
		PriorEdges: [][2]string{{"A", "B"}, {"A", "B"}}, L2: 0.01, Folds: 3, Seed: 7,
	})
	if err == nil {
		t.Fatal("重复的先验边必须报错")
	}
	if !strings.Contains(err.Error(), "A|B") {
		t.Errorf("错误必须点名重复的边：%v", err)
	}
}

// TestFitRejectsNonPositiveLambda：基准参数过不了裁剪域上的 Validate 时必须报错
// （λ ≤ 0 的公式在 Synthesize 里就被拒），不得自行兜底。
func TestFitRejectsNonPositiveLambda(t *testing.T) {
	base := fitBaseParams()
	base.Lambda = map[string]float64{"attack_surface": 0}
	if _, _, err := Fit(syntheticRecords(t, 0.4, 7), base, fitEdgeOpts(7)); err == nil {
		t.Fatal("λ ≤ 0 的基准参数必须报错")
	}
}

// ============================================================================
// fail-fast：拟合的前置条件不能被静默放宽
// ============================================================================

// TestFitRejectsEmptyRecords：零记录下任何"系数"都只是正则项的产物。
func TestFitRejectsEmptyRecords(t *testing.T) {
	if _, _, err := Fit(nil, fitBaseParams(), fitEdgeOpts(7)); err == nil {
		t.Fatal("零记录必须报错")
	}
}

// TestFitRejectsUnknownPriorEdgeFactor：先验边指向未建模因子时，边列会退化成
// 「拿主效应第 0 列相乘」的垃圾列，且边系数无处落 —— 必须报错而不是照算。
func TestFitRejectsUnknownPriorEdgeFactor(t *testing.T) {
	_, _, err := Fit(syntheticRecords(t, 0.4, 7), fitBaseParams(), FitOptions{
		PriorEdges: [][2]string{{"A", "GHOST"}}, L2: 0.01, Folds: 3, Seed: 7,
	})
	if err == nil {
		t.Fatal("先验边引用未建模因子必须报错")
	}
	if !strings.Contains(err.Error(), "GHOST") {
		t.Errorf("错误必须点名未知因子：%v", err)
	}
}

// TestFitRejectsSelfEdge：自耦合边（A|A）不会被 Synthesize 消费（它跳过 from == to），
// 拟合出来只会是一份"报告里有、模型里没有"的假参数。
func TestFitRejectsSelfEdge(t *testing.T) {
	if _, _, err := Fit(syntheticRecords(t, 0.4, 7), fitBaseParams(), FitOptions{
		PriorEdges: [][2]string{{"A", "A"}}, L2: 0.01, Folds: 3, Seed: 7,
	}); err == nil {
		t.Fatal("自耦合边必须报错")
	}
}

// TestFitRejectsTooManyPriorEdges：可辨识性约束（22 场景 vs 21 参数）落在**先验边集 ≤ 5**上，
// 超限必须报错而不是悄悄截断（截断会让报告里的边集与实际拟合的边集不是同一套）。
func TestFitRejectsTooManyPriorEdges(t *testing.T) {
	edges := [][2]string{{"A", "B"}, {"B", "A"}, {"A", "B"}, {"B", "A"}, {"A", "B"}, {"B", "A"}}
	_, _, err := Fit(syntheticRecords(t, 0.4, 7), fitBaseParams(), FitOptions{
		PriorEdges: edges, L2: 0.01, Folds: 3, Seed: 7,
	})
	if err == nil {
		t.Fatal("超过 5 条先验边必须报错")
	}
	if !strings.Contains(err.Error(), "5") {
		t.Errorf("错误必须点明上限：%v", err)
	}
}

// TestFitRejectsFoldsLargerThanSample：折数大于样本数时"交叉验证"无从进行，
// 返回 0 会被读成"零泛化误差"——那是凭空造出来的结论。
func TestFitRejectsFoldsLargerThanSample(t *testing.T) {
	recs := syntheticRecords(t, 0.4, 7)[:2]
	_, _, err := Fit(recs, fitBaseParams(), FitOptions{
		PriorEdges: [][2]string{{"A", "B"}}, L2: 0.01, Folds: 3, Seed: 7,
	})
	if err == nil {
		t.Fatal("折数 > 样本数必须报错")
	}
}

// TestFitRejectsEmptyDesign：基准既无因子又无边 ⇒ 设计矩阵只有截距，拟合无意义。
func TestFitRejectsEmptyDesign(t *testing.T) {
	base := fitBaseParams()
	base.Factors = nil
	base.Vectors = nil
	if _, _, err := Fit(syntheticRecords(t, 0.4, 7), base, FitOptions{L2: 0.01, Folds: 3, Seed: 7}); err == nil {
		t.Fatal("空设计矩阵必须报错")
	}
}

// TestFitRejectsCouplingOnNonCouplingModel：legacy/vector 不消费 Coupling，
// 传先验边却拟合出边系数，会得到一份"报告里有边、模型里没有边"的假产物。
func TestFitRejectsCouplingOnNonCouplingModel(t *testing.T) {
	base := fitBaseParams()
	base.Model = edgefactor.ModelVector
	if _, _, err := Fit(syntheticRecords(t, 0.4, 7), base, fitEdgeOpts(7)); err == nil {
		t.Fatal("vector 模型 + 先验边必须报错（该模型不消费 Coupling）")
	}
}

// ============================================================================
// 报告面：交叉验证误差与自助法区间必须是"真的测量过"
// ============================================================================

// TestFitReportCarriesRealUncertainty：CVErr 必须是真实的对数损失（有限、正、量级合理），
// 自助法区间必须覆盖每一列且 lo ≤ hi —— 三者都挡住"返回零值假装测过"。
func TestFitReportCarriesRealUncertainty(t *testing.T) {
	_, rep, err := Fit(syntheticRecords(t, 0.4, 7), fitBaseParams(), fitEdgeOpts(7))
	if err != nil {
		t.Fatalf("Fit: %v", err)
	}
	if !(rep.CVErr > 0.1 && rep.CVErr < 2.0) {
		t.Errorf("CVErr = %v，不像一次真实的对数损失测量（0 表示没测）", rep.CVErr)
	}
	for _, name := range []string{"(intercept)", "A", "B", "A|B"} {
		ci, ok := rep.Bootstrap[name]
		if !ok {
			t.Errorf("自助法区间缺列 %q：%+v", name, rep.Bootstrap)
			continue
		}
		if math.IsNaN(ci[0]) || math.IsNaN(ci[1]) || ci[0] > ci[1] {
			t.Errorf("%s 的区间非法：%v", name, ci)
		}
		if _, ok := rep.Coefficients[name]; !ok {
			t.Errorf("系数表缺列 %q：%+v", name, rep.Coefficients)
		}
	}
	if _, ok := rep.Coefficients["A"]; !ok {
		t.Errorf("系数表必须含主效应列：%+v", rep.Coefficients)
	}
	if _, ok := rep.EdgeCoefficients["A"]; ok {
		t.Errorf("EdgeCoefficients 只应含边列（键形如 i|j）：%+v", rep.EdgeCoefficients)
	}
}

// ============================================================================
// 可回填性：拟合产物必须能通过生产解析层与校验层（mandate 口径 5）
// ============================================================================

// TestFittedParamsRenderBackToConfigSection：把拟合结果按 Task 9 的导出器渲染成配置段，
// 再用**生产解析器 + 校验层**重解析 —— 与 Task 9 的"渲染后重解析"断言同款纪律。
func TestFittedParamsRenderBackToConfigSection(t *testing.T) {
	p, _, err := Fit(syntheticRecords(t, 0.4, 7), fitBaseParams(), fitEdgeOpts(7))
	if err != nil {
		t.Fatalf("Fit: %v", err)
	}
	var buf bytes.Buffer
	if err := RenderConfigSection(&buf, string(p.Model), p); err != nil {
		t.Fatalf("RenderConfigSection: %v", err)
	}
	sections, err := parseRenderedSections(buf.String())
	if err != nil {
		t.Fatalf("parseRenderedSections: %v", err)
	}
	cfg, present, err := config.ParseEdgeFactorModel(sections)
	if err != nil {
		t.Fatalf("拟合产物无法被 [edge_factors.model] 解析层接受：%v", err)
	}
	if !present {
		t.Fatal("渲染结果里没有 [edge_factors.model] 段")
	}
	rebuilt := edgefactor.Params{
		Model:              edgefactor.ModelID(cfg.Model),
		PFloor:             cfg.PFloor,
		Lambda:             cfg.Lambda,
		Vectors:            cfg.Vectors,
		Coupling:           cfg.Coupling,
		ChainWindowSeconds: cfg.ChainWindowSeconds,
	}
	if err := rebuilt.Validate(edgefactor.DefaultDomains()); err != nil {
		t.Fatalf("拟合产物过不了 Validate(DefaultDomains())：%v", err)
	}
	// 拟合出的耦合必须原样回填（不只是"能解析"）：渲染 → 重解析后系数逐位相同。
	if got := rebuilt.Coupling["A"]["B"]; got != p.Coupling["A"]["B"] {
		t.Errorf("回填后的耦合 = %v, want %v", got, p.Coupling["A"]["B"])
	}
}

// ============================================================================
// Fix round 1 / C1：β_ij ≤ 0 时的「不写」必须**移除基准里的旧值**
// ============================================================================

// TestFitRemovesUnsupportedBaseCoupling 钉住 C1：基准参数里已有的耦合，若数据不给支持
// （拟合出的 β_ij ≤ 0），**必须从产物里消失**。
//
// 为什么这条是 Critical：`Fit` 返回的是 `base` 的深拷贝。若对 β ≤ 0 只 `continue`，产物会
// 带着基准的旧耦合被 `RenderConfigSection` 写进配置段，而报告行却打印「coupling 不写（β ≤ 0）」
// —— 同一份产物自相矛盾。可达路径真实：`-fit` 的基准就是 `config.Load` 读进来的配置
// （真实配置会带 C 模型的级联边，或上一轮的拟合产物），于是重复拟合会把已经不再显著的边
// **永久保留**下来。
//
// 夹具用 c = −1.0（强负交互）：真值边系数约为 −1，远在任何容差之外，故本用例是确定性的
// （不需要"碰巧 β ≤ 0"）。同时验证三件事：
//  1. 产物里该边消失（正/反两个存储方向都要删 —— graph 的耦合是对称的）；
//  2. **基准本身不被就地改写**（深拷贝契约）；
//  3. 先验边集**之外**的边保持基准值（它们不进设计矩阵，无从估计）；
//  4. 报告仍然给出该边的系数（"哪些边显著"的结论需要看到这个负号）。
func TestFitRemovesUnsupportedBaseCoupling(t *testing.T) {
	for _, tc := range []struct {
		name    string
		coupled map[string]map[string]float64
	}{
		{"正向存储 A→B", map[string]map[string]float64{"A": {"B": 0.5}}},
		{"反向存储 B→A（graph 对称）", map[string]map[string]float64{"B": {"A": 0.5}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := fitBaseParams()
			base.Coupling = map[string]map[string]float64{}
			for from, tos := range tc.coupled {
				base.Coupling[from] = map[string]float64{}
				for to, c := range tos {
					base.Coupling[from][to] = c
				}
			}
			// 先验边集之外的边（作对照）：拟合不该动它 —— 它不在设计矩阵里，无从估计。
			base.Coupling["ZZ-ORPHAN"] = map[string]float64{"YY-ORPHAN": 0.25}

			p, rep, err := Fit(syntheticRecords(t, -1.0, 7), base, fitEdgeOpts(7))
			if err != nil {
				t.Fatalf("Fit: %v", err)
			}
			if beta, ok := rep.EdgeCoefficients["A|B"]; !ok {
				t.Fatalf("报告必须给出该边的系数（哪怕为负）：%+v", rep.EdgeCoefficients)
			} else if beta > 0 {
				t.Fatalf("夹具前提不成立：c = −1.0 的数据本应给出负的边系数，实际 %v", beta)
			}
			if got, ok := p.Coupling["A"]["B"]; ok {
				t.Errorf("数据不支持该边（β ≤ 0）⇒ 产物里必须没有 A→B，实际 %v", got)
			}
			if got, ok := p.Coupling["B"]["A"]; ok {
				t.Errorf("数据不支持该边（β ≤ 0）⇒ 产物里必须没有 B→A（graph 对称），实际 %v", got)
			}
			if _, ok := p.Coupling["A"]; ok {
				t.Errorf("删空的内层 map 应一并删掉，实际 %v", p.Coupling["A"])
			}
			// 基准是调用方的财产：既有耦合不能被就地删掉/改写。
			if base.Coupling["A"]["B"] != 0.5 && base.Coupling["B"]["A"] != 0.5 {
				t.Errorf("Fit 就地改写了基准的 Coupling：%v", base.Coupling)
			}
			// 先验边之外的边保持基准值。
			if p.Coupling["ZZ-ORPHAN"]["YY-ORPHAN"] != 0.25 {
				t.Errorf("先验边集之外的边应保持基准值，实际 %v", p.Coupling["ZZ-ORPHAN"])
			}
		})
	}
}

// TestFitKeepsCouplingWhenDataSupportsIt 是 C1 的**反向对照**：数据支持该边时不能把它删掉。
// 没有这条，把 `removeCouplingEdge` 写成无条件调用也能让上面那条测试通过。
func TestFitKeepsCouplingWhenDataSupportsIt(t *testing.T) {
	base := fitBaseParams()
	base.Coupling = map[string]map[string]float64{"A": {"B": 0.05}} // 旧值应被拟合值覆盖
	p, _, err := Fit(syntheticRecords(t, 0.4, 7), base, fitEdgeOpts(7))
	if err != nil {
		t.Fatalf("Fit: %v", err)
	}
	got, ok := p.Coupling["A"]["B"]
	if !ok {
		t.Fatal("数据支持该边（β > 0）⇒ 产物必须保留 A→B")
	}
	if got < 0.25 {
		t.Errorf("产物里的耦合 %v 应是拟合值（≈0.4），不是被保留的基准旧值 0.05", got)
	}
	if base.Coupling["A"]["B"] != 0.05 {
		t.Errorf("Fit 就地改写了基准的 Coupling：%v", base.Coupling)
	}
}

// ============================================================================
// Fix round 1 / I1：偏置断言 —— 抓得住"罚项把耦合系数整体推高"这类回归
// ============================================================================

// TestFitCouplingIsUnbiasedAcrossSeeds 断言**均值无偏**：多组独立数据集上还原出的耦合系数
// 的平均值必须贴近真值。
//
// 为什么必须补这条：`TestFitRecoversKnownCoupling` 的 ±0.25 是**逐数据集容差**，它挡的是
// 抽样噪声，挡不住系统偏置。实测：把 L2 换回绝对罚项（本任务 D2 修掉的那个缺陷）时，
// 真值 c = 0.4 的还原均值是 0.542（偏置 +0.142），**而每一组单独看都还在 ±0.25 之内** ——
// 也就是说没有这条断言，D2 的缺陷回归时全套测试照样全绿。
//
// 判据（40 组种子 × n = 60000）：
//
//	实现                                       实测均值   偏置     本断言
//	相对 L2（现实现）                            0.433    +0.033    ✅ 通过（余量 3.9σ）
//	绝对 L2（D2 之前的写法，临时回滚实测）        0.542    +0.142   ❌ 失败（−4.4σ）
//
// 阈值取 0.08：现实现的偏置 +0.033 距阈值 3.9 个标准误（sem ≈ 0.012），
// 而被测的那个回归偏置 +0.142 距阈值 4.4 个标准误 —— 两侧都有足够余量。
func TestFitCouplingIsUnbiasedAcrossSeeds(t *testing.T) {
	const (
		rounds  = 40
		records = 60000
		want    = 0.4
		tol     = 0.08
	)
	sum := 0.0
	for seed := int64(1); seed <= rounds; seed++ {
		opts := fitEdgeOpts(seed)
		got := estimateCouplingForTest(t, syntheticRecordsN(t, want, seed, records), fitBaseParams(), opts)
		sum += math.Min(math.Max(got, 0), 1) // 与 couplingFromCoefficient 的落库口径一致
	}
	mean := sum / float64(rounds)
	if math.Abs(mean-want) > tol {
		t.Errorf("还原出的耦合均值 = %.4f（偏置 %+.4f），want %.2f ± %.2f —— 逐数据集容差抓不住系统偏置，"+
			"绝对罚项回归时的实测偏置是 +0.142", mean, mean-want, want, tol)
	}
}

// TestFitBootstrapCoversTrueCoupling 断言自助法 95% 区间**覆盖真值**。
//
// 这条同时钉住两件事：
//  1. 区间是真的在测抽样分布（不是"返回零值假装测过"，也不是宽度为 0 的假区间）；
//  2. `Bootstrap` 与 `Coefficients` 处在**同一尺度**（Fix round 1 / I1 修正的 bug：
//     自助法重采样在标准化尺度上求解，早期实现在那个尺度上取百分位，于是区间看着总是
//     包不住系数 —— 区间与系数不同量纲，这条断言根本写不出来）。
func TestFitBootstrapCoversTrueCoupling(t *testing.T) {
	const want = 0.4
	for _, seed := range []int64{7, 20260912, 88} {
		p, rep, err := Fit(syntheticRecords(t, want, seed), fitBaseParams(), fitEdgeOpts(seed))
		if err != nil {
			t.Fatalf("seed=%d: Fit: %v", seed, err)
		}
		ci, ok := rep.Bootstrap["A|B"]
		if !ok {
			t.Fatalf("seed=%d: 缺 A|B 的自助法区间：%+v", seed, rep.Bootstrap)
		}
		if ci[0] >= ci[1] {
			t.Errorf("seed=%d: 区间非法 %v", seed, ci)
		}
		if want < ci[0] || want > ci[1] {
			t.Errorf("seed=%d: 95%% 自助法区间 [%v, %v] 未覆盖真值 %v（点估计 %v）—— "+
				"区间与系数可能已不在同一尺度", seed, ci[0], ci[1], want, p.Coupling["A"]["B"])
		}
		// 区间必须包含或贴着点估计（同一尺度、同一次拟合的必然结果）。
		if point := p.Coupling["A"]["B"]; point < ci[0] || point > ci[1] {
			t.Errorf("seed=%d: 点估计 %v 落在自己的 95%% 区间 [%v, %v] 之外 —— 尺度不一致",
				seed, point, ci[0], ci[1])
		}
	}
}

// ============================================================================
// Fix round 1 / I4：L1 路径的收缩与可复现性
// ============================================================================

// TestElasticNetL1ShrinksToExactZero 直接在**设计正交**的数据上钉住 L1 的收缩语义。
//
// 为什么不拿本包的合成夹具测"L1 把耦合压小"：那个夹具的列高度共线（交互列 ≈ 两个主效应列
// 之积），L1 会把主效应压没、转而用交互列当代理，**中等强度的 L1 反而把耦合系数推高**
// （实测 n=20000、c=0.4：l1 = 0 → 0.453；l1 = 0.01 → 0.664；l1 = 0.05 → 0.918，同时主效应被压到 0）。
// 那是共线性下的真实行为，不是求解器的问题，但它让"L1 ⇒ 耦合更小"在这个夹具上并不成立 ——
// 拿它当断言会写出假命题。故本用例改用 3 个**精确正交**（且与截距正交）的 ±1 列：
// Gram 矩阵是对角的 ⇒ 坐标解就是 `S(c_j, l1)/G_jj`，收缩与置零都是可逐项验证的精确行为。
func TestElasticNetL1ShrinksToExactZero(t *testing.T) {
	// 4 个模式两两正交、且与常数列正交；每个模式复制 400 次 ⇒ n = 1600。
	patterns := [][3]float64{{1, 1, 1}, {1, -1, -1}, {-1, 1, -1}, {-1, -1, 1}}
	const perPattern = 400
	truth := []float64{-0.3, 1.2, 0.6, 0.0} // 第 3 个特征无效 ⇒ L1 应当先把它压到 0
	rng := rand.New(rand.NewSource(20261010))
	var X [][]float64
	var y []bool
	for _, p := range patterns {
		z := truth[0] + truth[1]*p[0] + truth[2]*p[1] + truth[3]*p[2]
		prob := 1 / (1 + math.Exp(-z))
		for i := 0; i < perPattern; i++ {
			X = append(X, []float64{1, p[0], p[1], p[2]})
			y = append(y, rng.Float64() < prob)
		}
	}

	abs := func(w []float64) []float64 {
		out := make([]float64, len(w))
		for i, v := range w {
			out[i] = math.Abs(v)
		}
		return out
	}
	prev := abs(fitElasticNet(X, y, 0, 0, nil))
	if prev[1] < 0.5 || prev[2] < 0.2 {
		t.Fatalf("前提不成立：正交夹具上 L1=0 的系数本应接近真值，实际 %v", prev)
	}
	for _, l1 := range []float64{0.05, 0.2, 0.5, 1.0, 2.0} {
		got := fitElasticNet(X, y, l1, 0, nil)
		// ① 单调收缩：正交设计下 soft-threshold 对每个坐标都是非增的。
		for j := 1; j < len(got); j++ {
			if math.Abs(got[j]) > prev[j]+1e-12 {
				t.Errorf("l1=%v：第 %d 个系数 %v 比 l1 更小时（%v）更大 —— L1 必须收缩",
					l1, j, got[j], prev[j])
			}
		}
		// ② 可复现：同一输入两次求解逐位相同。
		if again := fitElasticNet(X, y, l1, 0, nil); !reflect.DeepEqual(got, again) {
			t.Errorf("l1=%v：两次求解不同 %v vs %v", l1, got, again)
		}
		prev = abs(got)
	}
	// ③ 足够大的 L1 把**无效特征精确压到 0**（软阈值的精确性，而不是"变小"）。
	big := fitElasticNet(X, y, 2.0, 0, nil)
	for j := 1; j < len(big); j++ {
		if big[j] != 0 {
			t.Errorf("l1=2.0：第 %d 个系数 %v 应为精确 0（软阈值）", j, big[j])
		}
	}
	if big[0] == 0 {
		t.Error("截距不参与惩罚，不该被压成 0")
	}
}

// TestFitWithLargeL1YieldsNoCoupling 是 L1 的**整链路**用例：罚到极致时所有非截距系数
// 恰好为 0 ⇒ 按映射规则得到"不写耦合 + f_i = 1（不惩罚）"，且基准里已有的耦合被移除
// （与 C1 同一口径），并且结果可复现。
func TestFitWithLargeL1YieldsNoCoupling(t *testing.T) {
	base := fitBaseParams()
	base.Coupling = map[string]map[string]float64{"A": {"B": 0.5}}
	opts := fitEdgeOpts(7)
	opts.L1 = 10 // 远大于任何非截距系数在标准化尺度上的偏残差
	p, rep, err := Fit(syntheticRecordsN(t, 0.4, 7, 20000), base, opts)
	if err != nil {
		t.Fatalf("Fit: %v", err)
	}
	for _, name := range []string{"A", "B", "A|B"} {
		if got := rep.Coefficients[name]; got != 0 {
			t.Errorf("L1=10 时 %s 的系数应为精确 0（软阈值），实际 %v", name, got)
		}
	}
	if _, ok := p.Coupling["A"]["B"]; ok {
		t.Errorf("耦合系数被压到 0 ⇒ 产物里必须没有该边，实际 %v", p.Coupling)
	}
	for _, id := range []string{"A", "B"} {
		if p.Factors[id] != 1 {
			t.Errorf("β_%s ≤ 0 ⇒ Factors[%s] = 1（不惩罚），实际 %v", id, id, p.Factors[id])
		}
	}
	if rep.Coefficients["(intercept)"] == 0 {
		t.Error("截距不参与惩罚，不该被压成 0")
	}
	p2, rep2, err := Fit(syntheticRecordsN(t, 0.4, 7, 20000), base, opts)
	if err != nil {
		t.Fatalf("Fit #2: %v", err)
	}
	if !reflect.DeepEqual(p, p2) || !reflect.DeepEqual(rep, rep2) {
		t.Error("L1 > 0 时拟合必须仍然确定（两次结果不同）")
	}
}

// ============================================================================
// Fix round 1 / I5：单类别标签必须 fail-fast
// ============================================================================

// TestFitRejectsSingleClassLabels：标签只有一类时 logistic 似然被推向完全分离区间 ——
// 系数被截停在饱和区（主效应 clip 到 1e-3、边系数 min(β,1)=1），CVErr 退化成常数预测器的
// 损失，而全程零错误零告警。真实实验里单类别并不罕见（某一轮只跑了一组被攻陷的场景），
// 故必须拒绝而不是产出一份"看起来正常"的极端参数。
func TestFitRejectsSingleClassLabels(t *testing.T) {
	for _, tc := range []struct {
		name   string
		labels bool
	}{
		{"全部被攻陷", true},
		{"全部未攻陷", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recs := syntheticRecordsN(t, 0.4, 7, 64)
			for i := range recs {
				recs[i].GroundTruth.Compromised = tc.labels
			}
			_, _, err := Fit(recs, fitBaseParams(), fitEdgeOpts(7))
			if err == nil {
				t.Fatal("单类别标签必须报错（否则产物是迭代上限的产物，而不是拟合结果）")
			}
			if !strings.Contains(err.Error(), "单类别标签") {
				t.Errorf("错误信息必须点明原因：%v", err)
			}
		})
	}
}
