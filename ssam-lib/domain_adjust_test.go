package ssam

import (
	"math"
	"math/rand"
	"reflect"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// 参照实现（改造前的逐行副本）
//
// legacySSAMV20Formula / legacyWeightedSum 是本次改动前 SSAMV20Formula 与
// evalWeightedSum 的**逐行副本**，仅作为「未注入域级修正时默认路径逐位一致」
// 的独立参照，不参与生产代码。
// 与之对照的字面量基线（legacy*Total 等）由改造前的实现实测捕获。
// ---------------------------------------------------------------------------

func legacySSAMV20Formula(domainScores []DomainScore, weights []WeightConfig, riskCtx RiskContext, edgeFactors []EdgeFactorResult) FinalScore {
	wMap := BuildWeightMap(weights)

	sum := 0.0
	totalWeight := 0.0
	for _, ds := range domainScores {
		if w, ok := wMap[ds.Domain]; ok && w > 0 {
			sum += ds.Score * w
			totalWeight += w
		}
	}
	if totalWeight == 0 {
		return FinalScore{
			Total: 0,
			Layers: RiskLayers{
				Intrinsic: RiskLayerDetail{Coeff: 0, Weight: 0, Contributors: []string{"domain_scores"}},
				Exposure:  RiskLayerDetail{Coeff: riskCtx.Exposure, Weight: 0, Contributors: []string{"exposure_coefficient"}},
				Threat:    RiskLayerDetail{Coeff: riskCtx.Threat, Weight: 0, Contributors: []string{"threat_coefficient"}},
			},
		}
	}

	baseScore := sum / totalWeight

	intrinsicContributors := []string{"domain_scores"}
	for _, f := range edgeFactors {
		if f.Active && f.Factor > 0 && f.Factor < 1.0 {
			intrinsicContributors = append(intrinsicContributors, "edge_factor:"+f.ID)
			baseScore *= f.Factor
		}
	}

	baseScore = math.Round(baseScore*100) / 100

	intrinsicCoeff := baseScore / 100.0

	exposureCoeff := riskCtx.Exposure
	if exposureCoeff <= 0 {
		exposureCoeff = 1.0
	}
	if exposureCoeff < 0.60 {
		exposureCoeff = 0.60
	}

	threatCoeff := riskCtx.Threat
	if threatCoeff <= 0 {
		threatCoeff = 1.0
	}
	if threatCoeff < 0.60 {
		threatCoeff = 0.60
	}

	intrinsicWeight := 50.0
	exposureWeight := 30.0
	threatWeight := 20.0
	totalLayerWeight := intrinsicWeight + exposureWeight + threatWeight

	weightedAvg := (intrinsicCoeff*intrinsicWeight + exposureCoeff*exposureWeight + threatCoeff*threatWeight) / totalLayerWeight
	finalScore := math.Round(weightedAvg*100*100) / 100

	return FinalScore{
		Total: finalScore,
		Layers: RiskLayers{
			Intrinsic: RiskLayerDetail{
				Coeff:        math.Round(intrinsicCoeff*100) / 100,
				Weight:       intrinsicWeight,
				Contributors: intrinsicContributors,
			},
			Exposure: RiskLayerDetail{
				Coeff:        exposureCoeff,
				Weight:       exposureWeight,
				Contributors: []string{"exposure_coefficient"},
			},
			Threat: RiskLayerDetail{
				Coeff:        threatCoeff,
				Weight:       threatWeight,
				Contributors: []string{"threat_coefficient"},
			},
		},
	}
}

func legacyWeightedSum(domainScores []DomainScore, weights []WeightConfig) float64 {
	wMap := BuildWeightMap(weights)

	sum := 0.0
	totalWeight := 0.0
	for _, ds := range domainScores {
		if w, ok := wMap[ds.Domain]; ok && w > 0 {
			sum += ds.Score * w
			totalWeight += w
		}
	}
	if totalWeight == 0 {
		return 0
	}
	return sum / totalWeight
}

// ---------------------------------------------------------------------------
// 夹具与字面量基线
// ---------------------------------------------------------------------------

// 改造前实测捕获（`go test -run TestZZCapturePreChangeBaselines -v`）：
//
//	V20 total=67.739999999999995 (=67.74)  evalWeightedSum=80.75
//	compiledSSAMV20AST=67.739062500000003  evalASTSSAMV20AST=67.739062500000003
//	ComputeScoreV2 total=92
//	V20 total(attack_surface*0.5)=63.280000000000001 (=63.28)
//
// legacyV20ASTAdjusted 是「修正后域分在默认路径上」的实测值（AST 两条路径一致）。
const (
	legacyV20Total            = 67.74
	legacyV20TotalAdjusted    = 63.28
	legacyWeightedSumValue    = 80.75
	legacyWeightedSumAdjusted = 66.75
	legacyCompiledV20AST      = 67.739062500000003
	legacyV20ASTAdjusted      = 63.276562499999997
	legacyComputeScoreV2Total = 92
)

func domainAdjustFixture() ([]DomainScore, []WeightConfig, RiskContext, []EdgeFactorResult) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "business_continuity", Score: 90},
		{Domain: "operation_trust", Score: 70},
		{Domain: "resilience", Score: 85},
	}
	riskCtx := RiskContext{Intrinsic: 0, Exposure: 0.8, Threat: 0.9}
	factors := []EdgeFactorResult{
		{ID: "EF-002FA", Factor: 0.85, Active: true},
		{ID: "EF-SYNCOOKIE", Factor: 0.75, Active: true},
		{ID: "EF-INACTIVE", Factor: 0.5, Active: false},
		{ID: "EF-ONE", Factor: 1.0, Active: true},
	}
	return scores, DefaultWeights, riskCtx, factors
}

// halfAttackSurfaceScores 返回「仅把 attack_surface 域分减半」的域分副本。
func halfAttackSurfaceScores(scores []DomainScore) []DomainScore {
	out := make([]DomainScore, 0, len(scores))
	for _, ds := range scores {
		cp := ds
		if cp.Domain == "attack_surface" {
			cp.Score *= 0.5
		}
		out = append(out, cp)
	}
	return out
}

// halfAttackSurfaceAdjust 是测试用域级修正：逐域乘系数（attack_surface=0.5，其余=1.0）。
// 这种「各域系数不同」的修正无法用返回单个总分乘子的 EdgeFactorStrategy 表达。
func halfAttackSurfaceAdjust(domainScores []DomainScore, factors []EdgeFactorResult) []DomainScore {
	return halfAttackSurfaceScores(domainScores)
}

func domainAdjustInputV2() AssessmentInputV2 {
	_, _, riskCtx, _ := domainAdjustFixture()
	return AssessmentInputV2{
		HostID:      "host-capture",
		Threshold:   60,
		RiskContext: riskCtx,
		Checks: []CheckInput{
			{CheckID: "OT-005", Domain: "operation_trust", Passed: false, Delta: 20},
			{CheckID: "AS-001", Domain: "attack_surface", Passed: false, Delta: 15},
		},
	}
}

// ---------------------------------------------------------------------------
// 域级修正钩子
// ---------------------------------------------------------------------------

// TestDomainAdjustIsAppliedBeforeAggregation：注入域级修正后，SSAMV20Formula
// 必须先按域修正域分、再按既有公式聚合总分，且结果逐位等于「旧实现在修正后域分上的结果」。
func TestDomainAdjustIsAppliedBeforeAggregation(t *testing.T) {
	defer RegisterDomainAdjust(nil)

	scores, weights, riskCtx, factors := domainAdjustFixture()

	baseline := SSAMV20Formula(scores, weights, riskCtx, factors)
	if baseline.Total != legacyV20Total {
		t.Fatalf("未注入时总分 = %v, 改动前基线 = %v", baseline.Total, legacyV20Total)
	}
	if want := legacySSAMV20Formula(scores, weights, riskCtx, factors); !reflect.DeepEqual(baseline, want) {
		t.Fatalf("未注入时结果与旧实现不一致:\n got %+v\nwant %+v", baseline, want)
	}

	adjusted := halfAttackSurfaceScores(scores)
	RegisterDomainAdjust(halfAttackSurfaceAdjust)

	got := SSAMV20Formula(scores, weights, riskCtx, factors)
	if got.Total == baseline.Total {
		t.Fatalf("注入域级修正后总分未变化（钩子未进入生产公式）: %v", got.Total)
	}
	if got.Total != legacyV20TotalAdjusted {
		t.Fatalf("注入域级修正后总分 = %v, want %v", got.Total, legacyV20TotalAdjusted)
	}
	if want := legacySSAMV20Formula(adjusted, weights, riskCtx, factors); !reflect.DeepEqual(got, want) {
		t.Fatalf("注入后结果必须等于旧实现在修正后域分上的结果:\n got %+v\nwant %+v", got, want)
	}
}

// TestDomainAdjustAppliesToAllFormulaPaths：域级修正对 V2 公式、EvalAST 与
// ASTToFormula（编译路径）三处域分聚合同时生效，且三处都只是「替换聚合输入」，
// 不引入任何额外算法差异。
func TestDomainAdjustAppliesToAllFormulaPaths(t *testing.T) {
	defer RegisterDomainAdjust(nil)

	scores, weights, riskCtx, factors := domainAdjustFixture()
	adjusted := halfAttackSurfaceScores(scores)

	rawCtx := EvalContext{DomainScores: scores, Weights: weights, RiskContext: riskCtx, EdgeFactors: factors}
	adjCtx := EvalContext{DomainScores: adjusted, Weights: weights, RiskContext: riskCtx, EdgeFactors: factors}
	compiled := ASTToFormula(SSAMV20AST())
	compiledWS := ASTToFormula(FormulaAST{Op: OpWeightedSum})

	RegisterDomainAdjust(halfAttackSurfaceAdjust)
	gotV20 := SSAMV20Formula(scores, weights, riskCtx, factors)
	gotEval, err := EvalAST(SSAMV20AST(), rawCtx)
	if err != nil {
		t.Fatalf("EvalAST: %v", err)
	}
	gotCompiled := compiled(scores, weights, riskCtx.Threat, riskCtx.Exposure, factors)
	gotWeightedSum := evalWeightedSum(rawCtx)
	gotCompiledWS := compiledWS(scores, weights, 1.0, 1.0, factors)

	RegisterDomainAdjust(nil)
	wantV20 := SSAMV20Formula(adjusted, weights, riskCtx, factors)
	wantEval, err := EvalAST(SSAMV20AST(), adjCtx)
	if err != nil {
		t.Fatalf("EvalAST(adjusted): %v", err)
	}
	wantCompiled := compiled(adjusted, weights, riskCtx.Threat, riskCtx.Exposure, factors)
	wantWeightedSum := evalWeightedSum(adjCtx)
	wantCompiledWS := compiledWS(adjusted, weights, 1.0, 1.0, factors)

	if gotV20.Total != wantV20.Total {
		t.Fatalf("SSAMV20Formula: 注入后 %v != 默认在修正后域分上 %v", gotV20.Total, wantV20.Total)
	}
	if gotEval != wantEval {
		t.Fatalf("EvalAST: 注入后 %v != 默认在修正后域分上 %v", gotEval, wantEval)
	}
	if gotCompiled != wantCompiled {
		t.Fatalf("ASTToFormula: 注入后 %v != 默认在修正后域分上 %v", gotCompiled, wantCompiled)
	}
	if gotWeightedSum != wantWeightedSum {
		t.Fatalf("evalWeightedSum: 注入后 %v != 默认在修正后域分上 %v", gotWeightedSum, wantWeightedSum)
	}
	if gotCompiledWS != wantCompiledWS {
		t.Fatalf("编译路径 weighted_sum: 注入后 %v != 默认在修正后域分上 %v", gotCompiledWS, wantCompiledWS)
	}

	// 字面量锚定：修正后域分确实进入了各条路径（不是空转）。
	if gotWeightedSum != legacyWeightedSumAdjusted {
		t.Fatalf("evalWeightedSum(注入) = %v, want %v", gotWeightedSum, legacyWeightedSumAdjusted)
	}
	if gotCompiledWS != legacyWeightedSumAdjusted {
		t.Fatalf("编译路径 weighted_sum(注入) = %v, want %v", gotCompiledWS, legacyWeightedSumAdjusted)
	}
	if gotEval != legacyV20ASTAdjusted {
		t.Fatalf("EvalAST(注入) = %v, want %v", gotEval, legacyV20ASTAdjusted)
	}
	if gotCompiled != legacyV20ASTAdjusted {
		t.Fatalf("ASTToFormula(注入) = %v, want %v", gotCompiled, legacyV20ASTAdjusted)
	}
	if gotWeightedSum == legacyWeightedSumValue {
		t.Fatalf("加权和未反映域级修正: %v", gotWeightedSum)
	}
	if gotEval == legacyCompiledV20AST || gotCompiled == legacyCompiledV20AST {
		t.Fatalf("AST 路径未反映域级修正: EvalAST=%v ASTToFormula=%v", gotEval, gotCompiled)
	}
}

// TestDomainAdjustReceivesFactorsAndKindInputContract：钩子收到全部域分与本次
// 边缘因子；钩子就地修改入参不会污染调用方的域分切片（生产引擎在公式调用后
// 仍复用同一切片做后验统计与输出）。
func TestDomainAdjustInputContractAndNoCallerMutation(t *testing.T) {
	defer RegisterDomainAdjust(nil)

	scores, weights, riskCtx, factors := domainAdjustFixture()
	snapshot := append([]DomainScore(nil), scores...)
	baseline := SSAMV20Formula(scores, weights, riskCtx, factors)

	var seenDomains, seenFactors int
	RegisterDomainAdjust(func(ds []DomainScore, fs []EdgeFactorResult) []DomainScore {
		seenDomains = len(ds)
		seenFactors = len(fs)
		if len(ds) > 0 {
			ds[0].Score = 0 // 就地修改：只应影响本次聚合
		}
		return ds
	})

	got := SSAMV20Formula(scores, weights, riskCtx, factors)
	if seenDomains != len(scores) {
		t.Fatalf("钩子收到 %d 个域分, want %d", seenDomains, len(scores))
	}
	if seenFactors != len(factors) {
		t.Fatalf("钩子收到 %d 个边缘因子, want %d", seenFactors, len(factors))
	}
	if got.Total == baseline.Total {
		t.Fatalf("钩子就地修改未进入聚合: total 仍为 %v", got.Total)
	}
	if !reflect.DeepEqual(scores, snapshot) {
		t.Fatalf("钩子就地修改污染了调用方域分:\n got %+v\nwant %+v", scores, snapshot)
	}
}

// TestDomainAdjustEmptyResultYieldsZeroTotal：钩子返回空切片即「无域分参与聚合」，
// 行为与旧实现在空域分输入下完全一致（显式钉住，不做事后静默回退）。
func TestDomainAdjustEmptyResultYieldsZeroTotal(t *testing.T) {
	defer RegisterDomainAdjust(nil)

	scores, weights, riskCtx, factors := domainAdjustFixture()
	RegisterDomainAdjust(func([]DomainScore, []EdgeFactorResult) []DomainScore { return nil })

	got := SSAMV20Formula(scores, weights, riskCtx, factors)
	if got.Total != 0 {
		t.Fatalf("钩子返回空切片时总分 = %v, want 0", got.Total)
	}
	if want := legacySSAMV20Formula(nil, weights, riskCtx, factors); !reflect.DeepEqual(got, want) {
		t.Fatalf("空域分行为与旧实现不一致:\n got %+v\nwant %+v", got, want)
	}
}

// TestDomainAdjustNilRestoresBitIdenticalDefault：RegisterDomainAdjust(nil) 必须
// 让生产公式逐位回到默认（乘性、无域级修正）。
func TestDomainAdjustNilRestoresBitIdenticalDefault(t *testing.T) {
	defer RegisterDomainAdjust(nil)

	scores, weights, riskCtx, factors := domainAdjustFixture()

	RegisterDomainAdjust(halfAttackSurfaceAdjust)
	if got := SSAMV20Formula(scores, weights, riskCtx, factors).Total; got != legacyV20TotalAdjusted {
		t.Fatalf("注入后总分 = %v, want %v", got, legacyV20TotalAdjusted)
	}

	RegisterDomainAdjust(nil)

	got := SSAMV20Formula(scores, weights, riskCtx, factors)
	if want := legacySSAMV20Formula(scores, weights, riskCtx, factors); !reflect.DeepEqual(got, want) {
		t.Fatalf("重置后结果与旧实现不一致:\n got %+v\nwant %+v", got, want)
	}
	if got.Total != legacyV20Total {
		t.Fatalf("重置后总分 = %v, want %v", got.Total, legacyV20Total)
	}
	if gotWeightedSum := evalWeightedSum(EvalContext{DomainScores: scores, Weights: weights, EdgeFactors: factors}); gotWeightedSum != legacyWeightedSum(scores, weights) {
		t.Fatalf("重置后 evalWeightedSum = %v, want %v", gotWeightedSum, legacyWeightedSum(scores, weights))
	}
}

// TestDomainAdjustDefaultIsBitIdenticalToLegacy 是硬要求（默认逐位一致）的回归护栏：
// 未注册任何钩子时，三条评分路径与端到端 ComputeScoreV2 必须与改造前逐位相同。
func TestDomainAdjustDefaultIsBitIdenticalToLegacy(t *testing.T) {
	defer RegisterDomainAdjust(nil)
	RegisterDomainAdjust(nil) // 显式保证「未注册」

	scores, weights, riskCtx, factors := domainAdjustFixture()
	ctx := EvalContext{DomainScores: scores, Weights: weights, RiskContext: riskCtx, EdgeFactors: factors}

	got := SSAMV20Formula(scores, weights, riskCtx, factors)
	if want := legacySSAMV20Formula(scores, weights, riskCtx, factors); !reflect.DeepEqual(got, want) {
		t.Fatalf("SSAMV20Formula 与旧实现不一致:\n got %+v\nwant %+v", got, want)
	}
	if got.Total != legacyV20Total {
		t.Fatalf("SSAMV20Formula total = %v, want %v", got.Total, legacyV20Total)
	}

	if gotWS := evalWeightedSum(ctx); gotWS != legacyWeightedSum(scores, weights) || gotWS != legacyWeightedSumValue {
		t.Fatalf("evalWeightedSum = %v, want %v", gotWS, legacyWeightedSumValue)
	}
	if gotEval, err := EvalAST(SSAMV20AST(), ctx); err != nil || gotEval != legacyCompiledV20AST {
		t.Fatalf("EvalAST = %v (err=%v), want %v", gotEval, err, legacyCompiledV20AST)
	}
	if gotCompiled := ASTToFormula(SSAMV20AST())(scores, weights, riskCtx.Threat, riskCtx.Exposure, factors); gotCompiled != legacyCompiledV20AST {
		t.Fatalf("ASTToFormula = %v, want %v", gotCompiled, legacyCompiledV20AST)
	}

	out, err := ComputeScoreV2(ScoringConfig{Weights: DefaultWeights, FormulaID: "ssam_v2.0"}, domainAdjustInputV2())
	if err != nil {
		t.Fatalf("ComputeScoreV2: %v", err)
	}
	if out.FinalScore.Total != legacyComputeScoreV2Total {
		t.Fatalf("ComputeScoreV2 total = %v, want %v", out.FinalScore.Total, legacyComputeScoreV2Total)
	}
}

// TestDomainAdjustRegistrationIsConcurrencySafe 并发注入/重置 + 并发评分，
// 结果必须是两个已知确定性取值之一（配合 -race 更有意义；本机无 cgo 时退化为冒烟）。
func TestDomainAdjustRegistrationIsConcurrencySafe(t *testing.T) {
	defer RegisterDomainAdjust(nil)

	scores, weights, riskCtx, factors := domainAdjustFixture()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if i%2 == 0 {
					if j%2 == 0 {
						RegisterDomainAdjust(halfAttackSurfaceAdjust)
					} else {
						RegisterDomainAdjust(nil)
					}
					continue
				}
				got := SSAMV20Formula(scores, weights, riskCtx, factors).Total
				if got != legacyV20Total && got != legacyV20TotalAdjusted {
					t.Errorf("并发评分读到未定义结果: %v", got)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	RegisterDomainAdjust(nil)
	if got := SSAMV20Formula(scores, weights, riskCtx, factors).Total; got != legacyV20Total {
		t.Fatalf("并发测试结束后总分 = %v, want %v", got, legacyV20Total)
	}
}

// ---------------------------------------------------------------------------
// 生产公式必须经过边缘因子合成策略的统一入口（缺口 1）
// ---------------------------------------------------------------------------

// TestProductionFormulaDefaultKeepsSequentialMultiplyOrder 钉住默认路径的**算术顺序**：
// IEEE754 乘法不满足结合律，「逐次 base*=f」与「base*(f1*f2*…)」在取整半格边界上
// 会给出不同的可观测结果。本用例的基分与因子组合恰好落在 0.025 的边界上：
//
//	顺序连乘 = 0.02499999999999999  → 取整 0.02 → 总分 50.01
//	单次乘积 = 0.024999999999999998 → 取整 0.03 → 总分 50.02
//
// 因此默认（未注入策略）路径必须保留逐次相乘的历史顺序，而非 base*乘积。
func TestProductionFormulaDefaultKeepsSequentialMultiplyOrder(t *testing.T) {
	defer RegisterEdgeFactorStrategy(nil)
	defer RegisterDomainAdjust(nil)
	RegisterEdgeFactorStrategy(nil)
	RegisterDomainAdjust(nil)

	scores := []DomainScore{{Domain: "attack_surface", Score: 0.09222116928185753}}
	weights := []WeightConfig{{Domain: "attack_surface", Weight: 1}}
	factors := []EdgeFactorResult{
		{ID: "EF-A", Factor: 0.537, Active: true},
		{ID: "EF-B", Factor: 0.887, Active: true},
		{ID: "EF-C", Factor: 0.915, Active: true},
		{ID: "EF-D", Factor: 0.622, Active: true},
	}
	riskCtx := RiskContext{Intrinsic: 1, Exposure: 1, Threat: 1}

	got := SSAMV20Formula(scores, weights, riskCtx, factors)
	if got.Total != 50.01 {
		t.Fatalf("默认路径总分 = %v, want 50.01（逐次相乘的历史顺序）", got.Total)
	}
	if want := legacySSAMV20Formula(scores, weights, riskCtx, factors); !reflect.DeepEqual(got, want) {
		t.Fatalf("默认路径与旧实现不一致:\n got %+v\nwant %+v", got, want)
	}

	// 注入策略时按「总分乘子单次作用」，语义仍为 base*乘子：
	// 基分 0.09222116928185753 原样保留 → 取整 0.09 → 总分 50.05。
	RegisterEdgeFactorStrategy(func([]EdgeFactorResult) float64 { return 1.0 })
	if injected := SSAMV20Formula(scores, weights, riskCtx, factors); injected.Total != 50.05 {
		t.Fatalf("注入乘子 1.0 后总分 = %v, want 50.05（基分未被因子缩放）", injected.Total)
	}
}

// TestProductionFormulaUsesInjectedEdgeFactorStrategy：注入总分乘子策略后，
// 生产评分公式 SSAMV20Formula 的总分必须随策略变化（此前它自己内联连乘，绕过统一入口）。
func TestProductionFormulaUsesInjectedEdgeFactorStrategy(t *testing.T) {
	defer RegisterEdgeFactorStrategy(nil)
	defer RegisterDomainAdjust(nil)

	scores, weights, riskCtx, factors := domainAdjustFixture()

	baseline := SSAMV20Formula(scores, weights, riskCtx, factors)
	if baseline.Total != legacyV20Total {
		t.Fatalf("未注入时总分 = %v, want %v", baseline.Total, legacyV20Total)
	}

	// 策略返回 1.0 = 取消边缘因子惩罚。基分 80.75 → intrinsic 0.8075
	// → total = (0.8075*50 + 0.8*30 + 0.9*20)/100*100 = 82.375 → 82.38
	RegisterEdgeFactorStrategy(func([]EdgeFactorResult) float64 { return 1.0 })
	got := SSAMV20Formula(scores, weights, riskCtx, factors)
	if got.Total == baseline.Total {
		t.Fatalf("生产公式未经过统一入口：注入策略后总分仍为 %v", got.Total)
	}
	if got.Total != 82.38 {
		t.Fatalf("注入乘子 1.0 后总分 = %v, want 82.38", got.Total)
	}
	if got.Layers.Intrinsic.Coeff != 0.81 {
		t.Fatalf("注入乘子 1.0 后 intrinsic 系数 = %v, want 0.81", got.Layers.Intrinsic.Coeff)
	}
	// 贡献者列表仍列出参与合成的激活因子（保持默认路径逐位一致）。
	wantContributors := []string{"domain_scores", "edge_factor:EF-002FA", "edge_factor:EF-SYNCOOKIE"}
	if !reflect.DeepEqual(got.Layers.Intrinsic.Contributors, wantContributors) {
		t.Fatalf("贡献者 = %v, want %v", got.Layers.Intrinsic.Contributors, wantContributors)
	}

	// 策略返回 0.5 = 单次作用（不是与默认乘性叠加）。
	// 80.75*0.5 = 40.375 → round2 40.38 → intrinsic 0.4038
	// → total = (0.4038*50 + 24 + 18) = 62.19
	RegisterEdgeFactorStrategy(func([]EdgeFactorResult) float64 { return 0.5 })
	if gotHalf := SSAMV20Formula(scores, weights, riskCtx, factors); gotHalf.Total != 62.19 {
		t.Fatalf("注入乘子 0.5 后总分 = %v, want 62.19", gotHalf.Total)
	}

	// 重置后逐位回到默认。
	RegisterEdgeFactorStrategy(nil)
	if gotReset := SSAMV20Formula(scores, weights, riskCtx, factors); !reflect.DeepEqual(gotReset, baseline) {
		t.Fatalf("重置策略后与默认结果不一致:\n got %+v\nwant %+v", gotReset, baseline)
	}
}

// TestProductionFormulaDefaultIsBitIdenticalToLegacy 用确定性随机输入逐例比较
// 「走统一入口的新实现」与「内联逐次连乘的旧实现」的完整 FinalScore：
// 未注册任何钩子时必须逐位一致（IEEE754 乘法不满足结合律，这里用差分测试钉住）。
func TestProductionFormulaDefaultIsBitIdenticalToLegacy(t *testing.T) {
	defer RegisterEdgeFactorStrategy(nil)
	defer RegisterDomainAdjust(nil)
	RegisterEdgeFactorStrategy(nil)
	RegisterDomainAdjust(nil)

	rng := rand.New(rand.NewSource(20260908))
	domains := []string{"attack_surface", "business_continuity", "operation_trust", "resilience"}

	for i := 0; i < 20000; i++ {
		scores := make([]DomainScore, 0, len(domains))
		for _, d := range domains {
			scores = append(scores, DomainScore{Domain: d, Score: float64(rng.Intn(10001)) / 100})
		}

		factorCount := rng.Intn(5)
		factors := make([]EdgeFactorResult, 0, factorCount)
		for j := 0; j < factorCount; j++ {
			factors = append(factors, EdgeFactorResult{
				ID:     "EF-" + string(rune('A'+j)),
				Factor: float64(rng.Intn(1000)) / 1000,
				Active: rng.Intn(4) != 0,
			})
		}

		riskCtx := RiskContext{
			Exposure: float64(rng.Intn(2001)) / 1000,
			Threat:   float64(rng.Intn(2001)) / 1000,
		}

		got := SSAMV20Formula(scores, DefaultWeights, riskCtx, factors)
		want := legacySSAMV20Formula(scores, DefaultWeights, riskCtx, factors)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("case %d 默认路径与旧实现不一致:\n inputs domainScores=%+v riskCtx=%+v edgeFactors=%+v\n got %+v\nwant %+v",
				i, scores, riskCtx, factors, got, want)
		}
	}
}
