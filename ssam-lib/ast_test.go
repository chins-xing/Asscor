package ssam

import (
	"math"
	"testing"
)

func TestSSAMV12AST_MatchesFormula(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "business_continuity", Score: 90},
		{Domain: "operation_trust", Score: 70},
		{Domain: "resilience", Score: 85},
	}
	weights := DefaultWeights

	tests := []struct {
		name        string
		threatCoeff float64
		spcScore    float64
		edgeFactors []EdgeFactorResult
	}{
		{"no_coeffs_no_edges", 1.0, 1.0, nil},
		{"with_threat", 0.90, 1.0, nil},
		{"with_spc", 1.0, 0.80, nil},
		{"with_both_coeffs", 0.90, 0.80, nil},
		{"with_edge_factors", 1.0, 1.0, []EdgeFactorResult{
			{ID: "EF-002FA", Factor: 0.85, Active: true},
			{ID: "EF-SELINUX", Factor: 0.80, Active: false},
		}},
		{"full_combo", 0.90, 0.80, []EdgeFactorResult{
			{ID: "EF-002FA", Factor: 0.85, Active: true},
			{ID: "EF-SYNCOOKIE", Factor: 0.75, Active: true},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			direct := SSAMV12Formula(scores, weights, tt.threatCoeff, tt.spcScore, tt.edgeFactors)

			ast := SSAMV12AST()
			ctx := EvalContext{
				DomainScores: scores,
				Weights:      weights,
				RiskContext:  RiskContext{Threat: tt.threatCoeff, Exposure: tt.spcScore, Intrinsic: 1.0},
				EdgeFactors:  tt.edgeFactors,
			}
			astResult, err := EvalAST(ast, ctx)
			if err != nil {
				t.Fatalf("EvalAST failed: %v", err)
			}

			if math.Abs(direct-astResult) > 0.02 {
				t.Errorf("V12 mismatch: direct=%.4f, ast=%.4f, diff=%.6f", direct, astResult, math.Abs(direct-astResult))
			}
		})
	}
}

func TestSSAMV20AST_MatchesFormula(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "business_continuity", Score: 90},
		{Domain: "operation_trust", Score: 70},
		{Domain: "resilience", Score: 85},
	}
	weights := DefaultWeights

	tests := []struct {
		name        string
		riskCtx     RiskContext
		edgeFactors []EdgeFactorResult
	}{
		{"no_coeffs_no_edges", RiskContext{Intrinsic: 1.0, Exposure: 1.0, Threat: 1.0}, nil},
		{"with_exposure", RiskContext{Intrinsic: 1.0, Exposure: 0.70, Threat: 1.0}, nil},
		{"with_threat", RiskContext{Intrinsic: 1.0, Exposure: 1.0, Threat: 0.90}, nil},
		{"with_both", RiskContext{Intrinsic: 1.0, Exposure: 0.70, Threat: 0.90}, nil},
		{"with_edge_factors", RiskContext{Intrinsic: 1.0, Exposure: 1.0, Threat: 1.0}, []EdgeFactorResult{
			{ID: "EF-002FA", Factor: 0.85, Active: true},
			{ID: "EF-SELINUX", Factor: 0.80, Active: false},
		}},
		{"full_combo", RiskContext{Intrinsic: 1.0, Exposure: 0.70, Threat: 0.90}, []EdgeFactorResult{
			{ID: "EF-002FA", Factor: 0.85, Active: true},
			{ID: "EF-SYNCOOKIE", Factor: 0.75, Active: true},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			direct := SSAMV20Formula(scores, weights, tt.riskCtx, tt.edgeFactors)

			ast := SSAMV20AST()
			ctx := EvalContext{
				DomainScores: scores,
				Weights:      weights,
				RiskContext:  tt.riskCtx,
				EdgeFactors:  tt.edgeFactors,
			}
			astResult, err := EvalAST(ast, ctx)
			if err != nil {
				t.Fatalf("EvalAST failed: %v", err)
			}

			if math.Abs(direct.Total-astResult) > 0.02 {
				t.Errorf("V20 mismatch: direct=%.4f, ast=%.4f, diff=%.6f", direct.Total, astResult, math.Abs(direct.Total-astResult))
			}
		})
	}
}

func TestSSAMV12AST_FullPassage(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 100},
		{Domain: "business_continuity", Score: 100},
		{Domain: "operation_trust", Score: 100},
		{Domain: "resilience", Score: 100},
	}
	weights := DefaultWeights

	ast := SSAMV12AST()
	ctx := EvalContext{
		DomainScores: scores,
		Weights:      weights,
		RiskContext:  RiskContext{Threat: 1.0, Exposure: 1.0, Intrinsic: 1.0},
		EdgeFactors:  nil,
	}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}
	if result != 100 {
		t.Errorf("V12 full passage: expected 100, got %.2f", result)
	}
}

func TestSSAMV20AST_FullPassage(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 100},
		{Domain: "business_continuity", Score: 100},
		{Domain: "operation_trust", Score: 100},
		{Domain: "resilience", Score: 100},
	}
	weights := DefaultWeights

	ast := SSAMV20AST()
	ctx := EvalContext{
		DomainScores: scores,
		Weights:      weights,
		RiskContext:  RiskContext{Intrinsic: 1.0, Exposure: 1.0, Threat: 1.0},
		EdgeFactors:  nil,
	}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}
	if result != 100 {
		t.Errorf("V20 full passage: expected 100, got %.2f", result)
	}
}

func TestASTCompile_MatchesEval(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "business_continuity", Score: 90},
		{Domain: "operation_trust", Score: 70},
		{Domain: "resilience", Score: 85},
	}
	weights := DefaultWeights
	edgeFactors := []EdgeFactorResult{
		{ID: "EF-002FA", Factor: 0.85, Active: true},
		{ID: "EF-SYNCOOKIE", Factor: 0.75, Active: true},
	}

	t.Run("V12", func(t *testing.T) {
		ast := SSAMV12AST()
		ctx := EvalContext{
			DomainScores: scores,
			Weights:      weights,
			RiskContext:  RiskContext{Threat: 0.90, Exposure: 0.80, Intrinsic: 1.0},
			EdgeFactors:  edgeFactors,
		}
		evalResult, err := EvalAST(ast, ctx)
		if err != nil {
			t.Fatalf("EvalAST failed: %v", err)
		}

		compiled := ASTToFormula(ast)
		compiledResult := compiled(scores, weights, 0.90, 0.80, edgeFactors)

		if math.Abs(evalResult-compiledResult) > 1e-10 {
			t.Errorf("V12 compile mismatch: eval=%.6f, compiled=%.6f", evalResult, compiledResult)
		}
	})

	t.Run("V20", func(t *testing.T) {
		ast := SSAMV20AST()
		ctx := EvalContext{
			DomainScores: scores,
			Weights:      weights,
			RiskContext:  RiskContext{Exposure: 0.70, Threat: 0.90, Intrinsic: 1.0},
			EdgeFactors:  edgeFactors,
		}
		evalResult, err := EvalAST(ast, ctx)
		if err != nil {
			t.Fatalf("EvalAST failed: %v", err)
		}

		compiled := ASTToFormula(ast)
		compiledResult := compiled(scores, weights, 0.90, 0.70, edgeFactors)

		if math.Abs(evalResult-compiledResult) > 1e-10 {
			t.Errorf("V20 compile mismatch: eval=%.6f, compiled=%.6f", evalResult, compiledResult)
		}
	})
}

func TestASTCompile_MatchesEval_CustomAST(t *testing.T) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 75},
		{Domain: "resilience", Score: 60},
	}
	weights := []WeightConfig{
		{Domain: "attack_surface", Weight: 50},
		{Domain: "resilience", Weight: 50},
	}
	edgeFactors := []EdgeFactorResult{
		{ID: "EF-002FA", Factor: 0.85, Active: true},
	}

	ast := FormulaAST{
		Op: OpDivide,
		Left: &FormulaAST{
			Op: OpMultiply,
			Left: &FormulaAST{
				Op: OpWeightedSum,
			},
			Right: &FormulaAST{
				Op: OpProductChain,
			},
		},
		Right: &FormulaAST{
			Op: OpMax,
			Left: &FormulaAST{
				Op:  OpRef,
				Ref: "exposure",
			},
			Right: &FormulaAST{
				Op:    OpConst,
				Const: 0.50,
			},
		},
	}

	ctx := EvalContext{
		DomainScores: scores,
		Weights:      weights,
		RiskContext:  RiskContext{Exposure: 0.70, Intrinsic: 1.0},
		EdgeFactors:  edgeFactors,
	}
	evalResult, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}

	compiled := ASTToFormula(ast)
	compiledResult := compiled(scores, weights, 1.0, 0.70, edgeFactors)

	if math.Abs(evalResult-compiledResult) > 1e-10 {
		t.Errorf("custom AST compile mismatch: eval=%.6f, compiled=%.6f", evalResult, compiledResult)
	}
}

func TestAST_UnknownOp(t *testing.T) {
	ast := FormulaAST{Op: "nonexistent_op"}
	ctx := EvalContext{}
	_, err := EvalAST(ast, ctx)
	if err == nil {
		t.Error("expected error for unknown op, got nil")
	}
}

func TestAST_EmptyAST(t *testing.T) {
	ast := FormulaAST{}
	ctx := EvalContext{}
	_, err := EvalAST(ast, ctx)
	if err == nil {
		t.Error("expected error for empty AST (no op), got nil")
	}
}

func TestAST_DeepNesting(t *testing.T) {
	ast := FormulaAST{
		Op:    OpConst,
		Const: 2.0,
	}
	for i := 0; i < 5; i++ {
		prev := ast
		ast = FormulaAST{
			Op: OpMultiply,
			Left: &FormulaAST{
				Op:    OpConst,
				Const: 2.0,
			},
			Right: &prev,
		}
	}

	ctx := EvalContext{}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed for deep nesting: %v", err)
	}

	expected := 64.0
	if math.Abs(result-expected) > 1e-10 {
		t.Errorf("deep nesting: expected %.0f, got %.6f", expected, result)
	}

	compiled := ASTToFormula(ast)
	compiledResult := compiled(nil, nil, 0, 0, nil)
	if math.Abs(compiledResult-expected) > 1e-10 {
		t.Errorf("deep nesting compiled: expected %.0f, got %.6f", expected, compiledResult)
	}
}

func TestAST_DivideByZero(t *testing.T) {
	ast := FormulaAST{
		Op: OpDivide,
		Left: &FormulaAST{
			Op:    OpConst,
			Const: 100.0,
		},
		Right: &FormulaAST{
			Op:    OpConst,
			Const: 0.0,
		},
	}

	ctx := EvalContext{}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST should not error on divide by zero: %v", err)
	}
	if result != 0 {
		t.Errorf("divide by zero: expected 0, got %.6f", result)
	}

	compiled := ASTToFormula(ast)
	compiledResult := compiled(nil, nil, 0, 0, nil)
	if compiledResult != 0 {
		t.Errorf("divide by zero compiled: expected 0, got %.6f", compiledResult)
	}
}

func TestAST_DivideByVerySmall(t *testing.T) {
	ast := FormulaAST{
		Op: OpDivide,
		Left: &FormulaAST{
			Op:    OpConst,
			Const: 100.0,
		},
		Right: &FormulaAST{
			Op:    OpConst,
			Const: 1e-13,
		},
	}

	ctx := EvalContext{}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}
	if result != 0 {
		t.Errorf("divide by very small: expected 0, got %.6f", result)
	}
}

func TestAST_MinOp(t *testing.T) {
	ast := FormulaAST{
		Op: OpMin,
		Left: &FormulaAST{
			Op:    OpConst,
			Const: 0.75,
		},
		Right: &FormulaAST{
			Op:    OpConst,
			Const: 0.90,
		},
	}

	ctx := EvalContext{}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}
	if math.Abs(result-0.75) > 1e-10 {
		t.Errorf("min: expected 0.75, got %.6f", result)
	}
}

func TestAST_MaxOp(t *testing.T) {
	ast := FormulaAST{
		Op: OpMax,
		Left: &FormulaAST{
			Op:    OpConst,
			Const: 0.75,
		},
		Right: &FormulaAST{
			Op:    OpConst,
			Const: 0.90,
		},
	}

	ctx := EvalContext{}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}
	if math.Abs(result-0.90) > 1e-10 {
		t.Errorf("max: expected 0.90, got %.6f", result)
	}
}

func TestAST_RefDomainScore(t *testing.T) {
	ast := FormulaAST{
		Op:  OpRef,
		Ref: "domain_score:attack_surface",
	}

	scores := []DomainScore{
		{Domain: "attack_surface", Score: 75},
		{Domain: "resilience", Score: 60},
	}
	ctx := EvalContext{DomainScores: scores}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}
	if math.Abs(result-75) > 1e-10 {
		t.Errorf("ref domain_score: expected 75, got %.6f", result)
	}
}

func TestAST_RefDomainScore_NotFound(t *testing.T) {
	ast := FormulaAST{
		Op:  OpRef,
		Ref: "domain_score:nonexistent",
	}

	ctx := EvalContext{}
	_, err := EvalAST(ast, ctx)
	if err == nil {
		t.Error("expected error for missing domain_score ref, got nil")
	}
}

func TestAST_RefWeight(t *testing.T) {
	ast := FormulaAST{
		Op:  OpRef,
		Ref: "weight:attack_surface",
	}

	weights := []WeightConfig{
		{Domain: "attack_surface", Weight: 35},
	}
	ctx := EvalContext{Weights: weights}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}
	if math.Abs(result-35) > 1e-10 {
		t.Errorf("ref weight: expected 35, got %.6f", result)
	}
}

func TestAST_RefExposure(t *testing.T) {
	ast := FormulaAST{
		Op:  OpRef,
		Ref: "exposure",
	}
	ctx := EvalContext{RiskContext: RiskContext{Exposure: 0.65}}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}
	if math.Abs(result-0.65) > 1e-10 {
		t.Errorf("ref exposure: expected 0.65, got %.6f", result)
	}
}

func TestAST_RefThreat(t *testing.T) {
	ast := FormulaAST{
		Op:  OpRef,
		Ref: "threat",
	}
	ctx := EvalContext{RiskContext: RiskContext{Threat: 0.85}}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}
	if math.Abs(result-0.85) > 1e-10 {
		t.Errorf("ref threat: expected 0.85, got %.6f", result)
	}
}

func TestAST_RefIntrinsic(t *testing.T) {
	ast := FormulaAST{
		Op:  OpRef,
		Ref: "intrinsic",
	}
	ctx := EvalContext{RiskContext: RiskContext{Intrinsic: 0.95}}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}
	if math.Abs(result-0.95) > 1e-10 {
		t.Errorf("ref intrinsic: expected 0.95, got %.6f", result)
	}
}

func TestAST_ProductChain_NoneActive(t *testing.T) {
	ast := FormulaAST{Op: OpProductChain}
	ctx := EvalContext{
		EdgeFactors: []EdgeFactorResult{
			{ID: "EF-SELINUX", Factor: 0.80, Active: false},
		},
	}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}
	if math.Abs(result-1.0) > 1e-10 {
		t.Errorf("product_chain none active: expected 1.0, got %.6f", result)
	}
}

func TestAST_ProductChain_Multiple(t *testing.T) {
	ast := FormulaAST{Op: OpProductChain}
	ctx := EvalContext{
		EdgeFactors: []EdgeFactorResult{
			{ID: "EF-002FA", Factor: 0.85, Active: true},
			{ID: "EF-SYNCOOKIE", Factor: 0.75, Active: true},
			{ID: "EF-SELINUX", Factor: 0.80, Active: false},
		},
	}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}
	expected := 0.85 * 0.75
	if math.Abs(result-expected) > 1e-10 {
		t.Errorf("product_chain: expected %.6f, got %.6f", expected, result)
	}
}

func TestAST_BinaryOpNilChildren(t *testing.T) {
	t.Run("multiply_left_nil", func(t *testing.T) {
		ast := FormulaAST{Op: OpMultiply}
		_, err := EvalAST(ast, EvalContext{})
		if err == nil {
			t.Error("expected error for nil left in multiply")
		}
	})

	t.Run("multiply_right_nil", func(t *testing.T) {
		ast := FormulaAST{
			Op: OpMultiply,
			Left: &FormulaAST{
				Op:    OpConst,
				Const: 1.0,
			},
		}
		_, err := EvalAST(ast, EvalContext{})
		if err == nil {
			t.Error("expected error for nil right in multiply")
		}
	})

	t.Run("divide_left_nil", func(t *testing.T) {
		ast := FormulaAST{Op: OpDivide}
		_, err := EvalAST(ast, EvalContext{})
		if err == nil {
			t.Error("expected error for nil left in divide")
		}
	})
}

func TestAST_WeightedSum_ZeroWeight(t *testing.T) {
	ast := FormulaAST{Op: OpWeightedSum}
	ctx := EvalContext{
		DomainScores: []DomainScore{{Domain: "attack_surface", Score: 100}},
		Weights:      []WeightConfig{{Domain: "attack_surface", Weight: 0}},
	}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}
	if result != 0 {
		t.Errorf("weighted_sum zero weight: expected 0, got %.6f", result)
	}
}

func TestAST_WeightedSum_ExtensionDomain(t *testing.T) {
	ast := FormulaAST{Op: OpWeightedSum}
	ctx := EvalContext{
		DomainScores: []DomainScore{
			{Domain: "attack_surface", Score: 80},
			{Domain: "kernel_security", Score: 50},
		},
		Weights: []WeightConfig{
			{Domain: "attack_surface", Weight: 35},
			{Domain: "kernel_security", Weight: 10},
		},
	}
	result, err := EvalAST(ast, ctx)
	if err != nil {
		t.Fatalf("EvalAST failed: %v", err)
	}
	expected := (80*35 + 50*10) / 45.0
	if math.Abs(result-expected) > 0.01 {
		t.Errorf("weighted_sum extension: expected %.2f, got %.2f", expected, result)
	}
}

func BenchmarkEvalAST_V12(b *testing.B) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "business_continuity", Score: 90},
		{Domain: "operation_trust", Score: 70},
		{Domain: "resilience", Score: 85},
	}
	weights := DefaultWeights
	edgeFactors := []EdgeFactorResult{
		{ID: "EF-002FA", Factor: 0.85, Active: true},
		{ID: "EF-SYNCOOKIE", Factor: 0.75, Active: true},
	}

	ast := SSAMV12AST()
	ctx := EvalContext{
		DomainScores: scores,
		Weights:      weights,
		RiskContext:  RiskContext{Threat: 0.90, Exposure: 0.80, Intrinsic: 1.0},
		EdgeFactors:  edgeFactors,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EvalAST(ast, ctx)
	}
}

func BenchmarkCompiled_V12(b *testing.B) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "business_continuity", Score: 90},
		{Domain: "operation_trust", Score: 70},
		{Domain: "resilience", Score: 85},
	}
	weights := DefaultWeights
	edgeFactors := []EdgeFactorResult{
		{ID: "EF-002FA", Factor: 0.85, Active: true},
		{ID: "EF-SYNCOOKIE", Factor: 0.75, Active: true},
	}

	compiled := ASTToFormula(SSAMV12AST())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compiled(scores, weights, 0.90, 0.80, edgeFactors)
	}
}

func BenchmarkEvalAST_V20(b *testing.B) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "business_continuity", Score: 90},
		{Domain: "operation_trust", Score: 70},
		{Domain: "resilience", Score: 85},
	}
	weights := DefaultWeights
	edgeFactors := []EdgeFactorResult{
		{ID: "EF-002FA", Factor: 0.85, Active: true},
		{ID: "EF-SYNCOOKIE", Factor: 0.75, Active: true},
	}

	ast := SSAMV20AST()
	ctx := EvalContext{
		DomainScores: scores,
		Weights:      weights,
		RiskContext:  RiskContext{Exposure: 0.70, Threat: 0.90, Intrinsic: 1.0},
		EdgeFactors:  edgeFactors,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EvalAST(ast, ctx)
	}
}

func BenchmarkCompiled_V20(b *testing.B) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "business_continuity", Score: 90},
		{Domain: "operation_trust", Score: 70},
		{Domain: "resilience", Score: 85},
	}
	weights := DefaultWeights
	edgeFactors := []EdgeFactorResult{
		{ID: "EF-002FA", Factor: 0.85, Active: true},
		{ID: "EF-SYNCOOKIE", Factor: 0.75, Active: true},
	}

	compiled := ASTToFormula(SSAMV20AST())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compiled(scores, weights, 0.90, 0.70, edgeFactors)
	}
}

func BenchmarkDirect_V12(b *testing.B) {
	scores := []DomainScore{
		{Domain: "attack_surface", Score: 80},
		{Domain: "business_continuity", Score: 90},
		{Domain: "operation_trust", Score: 70},
		{Domain: "resilience", Score: 85},
	}
	weights := DefaultWeights
	edgeFactors := []EdgeFactorResult{
		{ID: "EF-002FA", Factor: 0.85, Active: true},
		{ID: "EF-SYNCOOKIE", Factor: 0.75, Active: true},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SSAMV12Formula(scores, weights, 0.90, 0.80, edgeFactors)
	}
}
