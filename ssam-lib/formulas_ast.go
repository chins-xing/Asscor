package ssam

func SSAMV12AST() FormulaAST {
	return FormulaAST{
		Op: OpMultiply,
		Left: &FormulaAST{
			Op: OpMultiply,
			Left: &FormulaAST{
				Op: OpMultiply,
				Left: &FormulaAST{
					Op: OpWeightedSum,
				},
				Right: &FormulaAST{
					Op:  OpRef,
					Ref: "threat",
				},
			},
			Right: &FormulaAST{
				Op:  OpRef,
				Ref: "exposure",
			},
		},
		Right: &FormulaAST{
			Op: OpProductChain,
		},
	}
}

func SSAMV20AST() FormulaAST {
	return FormulaAST{
		Op: OpMultiply,
		Left: &FormulaAST{
			Op: OpMultiply,
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
					Const: 0.60,
				},
			},
		},
		Right: &FormulaAST{
			Op: OpMax,
			Left: &FormulaAST{
				Op:  OpRef,
				Ref: "threat",
			},
			Right: &FormulaAST{
				Op:    OpConst,
				Const: 0.60,
			},
		},
	}
}
