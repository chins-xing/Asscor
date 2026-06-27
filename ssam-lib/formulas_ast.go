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
	// Weighted average of three layers:
	// FinalScore = intrinsicCoeff * 50 + max(exposure,0.60) * 30 + max(threat,0.60) * 20
	// where intrinsicCoeff = weighted_sum * product_chain / 100
	//
	// add(
	//   add(
	//     multiply(multiply(weighted_sum, product_chain), const(0.50)),
	//     multiply(max(ref("exposure"), const(0.60)), const(30))
	//   ),
	//   multiply(max(ref("threat"), const(0.60)), const(20))
	// )
	return FormulaAST{
		Op: OpAdd,
		Left: &FormulaAST{
			Op: OpAdd,
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
					Op:    OpConst,
					Const: 0.50,
				},
			},
			Right: &FormulaAST{
				Op: OpMultiply,
				Left: &FormulaAST{
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
				Right: &FormulaAST{
					Op:    OpConst,
					Const: 30,
				},
			},
		},
		Right: &FormulaAST{
			Op: OpMultiply,
			Left: &FormulaAST{
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
			Right: &FormulaAST{
				Op:    OpConst,
				Const: 20,
			},
		},
	}
}
