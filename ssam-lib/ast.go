package ssam

import (
	"fmt"
	"math"
	"strings"
	"sync"
)

const (
	OpWeightedSum  = "weighted_sum"
	OpMultiply     = "multiply"
	OpDivide       = "divide"
	OpAdd          = "add"
	OpMin          = "min"
	OpMax          = "max"
	OpProductChain = "product_chain"
	OpRef          = "ref"
	OpConst        = "const"
)

type FormulaAST struct {
	Op    string      `json:"op"`
	Left  *FormulaAST `json:"left,omitempty"`
	Right *FormulaAST `json:"right,omitempty"`
	Ref   string      `json:"ref,omitempty"`
	Const float64     `json:"const,omitempty"`
}

type EvalContext struct {
	DomainScores []DomainScore
	Weights      []WeightConfig
	RiskContext  RiskContext
	EdgeFactors  []EdgeFactorResult
}

func EvalAST(ast FormulaAST, ctx EvalContext) (float64, error) {
	switch ast.Op {
	case OpConst:
		return ast.Const, nil

	case OpRef:
		return evalRef(ast.Ref, ctx)

	case OpWeightedSum:
		return evalWeightedSum(ctx), nil

	case OpProductChain:
		return applyEdgeFactorStrategy(ctx), nil

	case OpMultiply:
		if ast.Left == nil {
			return 0, fmt.Errorf("ssam: multiply: left operand is nil")
		}
		if ast.Right == nil {
			return 0, fmt.Errorf("ssam: multiply: right operand is nil")
		}
		left, err := EvalAST(*ast.Left, ctx)
		if err != nil {
			return 0, err
		}
		right, err := EvalAST(*ast.Right, ctx)
		if err != nil {
			return 0, err
		}
		return left * right, nil

	case OpAdd:
		if ast.Left == nil {
			return 0, fmt.Errorf("ssam: add: left operand is nil")
		}
		if ast.Right == nil {
			return 0, fmt.Errorf("ssam: add: right operand is nil")
		}
		left, err := EvalAST(*ast.Left, ctx)
		if err != nil {
			return 0, err
		}
		right, err := EvalAST(*ast.Right, ctx)
		if err != nil {
			return 0, err
		}
		return left + right, nil

	case OpDivide:
		if ast.Left == nil {
			return 0, fmt.Errorf("ssam: divide: left operand is nil")
		}
		if ast.Right == nil {
			return 0, fmt.Errorf("ssam: divide: right operand is nil")
		}
		left, err := EvalAST(*ast.Left, ctx)
		if err != nil {
			return 0, err
		}
		right, err := EvalAST(*ast.Right, ctx)
		if err != nil {
			return 0, err
		}
		if math.Abs(right) < 1e-12 {
			return 0, nil
		}
		return left / right, nil

	case OpMin:
		if ast.Left == nil {
			return 0, fmt.Errorf("ssam: min: left operand is nil")
		}
		if ast.Right == nil {
			return 0, fmt.Errorf("ssam: min: right operand is nil")
		}
		left, err := EvalAST(*ast.Left, ctx)
		if err != nil {
			return 0, err
		}
		right, err := EvalAST(*ast.Right, ctx)
		if err != nil {
			return 0, err
		}
		if left < right {
			return left, nil
		}
		return right, nil

	case OpMax:
		if ast.Left == nil {
			return 0, fmt.Errorf("ssam: max: left operand is nil")
		}
		if ast.Right == nil {
			return 0, fmt.Errorf("ssam: max: right operand is nil")
		}
		left, err := EvalAST(*ast.Left, ctx)
		if err != nil {
			return 0, err
		}
		right, err := EvalAST(*ast.Right, ctx)
		if err != nil {
			return 0, err
		}
		if left > right {
			return left, nil
		}
		return right, nil

	default:
		return 0, fmt.Errorf("ssam: unknown op: %s", ast.Op)
	}
}

func evalRef(ref string, ctx EvalContext) (float64, error) {
	switch {
	case ref == "exposure":
		return ctx.RiskContext.Exposure, nil
	case ref == "threat":
		return ctx.RiskContext.Threat, nil
	case ref == "intrinsic":
		return ctx.RiskContext.Intrinsic, nil
	case strings.HasPrefix(ref, "domain_score:"):
		domain := strings.TrimPrefix(ref, "domain_score:")
		for _, ds := range ctx.DomainScores {
			if ds.Domain == domain {
				return ds.Score, nil
			}
		}
		return 0, fmt.Errorf("ssam: ref domain_score not found: %s", domain)
	case strings.HasPrefix(ref, "weight:"):
		domain := strings.TrimPrefix(ref, "weight:")
		for _, w := range ctx.Weights {
			if w.Domain == domain {
				return w.Weight, nil
			}
		}
		return 0, fmt.Errorf("ssam: ref weight not found: %s", domain)
	default:
		return 0, fmt.Errorf("ssam: unknown ref: %s", ref)
	}
}

func evalWeightedSum(ctx EvalContext) float64 {
	wMap := BuildWeightMap(ctx.Weights)

	sum := 0.0
	totalWeight := 0.0
	for _, ds := range ctx.DomainScores {
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

// evalProductChain 是默认合成策略的实现（历史行为：仅对 Active 且在 (0,1) 内的因子连乘）。
// 保留为包级函数，既有测试可直接调用。
func evalProductChain(ctx EvalContext) float64 {
	result := 1.0
	for _, f := range ctx.EdgeFactors {
		if f.Active && f.Factor > 0 && f.Factor < 1.0 {
			result *= f.Factor
		}
	}
	return result
}

// EdgeFactorStrategy 决定多个激活因子如何合成为总乘子。
type EdgeFactorStrategy func(factors []EdgeFactorResult) float64

var (
	strategyMu         sync.RWMutex
	edgeFactorStrategy EdgeFactorStrategy = evalProductChainStrategy
)

// DefaultEdgeFactorStrategy 是默认（乘性连乘）策略的只读句柄。
// 注意：恢复默认请调用 RegisterEdgeFactorStrategy(nil)；重写本变量不会改变内部默认，
// 内部默认始终是 evalProductChainStrategy。
var DefaultEdgeFactorStrategy EdgeFactorStrategy = evalProductChainStrategy

func evalProductChainStrategy(factors []EdgeFactorResult) float64 {
	result := 1.0
	for _, f := range factors {
		if f.Active && f.Factor > 0 && f.Factor < 1.0 {
			result *= f.Factor
		}
	}
	return result
}

// RegisterEdgeFactorStrategy 注入自定义合成策略；nil 恢复默认乘性连乘。
// 默认路径与历史行为逐位一致（spec §3.3）。
func RegisterEdgeFactorStrategy(s EdgeFactorStrategy) {
	strategyMu.Lock()
	defer strategyMu.Unlock()
	if s == nil {
		edgeFactorStrategy = evalProductChainStrategy
		return
	}
	edgeFactorStrategy = s
}

// ValidateStrategy 报告合成策略是否可调用（装配根自检用）。
func ValidateStrategy() error {
	if currentStrategy() == nil {
		return fmt.Errorf("ssam: edge factor strategy is not callable")
	}
	return nil
}

func currentStrategy() EdgeFactorStrategy {
	strategyMu.RLock()
	defer strategyMu.RUnlock()
	return edgeFactorStrategy
}

// applyEdgeFactorStrategy 是内部统一入口：公式求值处改调本函数。
func applyEdgeFactorStrategy(ctx EvalContext) float64 {
	return currentStrategy()(ctx.EdgeFactors)
}

type compiledOp struct {
	op    string
	left  int
	right int
	ref   string
	constVal float64
}

func ASTToFormula(ast FormulaAST) ScoringFormula {
	ops := compileAST(ast)

	return func(domainScores []DomainScore, weights []WeightConfig, threatCoeff float64, spcScore float64, edgeFactors []EdgeFactorResult) float64 {
		wMap := BuildWeightMap(weights)

		stack := make([]float64, 0, len(ops))

		pushValue := func(v float64) {
			stack = append(stack, v)
		}
		pop := func() float64 {
			if len(stack) == 0 {
				return 0
			}
			v := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			return v
		}

		for _, op := range ops {
			switch op.op {
			case OpConst:
				pushValue(op.constVal)

			case OpRef:
				switch op.ref {
				case "exposure":
					pushValue(spcScore)
				case "threat":
					pushValue(threatCoeff)
				case "intrinsic":
					pushValue(1.0)
				default:
					if strings.HasPrefix(op.ref, "domain_score:") {
						domain := strings.TrimPrefix(op.ref, "domain_score:")
						found := false
						for _, ds := range domainScores {
							if ds.Domain == domain {
								pushValue(ds.Score)
								found = true
								break
							}
						}
						if !found {
							pushValue(0)
						}
					} else if strings.HasPrefix(op.ref, "weight:") {
						domain := strings.TrimPrefix(op.ref, "weight:")
						if w, ok := wMap[domain]; ok {
							pushValue(w)
						} else {
							pushValue(0)
						}
					} else {
						pushValue(0)
					}
				}

			case OpWeightedSum:
				sum := 0.0
				totalWeight := 0.0
				for _, ds := range domainScores {
					if w, ok := wMap[ds.Domain]; ok && w > 0 {
						sum += ds.Score * w
						totalWeight += w
					}
				}
				if totalWeight == 0 {
					pushValue(0)
				} else {
					pushValue(sum / totalWeight)
				}

			case OpProductChain:
				// 与 EvalAST 走同一策略入口，注入的策略对编译路径同样生效；
				// 默认策略实现与原先的内联循环逐位一致。
				pushValue(applyEdgeFactorStrategy(EvalContext{EdgeFactors: edgeFactors}))

			case OpMultiply:
				right := pop()
				left := pop()
				pushValue(left * right)

			case OpDivide:
				right := pop()
				left := pop()
				if math.Abs(right) < 1e-12 {
					pushValue(0)
				} else {
					pushValue(left / right)
				}

			case OpAdd:
				right := pop()
				left := pop()
				pushValue(left + right)

			case OpMin:
				right := pop()
				left := pop()
				if left < right {
					pushValue(left)
				} else {
					pushValue(right)
				}

			case OpMax:
				right := pop()
				left := pop()
				if left > right {
					pushValue(left)
				} else {
					pushValue(right)
				}

			default:
				pushValue(0)
			}
		}

		if len(stack) == 0 {
			return 0
		}
		return stack[len(stack)-1]
	}
}

func compileAST(ast FormulaAST) []compiledOp {
	ops := make([]compiledOp, 0)

	switch ast.Op {
	case OpConst:
		ops = append(ops, compiledOp{op: OpConst, constVal: ast.Const})

	case OpRef:
		ops = append(ops, compiledOp{op: OpRef, ref: ast.Ref})

	case OpWeightedSum:
		ops = append(ops, compiledOp{op: OpWeightedSum})

	case OpProductChain:
		ops = append(ops, compiledOp{op: OpProductChain})

	case OpMultiply, OpDivide, OpAdd, OpMin, OpMax:
		if ast.Left != nil {
			ops = append(ops, compileAST(*ast.Left)...)
		}
		if ast.Right != nil {
			ops = append(ops, compileAST(*ast.Right)...)
		}
		ops = append(ops, compiledOp{op: ast.Op})

	default:
		ops = append(ops, compiledOp{op: OpConst, constVal: 0})
	}

	return ops
}
