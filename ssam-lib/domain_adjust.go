package ssam

import "sync"

// DomainAdjustFunc 在「按域聚合总分」之前对域分做域级修正。
//
// 语义：入参是本次评分的原始域分与边缘因子结果，返回值将**替代**原始域分参与聚合。
// 形如 Score_d' = Base_d · P_d 的逐域系数修正即由此表达。
//
// 契约：
//   - 入参切片是本次评分专用副本，实现可以就地修改；返回值给出用于聚合的域分。
//   - 返回空切片表示「无域分参与聚合」，随后按既有零权重分支处理（总分 0），
//     不做静默回退——调用方需对返回值负责。
//   - 未注册（或 RegisterDomainAdjust(nil)）时为恒等，公式直接使用原始域分，
//     与历史行为逐位一致。
//
// 与 EdgeFactorStrategy 的分工：EdgeFactorStrategy 只能返回一个作用于总分的乘子，
// 无法表达「每个域各自的系数」；域级修正属于聚合之前、域分层面的可注入点。
type DomainAdjustFunc func(domainScores []DomainScore, factors []EdgeFactorResult) []DomainScore

// DefaultDomainAdjust 是默认（恒等，不做任何修正）的实现句柄。
// 注意：恢复默认请调用 RegisterDomainAdjust(nil)；重写本变量不会改变内部默认，
// 内部默认始终是 nil（applyDomainAdjust 直接使用原始域分：零分配、逐位一致）。
var DefaultDomainAdjust DomainAdjustFunc = identityDomainAdjust

func identityDomainAdjust(domainScores []DomainScore, _ []EdgeFactorResult) []DomainScore {
	return domainScores
}

var (
	domainAdjustMu sync.RWMutex
	domainAdjust   DomainAdjustFunc // nil == 恒等（默认）
)

// RegisterDomainAdjust 注入域级修正；nil 恢复默认（不做任何修正）。
// 约定在装配期（启动时）注入、评分期读取，读写由内部锁保护。
func RegisterDomainAdjust(fn DomainAdjustFunc) {
	domainAdjustMu.Lock()
	defer domainAdjustMu.Unlock()
	domainAdjust = fn
}

func currentDomainAdjust() DomainAdjustFunc {
	domainAdjustMu.RLock()
	defer domainAdjustMu.RUnlock()
	return domainAdjust
}

// applyDomainAdjust 是域级修正的内部统一入口：所有「按域聚合」的公式求值处
// （SSAMV20Formula、EvalAST 的 weighted_sum、ASTToFormula 的编译路径）都调用本函数。
// fn 为 nil（默认）时原样返回入参切片，保证默认路径零分配且逐位不变。
func applyDomainAdjust(domainScores []DomainScore, factors []EdgeFactorResult) []DomainScore {
	fn := currentDomainAdjust()
	if fn == nil {
		return domainScores
	}
	// 传副本：钩子就地修改只影响本次聚合，不污染调用方切片
	// （生产引擎在公式调用后仍沿用原始域分做后验统计与输出）。
	work := make([]DomainScore, len(domainScores))
	copy(work, domainScores)
	return fn(work, factors)
}
