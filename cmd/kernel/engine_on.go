//go:build engine

package main

import (
	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/engine"
	ascorprism "github.com/chins-xing/asscor/internal/engine/prism"
	"github.com/chins-xing/asscor/internal/engine/ssam"
	"github.com/chins-xing/asscor/internal/kernel"
	"github.com/chins-xing/asscor/internal/logger"
)

// newSSAMEngineAdapter returns the SSAM algorithm engine adapter, or nil when
// the engine build tag is disabled.
//
// 装配根职责（Task 7）：边缘因子合成模型由适配器构造函数按**同一份** cfg 装配
// （`ApplyEdgeFactorModel`），这里只做启动期自检。为什么不在这里装配：两个钩子都是
// 内仓的**进程级全局状态**，只在这个装配根装一次的话，任何别的构造路径（测试、离线工具、
// 未来的第二个适配器）都会漏装 —— 漏装的后果不是报错，而是评分悄悄用了上一个模型的参数。
func newSSAMEngineAdapter(cfg *config.Config) kernel.AssessorEngine {
	adapter := ssam.NewEngineAdapter(cfg)
	// 自检：无论走默认路径（零注册）还是启用路径，策略句柄都必须可调用，
	// 否则评分会在公式求值处 panic 而不是给出一个可解释的结果。
	if err := ssam.ValidateEdgeFactorStrategy(); err != nil {
		logger.WithComponent("kernel").Error(
			"edge factor strategy is not callable after assembly", "error", err)
	}
	return adapter
}

// newPrismEngine returns the Prism risk-dynamics engine, or nil when the
// engine build tag is disabled.
func newPrismEngine() kernel.PrismEngineProvider {
	return ascorprism.NewEngine()
}

// newEngineScorer returns the concrete scoring engine implementation injected
// into the assessor module. It lives in this engine-tagged file so the
// assessor module itself never imports the engine package.
func newEngineScorer(cfg *config.Config) kernel.EngineScorer {
	return engine.NewAssessor(cfg)
}
