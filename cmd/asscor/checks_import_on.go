//go:build checks && engine

package main

import (
	"github.com/chins-xing/asscor/internal/checks"
	"github.com/chins-xing/asscor/internal/config"
	"github.com/chins-xing/asscor/internal/logger"
)

// registerUserChecks 把配置里的 `[user_check.*]` 注册进全局检查表。
//
// 为什么需要它：本文件此前只**空白导入** checks（触发内置检查的 init 注册），
// 但 `[user_check.*]` 的装配在 kernel 侧是**组合根**显式做的一步
// （`cmd/kernel/main.go`：`for _, item := range config.ParseUserChecks(...) { checks.Register(item) }`）。
// `asscor`（standalone / legacy 路径）漏了这一步 ⇒ 配置里的自定义检查**被解析但从不执行**：
// 实测加两条 `user_check` 后仍只有 80 条内置检查、`probe_*` 一条都不出现。
//
// 返回注册条数（0 表示配置里没有），供 main 输出一条可核对的日志。
func registerUserChecks(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	items := config.ParseUserChecks(cfg.AdapterConfig)
	if len(items) == 0 {
		return 0
	}
	checks.Register(items...)
	logger.WithComponent("main").Info("user-defined checks registered from config",
		"count", len(items))
	return len(items)
}
