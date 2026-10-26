//go:build !checks && engine

package main

import "github.com/chins-xing/asscor/internal/config"

// registerUserChecks 在**未编译 checks 模块**的构建里是 no-op：
// 没有检查注册表就没有内置检查，自定义检查自然也无处注册。
// 保留同名函数是为了让 main 只有一条调用路径（避免在 main 里散落 build-tag 分支）。
func registerUserChecks(cfg *config.Config) int { return 0 }
