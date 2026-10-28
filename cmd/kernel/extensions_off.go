//go:build !federation

package main

import "github.com/chins-xing/asscor/internal/kernel"

// 未编译扩展包时返回空列表（CLI 命令也不会出现——扩展命令由扩展包自注册）。
func newExtensionPlugins() []kernel.Plugin { return nil }
