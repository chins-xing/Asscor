//go:build federation

package main

// 扩展包装配（带 -tags federation 时编译）。
// cmd/kernel 只知道"有一些扩展插件"，不 import 任何具体扩展的 API。
import (
	federation "github.com/chins-xing/asscor/extensions/federation"
	"github.com/chins-xing/asscor/internal/kernel"
)

func newExtensionPlugins() []kernel.Plugin {
	return []kernel.Plugin{federation.New()}
}
