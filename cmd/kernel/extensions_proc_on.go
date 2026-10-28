//go:build federation && federation_proc

package main

// 进程隔离装配（-tags "federation,federation_proc"）：
// 内核只启动 federation-mod 子进程并代理其状态/查询，联邦逻辑不在内核进程内。
import (
	federation "github.com/chins-xing/asscor/extensions/federation"
	"github.com/chins-xing/asscor/internal/kernel"
)

func newExtensionPlugins() []kernel.Plugin {
	return []kernel.Plugin{federation.NewProxy()}
}
