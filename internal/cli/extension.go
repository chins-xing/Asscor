package cli

import "sync"

// ExtensionCommand 是一个由扩展包注册的命令。
//
// 扩展包（如 extensions/federation）在 init() 中调用 RegisterExtensionCommand，
// 由 RegisterBuiltinCommands 统一注册；internal/cli 本身不 import 任何扩展包，
// 从而保持 CLI 内核"零联邦/零插件知识"。
type ExtensionCommand struct {
	Info        CommandInfo
	Handler     CommandHandler
	Completions func(ctx *CommandContext, partial string) []string
}

var (
	extensionMu   sync.Mutex
	extensionCmds []ExtensionCommand
)

// RegisterExtensionCommand 注册扩展命令。应在 CLI 引擎 Init 之前调用
// （扩展包 init 阶段即可）。
func RegisterExtensionCommand(info CommandInfo, handler CommandHandler) {
	if info.Name == "" || handler == nil {
		return
	}
	extensionMu.Lock()
	defer extensionMu.Unlock()
	for _, c := range extensionCmds {
		if c.Info.Name == info.Name {
			return // 同名命令只注册一次（多扩展共享内核时幂等）
		}
	}
	extensionCmds = append(extensionCmds, ExtensionCommand{Info: info, Handler: handler})
}

// ExtensionCommandNames 返回已注册的扩展命令名（测试与自检用）。
func ExtensionCommandNames() []string {
	extensionMu.Lock()
	defer extensionMu.Unlock()
	out := make([]string, 0, len(extensionCmds))
	for _, c := range extensionCmds {
		out = append(out, c.Info.Name)
	}
	return out
}

func extensionCommands() []ExtensionCommand {
	extensionMu.Lock()
	defer extensionMu.Unlock()
	out := make([]ExtensionCommand, len(extensionCmds))
	copy(out, extensionCmds)
	return out
}
