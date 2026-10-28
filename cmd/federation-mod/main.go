package main

// federation-mod 是进程隔离模式下的联邦模块进程（master 或 node）。
//
// 它不 import internal/kernel：只依赖 extensions/federation 的纯逻辑组件，
// 由内核侧 Proxy 通过 stdin/stdout 的 JSON-Lines 协议喂配置与拓扑快照。
import (
	"fmt"
	"os"

	federation "github.com/chins-xing/asscor/extensions/federation"
)

func main() {
	if err := federation.RunChild(); err != nil {
		fmt.Fprintln(os.Stderr, "federation-mod:", err)
		os.Exit(1)
	}
}
