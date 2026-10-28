package federation

import (
	"context"
	"strings"
	"testing"

	"github.com/chins-xing/asscor/internal/cli"
)

func newCtx(args ...string) *cli.CommandContext {
	return &cli.CommandContext{
		Ctx:    context.Background(),
		Args:   args,
		Params: map[string]string{},
	}
}

// 扩展命令必须已自注册（internal/cli 不再 import federation）。
func TestExtensionCommandRegistered(t *testing.T) {
	names := cli.ExtensionCommandNames()
	found := false
	for _, n := range names {
		if n == "federation" {
			found = true
		}
	}
	if !found {
		t.Fatalf("federation 未注册为扩展命令，got %v", names)
	}
}

// role=off 是信息态：status 返回 OK 且输出明确"未启用"。
func TestCommandStatusOffIsInfo(t *testing.T) {
	p := &Plugin{state: 0, cfg: Config{Role: RoleOff}}
	setCurrent(p)
	res := federationCmdHandler(newCtx("status"))
	if res.ExitCode != cli.ExitOK || res.Err != nil {
		t.Fatalf("off 状态应为 OK，got code=%v err=%v", res.ExitCode, res.Err)
	}
	if !strings.Contains(res.Output, "未启用") {
		t.Fatalf("输出应说明未启用，got %q", res.Output)
	}
}

// 非 master 执行 check/export 必须给出明确错误。
func TestCommandCheckRequiresMaster(t *testing.T) {
	p := &Plugin{state: 0, cfg: Config{Role: RoleNode, NodeID: "nk1"}}
	setCurrent(p)
	ctx := newCtx("check", "a", "b")
	res := federationCmdHandler(ctx)
	if res.ExitCode == cli.ExitOK {
		t.Fatalf("node 角色 check 应失败，got %v", res.Output)
	}
}

// master 的 report-now 也是错误（只有 node 能上报）。
func TestCommandReportNowRequiresNode(t *testing.T) {
	p := &Plugin{state: 0, cfg: Config{Role: RoleMaster}}
	setCurrent(p)
	res := federationCmdHandler(newCtx("report-now"))
	if res.ExitCode == cli.ExitOK {
		t.Fatalf("master 角色 report-now 应失败，got %v", res.Output)
	}
}
