package cli

import (
	"encoding/json"
	"fmt"
)

// ReachChecker 是 SRD 可达性查询的窄接口（v2.3 T3）。
// 由 kernel 在 Bootstrap 后注入（避免 cli 依赖 engine build tag）。
type ReachChecker interface {
	CheckReach(src, dst string) (any, error)
}

var reachChecker ReachChecker

// SetReachChecker 注入 SRD 查询实现（kernel main 在插件就绪后调用）。
func SetReachChecker(c ReachChecker) { reachChecker = c }

var srdCmdInfo = CommandInfo{
	Name:         "srd",
	Short:        "Query SRD reachability between two hosts",
	Description:  "Explain whether src can reach dst: verdict, path, blocked-at and unknown facts (SRD 分层图)",
	Usage:        "srd check <src> <dst>",
	Category:     CategorySystem,
	RequiredPerm: PermRead,
	Params: []CommandParam{
		{Name: "action", Description: "Action: check", Required: true, EnumValues: []string{"check"}},
		{Name: "src", Description: "Source host id", Required: true},
		{Name: "dst", Description: "Destination host id", Required: true},
	},
	Examples: []string{
		"srd check domA-web domB-web",
		"srd check domA-web domB-web --json",
	},
}

func srdCmdHandler(ctx *CommandContext) *CommandResult {
	// 兼容两种写法：`srd check <src> <dst>` 与 `srd check --src A --dst B`。
	// socket 会话里位置参数可能不落到 Params，因此回退到 ctx.Args。
	args := ctx.Args
	action := ctx.Params["action"]
	if action == "" && len(args) > 0 {
		action = args[0]
	}
	if action == "" {
		action = "check"
	}
	fail := func(code ExitCode, msg string) *CommandResult {
		return &CommandResult{ExitCode: code, Err: fmt.Errorf("%s", msg), Output: "error: " + msg + "\n"}
	}
	if action != "check" {
		return fail(ExitUsage, "unsupported action: "+action)
	}
	src, dst := ctx.Params["src"], ctx.Params["dst"]
	if (src == "" || dst == "") && len(args) >= 3 {
		src, dst = args[1], args[2]
	}
	if src == "" || dst == "" {
		return fail(ExitUsage, "usage: srd check <src> <dst>")
	}
	if reachChecker == nil {
		return fail(ExitError, "SRD 插件未加载（构建需 -tags srdwrapper,engine）")
	}
	res, err := reachChecker.CheckReach(src, dst)
	if err != nil {
		return fail(ExitError, err.Error())
	}
	if ctx.JSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		return &CommandResult{ExitCode: ExitOK, Output: string(b)}
	}
	if f, ok := res.(interface{ String() string }); ok {
		return &CommandResult{ExitCode: ExitOK, Output: f.String()}
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	return &CommandResult{ExitCode: ExitOK, Output: string(b)}
}
