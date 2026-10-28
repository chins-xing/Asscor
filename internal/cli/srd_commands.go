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
	action := ctx.Params["action"]
	if action == "" {
		action = "check"
	}
	if action != "check" {
		return &CommandResult{ExitCode: ExitUsage, Err: fmt.Errorf("unsupported action: %s", action)}
	}
	src, dst := ctx.Params["src"], ctx.Params["dst"]
	if src == "" || dst == "" {
		return &CommandResult{ExitCode: ExitUsage, Err: fmt.Errorf("usage: srd check <src> <dst>")}
	}
	if reachChecker == nil {
		return &CommandResult{ExitCode: ExitError, Err: fmt.Errorf("SRD 插件未加载（构建需 -tags srdwrapper,engine）")}
	}
	res, err := reachChecker.CheckReach(src, dst)
	if err != nil {
		return &CommandResult{ExitCode: ExitError, Err: err}
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
