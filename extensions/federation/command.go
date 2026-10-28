package federation

// CLI 命令由扩展包自注册：internal/cli 不知道 federation 的存在。
import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chins-xing/asscor/internal/cli"
)

var currentPlugin *Plugin

func setCurrent(p *Plugin) { currentPlugin = p }

func init() {
	cli.RegisterExtensionCommand(federationCmdInfo, federationCmdHandler)
}

var federationCmdInfo = cli.CommandInfo{
	Name:         "federation",
	Short:        "Federation master/node status, merged check, export (extension)",
	Description:  "扩展包 extensions/federation：master 展示节点表/合并图；node 展示配置与上报状态；合并图可跨节点 check/export。",
	Usage:        "federation status [--json] | check <src> <dst> | export | report-now",
	Category:     cli.CategorySystem,
	RequiredPerm: cli.PermRead,
	Params: []cli.CommandParam{
		{Name: "action", Description: "Action: status | check | export | report-now", Required: false,
			EnumValues: []string{"status", "check", "export", "report-now"}},
		{Name: "src", Description: "check: source host id", Required: false},
		{Name: "dst", Description: "check: destination host id", Required: false},
	},
	Examples: []string{
		"federation status",
		"federation status --json",
		"federation check domA-web domB-web",
		"federation export",
		"federation report-now",
	},
}

func federationCmdHandler(ctx *cli.CommandContext) *cli.CommandResult {
	fail := func(code cli.ExitCode, msg string) *cli.CommandResult {
		return &cli.CommandResult{ExitCode: code, Err: fmt.Errorf("%s", msg), Output: "error: " + msg + "\n"}
	}

	action := strings.TrimSpace(ctx.Params["action"])
	if action == "" && len(ctx.Args) > 0 {
		action = strings.TrimSpace(ctx.Args[0])
	}
	if action == "" {
		action = "status"
	}

	p := currentPlugin
	if p == nil {
		return fail(cli.ExitError, "federation 扩展未加载（构建需 -tags federation）")
	}

	switch action {
	case "status":
		if p.cfg.Role == RoleOff {
			return &cli.CommandResult{ExitCode: cli.ExitOK, Output: "federation 未启用（[federation] role = off）\n"}
		}
		st := p.FederationStatus()
		if ctx.JSON {
			data, err := json.MarshalIndent(st, "", "  ")
			if err != nil {
				return fail(cli.ExitError, "marshal federation status: "+err.Error())
			}
			return &cli.CommandResult{ExitCode: cli.ExitOK, Output: string(data) + "\n"}
		}
		return &cli.CommandResult{ExitCode: cli.ExitOK, Output: renderStatus(st)}

	case "check":
		src, dst := ctx.Params["src"], ctx.Params["dst"]
		if (src == "" || dst == "") && len(ctx.Args) >= 3 {
			src, dst = ctx.Args[1], ctx.Args[2]
		}
		if src == "" || dst == "" {
			return fail(cli.ExitUsage, "usage: federation check <src> <dst>")
		}
		res, err := p.MergedCheck(src, dst)
		if err != nil {
			return fail(cli.ExitError, err.Error())
		}
		if ctx.JSON {
			data, _ := json.MarshalIndent(res, "", "  ")
			return &cli.CommandResult{ExitCode: cli.ExitOK, Output: string(data) + "\n"}
		}
		if f, ok := res.(interface{ String() string }); ok {
			return &cli.CommandResult{ExitCode: cli.ExitOK, Output: f.String()}
		}
		data, _ := json.MarshalIndent(res, "", "  ")
		return &cli.CommandResult{ExitCode: cli.ExitOK, Output: string(data) + "\n"}

	case "export":
		exp, err := p.ExportMerged()
		if err != nil {
			return fail(cli.ExitError, err.Error())
		}
		data, err := json.MarshalIndent(exp, "", "  ")
		if err != nil {
			return fail(cli.ExitError, "marshal export: "+err.Error())
		}
		return &cli.CommandResult{ExitCode: cli.ExitOK, Output: string(data) + "\n"}

	case "report-now":
		if err := p.ReportNow(context.Background()); err != nil {
			return fail(cli.ExitError, "report-now: "+err.Error())
		}
		return &cli.CommandResult{ExitCode: cli.ExitOK, Output: "federation report sent\n"}

	default:
		return fail(cli.ExitUsage, "unsupported action: "+action+" (usage: federation status | check | export | report-now)")
	}
}

func renderStatus(st Status) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  Federation (%s)\n", st.Role)
	b.WriteString("  ─────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(&b, "  Running:        %v\n", st.Running)
	if st.NodeID != "" {
		fmt.Fprintf(&b, "  Node ID:        %s\n", st.NodeID)
	}
	if st.MasterURL != "" {
		fmt.Fprintf(&b, "  Master URL:     %s\n", st.MasterURL)
	}
	if st.ListenAddr != "" {
		fmt.Fprintf(&b, "  Listen:         %s\n", st.ListenAddr)
	}
	if st.ListenError != "" {
		fmt.Fprintf(&b, "  Listen error:   %s\n", st.ListenError)
	}
	if st.ConfigError != "" {
		fmt.Fprintf(&b, "  Config error:   %s\n", st.ConfigError)
	}
	if st.ConfigHash != "" {
		fmt.Fprintf(&b, "  Config hash:    %s\n", ShortHash(st.ConfigHash))
	}
	if len(st.Params) > 0 {
		fmt.Fprintf(&b, "  Params:         %s\n", FormatParams(st.Params))
	}
	if st.Hosts > 0 {
		fmt.Fprintf(&b, "  Hosts:          %d\n", st.Hosts)
	}
	if st.LastReportAt != nil {
		fmt.Fprintf(&b, "  Last report:    %s\n", st.LastReportAt.Format("2006-01-02 15:04:05"))
	}
	if st.LastReportError != "" {
		fmt.Fprintf(&b, "  Last error:     %s (attempts=%d)\n", st.LastReportError, st.LastReportAttempts)
	}
	if len(st.Nodes) > 0 {
		fmt.Fprintf(&b, "  Nodes:          %d\n\n", len(st.Nodes))
		b.WriteString("  NODE_ID        CONFIG_HASH         HOSTS   AVG_SSAM  LAST_REPORT\n")
		b.WriteString("  ─────────────────────────────────────────────────────────────\n")
		for _, n := range st.Nodes {
			last := "-"
			ts := n.ReceivedAt
			if ts.IsZero() {
				ts = n.ReportedAt
			}
			if !ts.IsZero() {
				last = ts.Local().Format("2006-01-02 15:04:05")
			}
			fmt.Fprintf(&b, "  %-14s %-19s %-7d %-9.1f %s\n", n.NodeID, ShortHash(n.ConfigHash), n.Hosts, n.AvgSSAM, last)
		}
	}
	b.WriteString("\n")
	return b.String()
}
