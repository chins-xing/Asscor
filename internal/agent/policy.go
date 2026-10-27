package agent

import (
	"encoding/json"
	"os"
	"strings"

	apiv1 "github.com/chins-xing/asscor/api/v1"
	"github.com/chins-xing/asscor/internal/common"
)

// 本文件实现 SRD 分层图所需的 **L4 策略事实采集**（policy 层）。
//
// 设计约束（来自"未知 ≠ 放行"这条硬规则）：
//   - 只有在**成功执行**了 nft/iptables 查询时才把 known 置真；
//   - 只提取"能看到 saddr+daddr+verdict"的规则；复杂匹配（用户链、集合、
//     连接跟踪状态、接口匹配）一律**不猜**；
//   - 解析失败/命令缺失 ⇒ known=false，SRD 会判 probable，而不是 assume allow。

// collectPolicyFacts 采集本机防火墙的显式 allow/deny 结论。
// 返回 (rules, known)。known=false 表示"没采集到"，不是"没有策略"。
func collectPolicyFacts() ([]apiv1.PolicyRule, bool) {
	if out, ok := runQuiet("nft", "-j", "list", "ruleset"); ok {
		rules, parsed := parseNftRuleset(out)
		if parsed {
			return rules, true
		}
	}
	if out, ok := runQuiet("iptables-save"); ok {
		rules, parsed := parseIptablesSave(out)
		if parsed {
			return rules, true
		}
	}
	return nil, false
}

// parseNftRuleset 解析 `nft -j list ruleset` 的 JSON 输出。
//
// 结构：{"nftables":[{"rule":{...}}, ...]}。一条 rule 的 expr 里：
//
//	{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"172.22.10.0/24"}}
//	{"drop":null} / {"reject":null} / {"accept":null}
func parseNftRuleset(raw string) ([]apiv1.PolicyRule, bool) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, false
	}
	var rules []apiv1.PolicyRule
	for _, item := range doc.Nftables {
		ruleRaw, ok := item["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Expr []map[string]json.RawMessage `json:"expr"`
		}
		if err := json.Unmarshal(ruleRaw, &rule); err != nil {
			continue
		}
		var from, to string
		var verdict *bool
		for _, e := range rule.Expr {
			if m, ok := e["match"]; ok {
				var match struct {
					Left  map[string]json.RawMessage `json:"left"`
					Right json.RawMessage            `json:"right"`
				}
				if json.Unmarshal(m, &match) != nil {
					continue
				}
				payload, ok := match.Left["payload"]
				if !ok {
					continue
				}
				var pl struct {
					Protocol string `json:"protocol"`
					Field    string `json:"field"`
				}
				if json.Unmarshal(payload, &pl) != nil || pl.Protocol != "ip" {
					continue
				}
				var val string
				if json.Unmarshal(match.Right, &val) != nil {
					continue
				}
				switch pl.Field {
				case "saddr":
					from = val
				case "daddr":
					to = val
				}
				continue
			}
			if _, ok := e["drop"]; ok {
				v := false
				verdict = &v
			} else if _, ok := e["reject"]; ok {
				v := false
				verdict = &v
			} else if _, ok := e["accept"]; ok {
				v := true
				verdict = &v
			}
		}
		if from != "" && to != "" && verdict != nil {
			rules = append(rules, apiv1.PolicyRule{From: from, To: to, Allow: *verdict})
		}
	}
	return rules, true
}

// parseIptablesSave 解析 `iptables-save` 输出里 FORWARD 链的显式规则：
//
//	-A FORWARD -s 172.22.10.0/24 -d 172.23.10.0/24 -j DROP
func parseIptablesSave(raw string) ([]apiv1.PolicyRule, bool) {
	var rules []apiv1.PolicyRule
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A FORWARD") {
			continue
		}
		if strings.Contains(line, "! ") || strings.Contains(line, "-m ") {
			continue // 带取反/扩展匹配的规则不猜
		}
		fields := strings.Fields(line)
		var from, to, target string
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "-s", "--source":
				from = fields[i+1]
			case "-d", "--destination":
				to = fields[i+1]
			case "-j", "--jump":
				target = fields[i+1]
			}
		}
		if from == "" || to == "" {
			continue
		}
		switch target {
		case "DROP", "REJECT":
			rules = append(rules, apiv1.PolicyRule{From: from, To: to, Allow: false})
		case "ACCEPT":
			rules = append(rules, apiv1.PolicyRule{From: from, To: to, Allow: true})
		}
	}
	return rules, true
}

// collectVLANs 采集本机可见的 VLAN 标识（通常容器内为空 ⇒ 未知）。
func collectVLANs() []string {
	var vlans []string
	entries, err := os.ReadDir("/proc/net/vlan")
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.Name() == "config" {
			continue
		}
		vlans = append(vlans, e.Name())
	}
	return vlans
}

// collectForwards 读取 ip_forward；读不到则按 false（保守：不能中继）。
func collectForwards() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}

// runQuiet 执行命令并返回输出与是否成功（不区分"命令不存在"与"执行失败"，
// 两者都视为 known=false 的素材）。
func runQuiet(name string, args ...string) (string, bool) {
	return common.RunCmdQuiet(name, args...)
}
