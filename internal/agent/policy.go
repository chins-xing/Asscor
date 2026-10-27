package agent

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
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
	ifaces := interfaceSubnets()
	if out, ok := runQuiet("nft", "-j", "list", "ruleset"); ok {
		rules, parsed := parseNftRuleset(out, ifaces)
		if parsed {
			return rules, true
		}
	}
	if out, ok := runQuiet("iptables-save"); ok {
		rules, parsed := parseIptablesSave(out, ifaces)
		if parsed {
			return rules, true
		}
	}
	return nil, false
}

// interfaceSubnets 采集"接口名 → 该接口上的子网"映射。
//
// 接口级 ACL（`iifname eth0 oifname eth1 drop`）本身不含地址，只有把接口映射到
// 子网，才能还原成"172.22.10.0/24 → 172.23.10.0/24 阻断"这种可推理的策略事实。
// 这就是"真实配置无需改造即可被理解"的关键一步。
func interfaceSubnets() map[string][]string {
	out := map[string][]string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
				out[iface.Name] = append(out[iface.Name], ipNet.String())
			}
		}
	}
	return out
}

// parseNftRuleset 解析 `nft -j list ruleset` 的 JSON 输出。
//
// 结构：{"nftables":[{"rule":{...}}, ...]}。一条 rule 的 expr 里：
//
//	{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"172.22.10.0/24"}}
//	{"drop":null} / {"reject":null} / {"accept":null}
func parseNftRuleset(raw string, ifaces map[string][]string) ([]apiv1.PolicyRule, bool) {
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
			Chain string                      `json:"chain"`
			Expr  []map[string]json.RawMessage `json:"expr"`
		}
		if err := json.Unmarshal(ruleRaw, &rule); err != nil {
			continue
		}
		var from, to string
		var inIface, outIface string
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
				if metaRaw, ok := match.Left["meta"]; ok {
					var meta struct {
						Key string `json:"key"`
					}
					if json.Unmarshal(metaRaw, &meta) == nil {
						var ifname string
						_ = json.Unmarshal(match.Right, &ifname)
						switch meta.Key {
						case "iifname":
							inIface = ifname
						case "oifname":
							outIface = ifname
						}
					}
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
				switch pl.Field {
				case "saddr":
					from = nftCIDR(match.Right)
				case "daddr":
					to = nftCIDR(match.Right)
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
		if verdict == nil {
			continue
		}
		inbound := strings.EqualFold(rule.Chain, "input")
		if inbound {
			// 入向规则三种形态（"不猜"边界）：
			//   saddr → 拒绝/放行来自该源的入向；
			//   daddr → 拒绝/放行到该目标子网的入向（A-5：此前被丢弃）；
			//   iifname → 用接口→子网映射展开成来源子网。
			switch {
			case from != "":
				rules = append(rules, apiv1.PolicyRule{From: from, Allow: *verdict, Direction: "inbound"})
			case to != "":
				rules = append(rules, apiv1.PolicyRule{To: to, Allow: *verdict, Direction: "inbound"})
			case inIface != "":
				for _, fs := range ifaces[inIface] {
					rules = append(rules, apiv1.PolicyRule{From: fs, Allow: *verdict, Direction: "inbound"})
				}
			}
			continue
		}
		if from != "" && to != "" {
			rules = append(rules, apiv1.PolicyRule{From: from, To: to, Allow: *verdict})
			continue
		}
		// 接口级规则：把接口映射到它所在子网，展开成子网对策略。
		// 只映射**两端都已知**的规则；缺一端就不猜。
		if inIface != "" && outIface != "" {
			for _, fs := range ifaces[inIface] {
				for _, ts := range ifaces[outIface] {
					rules = append(rules, apiv1.PolicyRule{From: fs, To: ts, Allow: *verdict})
				}
			}
		}
	}
	return rules, true
}

// nftCIDR 从 nft JSON 的 match.right 取出 CIDR：
// 既可能是字符串（"172.22.10.0/24"），也可能是 {"prefix":{"addr":"...","len":24}}。
func nftCIDR(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		return s
	}
	var p struct {
		Prefix struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}
	if json.Unmarshal(raw, &p) == nil && p.Prefix.Addr != "" {
		return p.Prefix.Addr + "/" + itoa(p.Prefix.Len)
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// parseIptablesSave 解析 `iptables-save` 输出里 FORWARD 链的显式规则：
//
//	-A FORWARD -s 172.22.10.0/24 -d 172.23.10.0/24 -j DROP
func parseIptablesSave(raw string, ifaces map[string][]string) ([]apiv1.PolicyRule, bool) {
	var rules []apiv1.PolicyRule
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		inbound := strings.HasPrefix(line, "-A INPUT")
		if !strings.HasPrefix(line, "-A FORWARD") && !inbound {
			continue
		}
		if strings.Contains(line, "! ") || strings.Contains(line, "-m ") {
			continue // 带取反/扩展匹配的规则不猜
		}
		fields := strings.Fields(line)
		var from, to, target, inIface, outIface string
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "-s", "--source":
				from = fields[i+1]
			case "-d", "--destination":
				to = fields[i+1]
			case "-j", "--jump":
				target = fields[i+1]
			case "-i", "--in-interface":
				inIface = fields[i+1]
			case "-o", "--out-interface":
				outIface = fields[i+1]
			}
		}
		var allow bool
		switch target {
		case "DROP", "REJECT":
			allow = false
		case "ACCEPT":
			allow = true
		default:
			continue
		}
		if inbound {
			switch {
			case from != "":
				rules = append(rules, apiv1.PolicyRule{From: from, Allow: allow, Direction: "inbound"})
			case to != "":
				rules = append(rules, apiv1.PolicyRule{To: to, Allow: allow, Direction: "inbound"})
			case inIface != "":
				for _, fs := range ifaces[inIface] {
					rules = append(rules, apiv1.PolicyRule{From: fs, Allow: allow, Direction: "inbound"})
				}
			}
			continue
		}
		if from != "" && to != "" {
			rules = append(rules, apiv1.PolicyRule{From: from, To: to, Allow: allow})
			continue
		}
		if inIface != "" && outIface != "" {
			for _, fs := range ifaces[inIface] {
				for _, ts := range ifaces[outIface] {
					rules = append(rules, apiv1.PolicyRule{From: fs, To: ts, Allow: allow})
				}
			}
		}
	}
	return rules, true
}

// collectLinks 采集 L1 链路事实：每个非回环接口的 up/down、子网、VLAN。
//
// PVE SDN 的 VLAN tag 配在**宿主 OVS 端口**上，容器内看不到；为让 L2 语义在
// 容器环境也可用，支持运维用 `ASSCOR_AGENT_VLANS="eth0=101,eth1=102"` 显式覆盖。
func collectLinks() []apiv1.LinkInfo {
	overrides := vlanOverrides()
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]apiv1.LinkInfo, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		li := apiv1.LinkInfo{Name: iface.Name, Up: iface.Flags&net.FlagUp != 0}
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
					li.Subnets = append(li.Subnets, ipNet.String())
				}
			}
		}
		if v, ok := overrides[iface.Name]; ok {
			li.VLANs = append(li.VLANs, v)
		} else {
			li.VLANs = vlanForInterface(iface.Name)
		}
		out = append(out, li)
	}
	return out
}

// vlanOverrides 解析 ASSCOR_AGENT_VLANS（"eth0=101,eth1=102"）。
func vlanOverrides() map[string]string {
	out := map[string]string{}
	raw := strings.TrimSpace(os.Getenv("ASSCOR_AGENT_VLANS"))
	if raw == "" {
		return out
	}
	for _, kv := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(kv), "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			continue
		}
		out[parts[0]] = parts[1]
	}
	return out
}

// vlanForInterface 返回接口的 VLAN 标识：优先 /proc/net/vlan/<iface>，
// 其次接口名后缀（eth0.101 这种 802.1Q 命名）。
func vlanForInterface(name string) []string {
	if _, err := os.Stat("/proc/net/vlan/" + name); err == nil {
		return []string{name}
	}
	if idx := strings.LastIndex(name, "."); idx > 0 && idx < len(name)-1 {
		if _, err := strconv.Atoi(name[idx+1:]); err == nil {
			return []string{name}
		}
	}
	return nil
}

// collectVLANs 采集本机可见的 VLAN 标识（通常容器内为空 ⇒ 未知）。
func collectVLANs() []string {
	var vlans []string
	for _, v := range vlanOverrides() {
		vlans = append(vlans, v)
	}
	entries, err := os.ReadDir("/proc/net/vlan")
	if err != nil {
		// 容器内没有 VLAN procfs：**不能丢已经收集到的 env 覆盖**（A-3 实测踩到）。
		return vlans
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
