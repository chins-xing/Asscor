package agent

import "testing"

// nft -j list ruleset 的真实结构（节选）：forward 链里一条 A→B drop。
const nftSample = `{"nftables":[
 {"metainfo":{"version":"1.0.6","release_name":"Lester Gooch","json_schema_version":1}},
 {"table":{"family":"ip","name":"filter"}},
 {"chain":{"family":"ip","table":"filter","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"drop"}},
 {"rule":{"family":"ip","table":"filter","chain":"forward",
   "expr":[
     {"match":{"op":"==","left":{"ct":{"key":"state"}},"right":"established,related"}},
     {"accept":null}]}},
 {"rule":{"family":"ip","table":"filter","chain":"forward",
   "expr":[
     {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
     {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth1"}},
     {"drop":null}]}},
 {"rule":{"family":"ip","table":"filter","chain":"forward",
   "expr":[
     {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"172.22.10.0/24"}},
     {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"172.23.10.0/24"}},
     {"drop":null}]}},
 {"rule":{"family":"ip","table":"filter","chain":"forward",
   "expr":[
     {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"172.22.10.0/24"}},
     {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"100.64.0.0/24"}},
     {"accept":null}]}}
]}`

func TestParseNftRulesetExtractsCIDRRules(t *testing.T) {
	ifaces := map[string][]string{
		"eth0": {"172.22.10.0/24"},
		"eth1": {"172.23.10.0/24"},
	}
	rules, ok := parseNftRuleset(nftSample, ifaces)
	if !ok {
		t.Fatal("解析失败")
	}
	if len(rules) != 3 {
		// 2 条地址级（saddr+daddr）+ 1 条接口级（eth0→eth1 展开）
		t.Fatalf("应提取 3 条（2 地址级 + 1 接口级），got %d: %+v", len(rules), rules)
	}
	if rules[0].From != "172.22.10.0/24" || rules[0].To != "172.23.10.0/24" || rules[0].Allow {
		t.Errorf("drop 规则解析错误: %+v", rules[0])
	}
	if rules[1].From != "172.22.10.0/24" || rules[1].To != "172.23.10.0/24" || rules[1].Allow {
		t.Errorf("接口级 drop 映射错误: %+v", rules[1])
	}
	if rules[2].From != "172.22.10.0/24" || rules[2].To != "100.64.0.0/24" || !rules[2].Allow {
		t.Errorf("accept 规则解析错误: %+v", rules[2])
	}
}

// 只按接口/状态的规则不能当子网策略（必须忽略，不能猜）。
func TestParseNftRulesetIgnoresInterfaceRules(t *testing.T) {
	ifaces := map[string][]string{"eth0": {"172.22.10.0/24"}, "eth1": {"172.23.10.0/24"}}
	rules, ok := parseNftRuleset(nftSample, ifaces)
	if !ok {
		t.Fatal("解析失败")
	}
	for _, r := range rules {
		if r.From == "" || r.To == "" {
			t.Errorf("出现了没有 CIDR 的规则: %+v", r)
		}
	}
}

func TestParseNftRulesetRejectsGarbage(t *testing.T) {
	if _, ok := parseNftRuleset("not json", nil); ok {
		t.Fatal("垃圾输入不应返回 known=true")
	}
}

func TestParseIptablesSave(t *testing.T) {
	raw := `*filter
:FORWARD DROP [0:0]
-A FORWARD -s 172.22.10.0/24 -d 172.23.10.0/24 -j DROP
-A FORWARD -s 172.22.10.0/24 -d 100.64.0.0/24 -j ACCEPT
-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i eth0 -o eth1 -j DROP
COMMIT`
	rules, ok := parseIptablesSave(raw, nil)
	if !ok {
		t.Fatal("解析失败")
	}
	if len(rules) != 2 {
		t.Fatalf("应提取 2 条（跳过 state 与接口规则），got %d: %+v", len(rules), rules)
	}
	if rules[0].Allow || rules[1].Allow != true {
		t.Errorf("方向判定错误: %+v", rules)
	}
}

func TestParseIptablesSaveNegationIgnored(t *testing.T) {
	raw := "-A FORWARD ! -s 172.22.10.0/24 -d 172.23.10.0/24 -j DROP"
	rules, ok := parseIptablesSave(raw, nil)
	if !ok {
		t.Fatal("解析失败")
	}
	if len(rules) != 0 {
		t.Fatalf("带取反的规则不应被猜成策略，got %+v", rules)
	}
}

// TestParseNftRulesetMapsInterfaceACLToSubnets 钉住"接口级 ACL 无需改造即可被理解"：
// 真实配置写的是 `iifname "eth0" oifname "eth1" drop`，agent 用接口→子网映射
// 展开成 172.22.10.0/24 → 172.23.10.0/24 阻断。
func TestParseNftRulesetMapsInterfaceACLToSubnets(t *testing.T) {
	const raw = `{"nftables":[
	 {"table":{"family":"ip","name":"filter"}},
	 {"chain":{"family":"ip","table":"filter","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"drop"}},
	 {"rule":{"family":"ip","table":"filter","chain":"forward","expr":[
	   {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
	   {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth1"}},
	   {"drop":null}]}},
	 {"rule":{"family":"ip","table":"filter","chain":"forward","expr":[
	   {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth1"}},
	   {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth0"}},
	   {"drop":null}]}}
	]}`
	ifaces := map[string][]string{
		"eth0": {"172.22.10.0/24"},
		"eth1": {"172.23.10.0/24"},
	}
	rules, ok := parseNftRuleset(raw, ifaces)
	if !ok {
		t.Fatal("解析失败")
	}
	if len(rules) != 2 {
		t.Fatalf("应展开成 2 条子网级策略，got %d: %+v", len(rules), rules)
	}
	if rules[0].From != "172.22.10.0/24" || rules[0].To != "172.23.10.0/24" || rules[0].Allow {
		t.Errorf("A→B 阻断映射错误: %+v", rules[0])
	}
	if rules[1].From != "172.23.10.0/24" || rules[1].To != "172.22.10.0/24" || rules[1].Allow {
		t.Errorf("B→A 阻断映射错误: %+v", rules[1])
	}
}

// TestParseNftRulesetPrefixObject：nft 新版把 CIDR 输出成 {"prefix":{...}}，
// 必须能解析，否则地址级 ACL 会被静默丢弃。
func TestParseNftRulesetPrefixObject(t *testing.T) {
	const raw = `{"nftables":[
	 {"rule":{"family":"ip","table":"filter","chain":"forward","expr":[
	   {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"172.22.10.0","len":24}}}},
	   {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"172.23.10.0","len":24}}}},
	   {"drop":null}]}}
	]}`
	rules, ok := parseNftRuleset(raw, nil)
	if !ok || len(rules) != 1 {
		t.Fatalf("prefix 对象解析失败: ok=%v rules=%+v", ok, rules)
	}
	if rules[0].From != "172.22.10.0/24" || rules[0].To != "172.23.10.0/24" || rules[0].Allow {
		t.Fatalf("prefix 解析结果错误: %+v", rules[0])
	}
}

// 接口未知时不猜（不能把 eth1 当任意子网）。
func TestParseNftRulesetUnknownIfaceNotGuessed(t *testing.T) {
	const raw = `{"nftables":[
	 {"rule":{"family":"ip","table":"filter","chain":"forward","expr":[
	   {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth9"}},
	   {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth8"}},
	   {"drop":null}]}}
	]}`
	rules, ok := parseNftRuleset(raw, map[string][]string{"eth0": {"10.0.0.0/24"}})
	if !ok {
		t.Fatal("解析失败")
	}
	if len(rules) != 0 {
		t.Fatalf("接口未知时不应猜出策略，got %+v", rules)
	}
}

// iptables-save 的接口级规则同样映射
func TestParseIptablesSaveMapsInterfaceACL(t *testing.T) {
	raw := "-A FORWARD -i eth0 -o eth1 -j DROP"
	ifaces := map[string][]string{"eth0": {"172.22.10.0/24"}, "eth1": {"172.23.10.0/24"}}
	rules, ok := parseIptablesSave(raw, ifaces)
	if !ok || len(rules) != 1 {
		t.Fatalf("接口级 iptables 映射失败: ok=%v rules=%+v", ok, rules)
	}
	if rules[0].From != "172.22.10.0/24" || rules[0].To != "172.23.10.0/24" || rules[0].Allow {
		t.Fatalf("映射结果错误: %+v", rules[0])
	}
}
