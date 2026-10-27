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
	rules, ok := parseNftRuleset(nftSample)
	if !ok {
		t.Fatal("解析失败")
	}
	if len(rules) != 2 {
		t.Fatalf("应只提取 2 条带 saddr+daddr 的规则，got %d: %+v", len(rules), rules)
	}
	if rules[0].From != "172.22.10.0/24" || rules[0].To != "172.23.10.0/24" || rules[0].Allow {
		t.Errorf("drop 规则解析错误: %+v", rules[0])
	}
	if rules[1].From != "172.22.10.0/24" || rules[1].To != "100.64.0.0/24" || !rules[1].Allow {
		t.Errorf("accept 规则解析错误: %+v", rules[1])
	}
}

// 只按接口/状态的规则不能当子网策略（必须忽略，不能猜）。
func TestParseNftRulesetIgnoresInterfaceRules(t *testing.T) {
	rules, ok := parseNftRuleset(nftSample)
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
	if _, ok := parseNftRuleset("not json"); ok {
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
	rules, ok := parseIptablesSave(raw)
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
	rules, ok := parseIptablesSave(raw)
	if !ok {
		t.Fatal("解析失败")
	}
	if len(rules) != 0 {
		t.Fatalf("带取反的规则不应被猜成策略，got %+v", rules)
	}
}
