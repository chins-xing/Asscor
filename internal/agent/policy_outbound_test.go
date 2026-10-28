package agent

import "testing"

// v2.3 T1：nft output 链的 daddr 规则 → outbound 方向。
func TestNftOutputDaddrRuleParsed(t *testing.T) {
	const raw = `{"nftables":[
	 {"chain":{"family":"ip","table":"filter","name":"output","type":"filter","hook":"output","prio":0,"policy":"accept"}},
	 {"rule":{"family":"ip","table":"filter","chain":"output","expr":[
	   {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"172.23.10.0/24"}},
	   {"drop":null}]}}
	]}`
	rules, ok := parseNftRuleset(raw, nil)
	if !ok {
		t.Fatal("解析失败")
	}
	if len(rules) != 1 {
		t.Fatalf("应提取 1 条 outbound，got %d: %+v", len(rules), rules)
	}
	r := rules[0]
	if r.Direction != "outbound" || r.Allow || r.To != "172.23.10.0/24" {
		t.Fatalf("outbound 解析错误: %+v", r)
	}
}

// iptables OUTPUT 的 -d 也走同一路径。
func TestIptablesOutputRuleParsed(t *testing.T) {
	const raw = `*filter
:OUTPUT ACCEPT [0:0]
-A OUTPUT -d 172.23.10.0/24 -j DROP
COMMIT
`
	rules, ok := parseIptablesSave(raw, nil)
	if !ok {
		t.Fatal("解析失败")
	}
	if len(rules) != 1 || rules[0].Direction != "outbound" || rules[0].To != "172.23.10.0/24" {
		t.Fatalf("iptables OUTPUT 解析错误: %+v", rules)
	}
}
