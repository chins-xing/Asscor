package agent

import "testing"

// A-5：入向链里只带 daddr 的规则（`ip daddr X drop`）也要被识别。
func TestNftInputDaddrRuleParsed(t *testing.T) {
	const raw = `{"nftables":[
	 {"chain":{"family":"ip","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"accept"}},
	 {"rule":{"family":"ip","table":"filter","chain":"input","expr":[
	   {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"172.22.10.0/24"}},
	   {"drop":null}]}}
	]}`
	rules, ok := parseNftRuleset(raw, nil)
	if !ok {
		t.Fatal("解析失败")
	}
	if len(rules) != 1 {
		t.Fatalf("应提取 1 条 inbound，got %d: %+v", len(rules), rules)
	}
	r := rules[0]
	if r.Direction != "inbound" || r.Allow || r.To != "172.22.10.0/24" || r.From != "" {
		t.Fatalf("daddr 规则解析错误: %+v", r)
	}
}

// A-5：iptables INPUT 的 `-d` 也走同一路径。
func TestIptablesInputDaddrRuleParsed(t *testing.T) {
	const raw = `*filter
:INPUT ACCEPT [0:0]
-A INPUT -d 172.23.10.0/24 -j DROP
COMMIT
`
	rules, ok := parseIptablesSave(raw, nil)
	if !ok {
		t.Fatal("解析失败")
	}
	if len(rules) != 1 {
		t.Fatalf("应提取 1 条 inbound，got %d: %+v", len(rules), rules)
	}
	if rules[0].Direction != "inbound" || rules[0].To != "172.23.10.0/24" || rules[0].From != "" {
		t.Fatalf("iptables -d 解析错误: %+v", rules[0])
	}
}
