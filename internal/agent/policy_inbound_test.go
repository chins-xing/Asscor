package agent

import "testing"

// A-5：nft input 链里 `ct state established accept` 这类无 saddr 的规则必须被忽略；
// 只有带 saddr 的 drop 才转成 inbound 策略（"不猜"边界）。
func TestNftInputCtStateRuleIgnored(t *testing.T) {
	const raw = `{"nftables":[
	 {"chain":{"family":"ip","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"accept"}},
	 {"rule":{"family":"ip","table":"filter","chain":"input","expr":[
	   {"match":{"op":"==","left":{"ct":{"key":"state"}},"right":["established","related"]}},
	   {"accept":null}]}},
	 {"rule":{"family":"ip","table":"filter","chain":"input","expr":[
	   {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"172.22.10.0/24"}},
	   {"drop":null}]}}
	]}`
	rules, ok := parseNftRuleset(raw, nil)
	if !ok {
		t.Fatal("解析失败")
	}
	if len(rules) != 1 {
		t.Fatalf("应只提取 1 条入向策略，got %d: %+v", len(rules), rules)
	}
	if rules[0].Direction != "inbound" || rules[0].Allow || rules[0].From != "172.22.10.0/24" {
		t.Fatalf("入向策略解析错误: %+v", rules[0])
	}
}
