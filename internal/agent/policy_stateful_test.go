package agent

import "testing"

// v2.3 T2：input 链里有 ct state established,related accept ⇒ StatefulInput=true。
func TestParseNftStatefulDetectsCTAccept(t *testing.T) {
	const raw = `{"nftables":[
	 {"chain":{"family":"ip","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"accept"}},
	 {"rule":{"family":"ip","table":"filter","chain":"input","expr":[
	   {"match":{"op":"==","left":{"ct":{"key":"state"}},"right":["established","related"]}},
	   {"accept":null}]}},
	 {"rule":{"family":"ip","table":"filter","chain":"input","expr":[
	   {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"10.0.0.11/32"}},
	   {"drop":null}]}}
	]}`
	in, out := parseNftStateful(raw)
	if !in || out {
		t.Fatalf("应只识别 input 状态化：in=%v out=%v", in, out)
	}
}

// 没有 ct accept 的链 ⇒ 不算状态化。
func TestParseNftStatefulWithoutCTRule(t *testing.T) {
	const raw = `{"nftables":[
	 {"rule":{"family":"ip","table":"filter","chain":"input","expr":[
	   {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"10.0.0.11/32"}},
	   {"drop":null}]}}
	]}`
	in, out := parseNftStateful(raw)
	if in || out {
		t.Fatalf("无 ct accept 不应判状态化：in=%v out=%v", in, out)
	}
}
