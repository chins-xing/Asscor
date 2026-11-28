package agent

import "testing"

func TestParseNftL4Ports(t *testing.T) {
	raw := `{"nftables":[
	  {"rule":{"chain":"input","expr":[
	    {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"10.0.0.0/24"}},
	    {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":80}},
	    {"accept":null}
	  ]}}
	]}`
	rules, ok := parseNftRuleset(raw, nil)
	if !ok || len(rules) != 1 {
		t.Fatalf("rules=%+v ok=%v", rules, ok)
	}
	r := rules[0]
	if r.Protocol != "tcp" || r.DstPort != 80 || !r.Allow {
		t.Fatalf("rule = %+v", r)
	}
}

func TestParseIptablesL4Ports(t *testing.T) {
	raw := `-A INPUT -s 10.0.0.0/24 -p tcp -m tcp --dport 22 -j DROP`
	rules, ok := parseIptablesSave(raw, nil)
	if !ok || len(rules) != 1 {
		t.Fatalf("rules=%+v ok=%v", rules, ok)
	}
	r := rules[0]
	if r.Protocol != "tcp" || r.DstPort != 22 || r.Allow {
		t.Fatalf("rule = %+v", r)
	}
}

func TestParseIptablesSkipsComplexModules(t *testing.T) {
	raw := `-A INPUT -s 10.0.0.0/24 -m conntrack --ctstate NEW -j ACCEPT`
	rules, ok := parseIptablesSave(raw, nil)
	if !ok {
		t.Fatal("parser should still report known")
	}
	if len(rules) != 0 {
		t.Fatalf("complex module must not be guessed: %+v", rules)
	}
}
