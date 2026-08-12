package common

import "testing"

func TestIsolateHostCommandAllowed(t *testing.T) {
	// isolate_host maps to iptables internally — iptables must be in the
	// allowlist for the last-resort blocking action to execute.
	if !IsCommandAllowed("iptables") {
		t.Error("iptables must be in the command allowlist for isolate_host")
	}
	if !IsCommandAllowed("nft") {
		t.Error("nft must be in the command allowlist for isolate_host")
	}

	name, args, ok := ParseCommand("iptables -P INPUT DROP")
	if !ok {
		t.Fatal("iptables should parse")
	}
	if name != "iptables" || len(args) != 3 {
		t.Errorf("expected iptables with 3 args, got %q %v", name, args)
	}
}
