package federation

import "testing"

func TestMergedTopologyCarriesSemantics(t *testing.T) {
	reports := conflictReports()
	exp := MergedTopology(reports)
	if len(exp.Conflicts) != 1 {
		t.Fatalf("conflicts = %+v", exp.Conflicts)
	}
	if exp.Stats["hosts"] != 3 {
		t.Fatalf("stats = %+v", exp.Stats)
	}
	if exp.GeneratedAt.IsZero() {
		t.Fatal("generated_at missing")
	}

	unknownReports := []NodeReport{{
		NodeID: "u1", PolicyKnown: false,
		HostFacts: []HostFact{{ID: "U", Subnets: []string{"10.20.0.0/24"}}},
	}}
	exp2 := MergedTopology(unknownReports)
	if len(exp2.PolicyUnknownSubnets) != 1 || exp2.PolicyUnknownSubnets[0] != "10.20.0.0/24" {
		t.Fatalf("unknown subnets = %v", exp2.PolicyUnknownSubnets)
	}
}
