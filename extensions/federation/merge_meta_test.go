package federation

import (
	"testing"
	"time"
)

func TestMergePreservesMetadata(t *testing.T) {
	t1 := time.Now().Add(-2 * time.Hour)
	t2 := time.Now().Add(-time.Hour)
	exp := t2.Add(time.Hour)
	reports := []NodeReport{
		{NodeID: "m1", PolicyKnown: true, HostFacts: []HostFact{{
			ID: "MH", Subnets: []string{"10.13.0.0/24"}, Confidence: 0.8, ObservedAt: t1, ValidUntil: exp,
		}}},
		{NodeID: "m2", PolicyKnown: true, HostFacts: []HostFact{{
			ID: "MH", Subnets: []string{"10.13.0.0/24"}, Confidence: 0.5, ObservedAt: t2, ValidUntil: exp,
		}}},
	}
	topo := MergedTopology(reports)
	if len(topo.Hosts) != 1 {
		t.Fatalf("hosts = %d", len(topo.Hosts))
	}
	h := topo.Hosts[0]
	if h.Confidence != 0.5 {
		t.Fatalf("confidence = %v, want min 0.5", h.Confidence)
	}
	if !h.ObservedAt.Equal(t2) {
		t.Fatalf("observed_at = %v, want latest %v", h.ObservedAt, t2)
	}
}
