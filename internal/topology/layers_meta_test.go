package topology

import (
	"testing"
	"time"
)

func TestExpiredHostAndPolicyAreFiltered(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	hosts := []HostFacts{
		{HostID: "A", Subnets: []string{"10.11.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.11.0.0/24"}, ValidUntil: past, Confidence: 0.4},
	}
	g := BuildLayeredGraphAt(hosts, nil, true, true, now)
	if _, ok := g.hosts["B"]; ok {
		t.Fatal("expired host must be filtered")
	}
	if len(g.hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(g.hosts))
	}

	policies := []PolicyRule{{From: "10.11.0.0/24", To: "10.11.0.0/24", Allow: false, ValidUntil: past}}
	fresh := []HostFacts{
		{HostID: "A", Subnets: []string{"10.11.0.0/24"}},
		{HostID: "B", Subnets: []string{"10.11.0.0/24"}},
	}
	g2 := BuildLayeredGraphAt(fresh, policies, true, true, now)
	if got := Summary(g2.HostReachable("A", "B", 2)); got != VerdictReachable {
		t.Fatalf("expired deny should be ignored, got %s", got)
	}
}

func TestConfidencePreserved(t *testing.T) {
	now := time.Now()
	h := []HostFacts{{HostID: "A", Subnets: []string{"10.12.0.0/24"}, Confidence: 0.75}}
	g := BuildLayeredGraphAt(h, nil, true, true, now)
	if got := g.hosts["A"].Confidence; got != 0.75 {
		t.Fatalf("confidence = %v, want 0.75", got)
	}
}
