package federation

import (
	"errors"
	"testing"
)

func TestCollectorDedupAndUpdate(t *testing.T) {
	c := NewCollector()
	if err := c.Apply(NodeReport{NodeID: "nk1", Hosts: 3, ConfigHash: "aaa"}); err != nil {
		t.Fatalf("Apply nk1: %v", err)
	}
	if err := c.Apply(NodeReport{NodeID: "nk2", Hosts: 4, ConfigHash: "ccc"}); err != nil {
		t.Fatalf("Apply nk2: %v", err)
	}
	// Same node_id again: must update in place, not append a duplicate.
	if err := c.Apply(NodeReport{NodeID: "nk1", Hosts: 10, ConfigHash: "bbb"}); err != nil {
		t.Fatalf("Apply nk1 update: %v", err)
	}

	if got := c.Count(); got != 2 {
		t.Fatalf("Count = %d, want 2 (dedup by node_id)", got)
	}
	nodes := c.Nodes()
	if len(nodes) != 2 {
		t.Fatalf("Nodes len = %d, want 2", len(nodes))
	}
	if nodes[0].NodeID != "nk1" || nodes[1].NodeID != "nk2" {
		t.Errorf("Nodes order = %s,%s, want sorted nk1,nk2", nodes[0].NodeID, nodes[1].NodeID)
	}
	if nodes[0].Hosts != 10 || nodes[0].ConfigHash != "bbb" {
		t.Errorf("nk1 = %+v, want the latest report", nodes[0])
	}
	if nodes[0].ReceivedAt.IsZero() {
		t.Error("ReceivedAt was not stamped by the collector")
	}
	if nodes[0].ReportedAt.IsZero() {
		t.Error("ReportedAt should default to now when omitted")
	}

	if n, ok := c.Get("nk2"); !ok || n.Hosts != 4 {
		t.Errorf("Get(nk2) = %+v, %v", n, ok)
	}
	if _, ok := c.Get("missing"); ok {
		t.Error("Get(missing) should report not found")
	}
	if c.LastUpdated().IsZero() {
		t.Error("LastUpdated is zero after Apply")
	}
}

func TestMasterStateAlias(t *testing.T) {
	st := NewMasterState()
	if err := st.Apply(NodeReport{NodeID: "nk1", Hosts: 1}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := len(st.GetNodes()); got != 1 {
		t.Errorf("GetNodes len = %d, want 1", got)
	}
}

func TestCollectorRejectsEmptyNodeID(t *testing.T) {
	c := NewCollector()
	err := c.Apply(NodeReport{NodeID: "   "})
	if !errors.Is(err, ErrMissingNodeID) {
		t.Fatalf("Apply(empty node_id) = %v, want ErrMissingNodeID", err)
	}
	if c.Count() != 0 {
		t.Errorf("Count = %d after rejected report, want 0", c.Count())
	}
}

func TestCollectorNodesAreCopies(t *testing.T) {
	c := NewCollector()
	_ = c.Apply(NodeReport{
		NodeID: "nk1",
		Params: map[string]string{"prism.debt_alpha": "1.2"},
		Zones:  map[string]ZoneSummary{"dma": {Hosts: 1}},
	})
	nodes := c.Nodes()
	nodes[0].Params["prism.debt_alpha"] = "mutated"
	nodes[0].Zones["dma"] = ZoneSummary{Hosts: 99}

	again := c.Nodes()
	if again[0].Params["prism.debt_alpha"] != "1.2" {
		t.Errorf("Params map is shared with the collector: %v", again[0].Params)
	}
	if again[0].Zones["dma"].Hosts != 1 {
		t.Errorf("Zones map is shared with the collector: %v", again[0].Zones)
	}
}

func TestNodeReportOverallAvgSSAM(t *testing.T) {
	r := NodeReport{Zones: map[string]ZoneSummary{
		"dma": {Hosts: 2, Scored: 2, AvgSSAM: 80},
		"web": {Hosts: 3, Scored: 1, AvgSSAM: 50},
		"new": {Hosts: 4, Scored: 0},
	}}
	want := (80.0*2 + 50.0) / 3.0
	if got := r.OverallAvgSSAM(); got != want {
		t.Errorf("OverallAvgSSAM = %v, want %v (weighted by scored hosts)", got, want)
	}

	if got := (NodeReport{}).OverallAvgSSAM(); got != 0 {
		t.Errorf("empty report avg = %v, want 0", got)
	}
}

func TestConfigHashAndShortHash(t *testing.T) {
	a := ConfigHash(map[string]string{"srd.aggregation": "rss", "prism.debt_alpha": "1.2"})
	b := ConfigHash(map[string]string{"prism.debt_alpha": "1.2", "srd.aggregation": "rss"})
	if a != b {
		t.Errorf("ConfigHash must be map-order independent: %s != %s", a, b)
	}
	if a == ConfigHash(map[string]string{"prism.debt_alpha": "1.8", "srd.aggregation": "rss"}) {
		t.Error("ConfigHash ignored a changed parameter")
	}
	if len(ShortHash(a)) != 16 {
		t.Errorf("ShortHash len = %d, want 16", len(ShortHash(a)))
	}
	if ShortHash("short") != "short" {
		t.Error("ShortHash should keep short input unchanged")
	}
}
