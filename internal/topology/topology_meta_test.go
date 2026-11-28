package topology

import "testing"

func TestRecordNetworkFactsMetadata(t *testing.T) {
	id := "meta-host-test"
	RecordNetworkFacts(id, []string{"10.17.0.0/24"}, "internal", nil, false, nil, true, nil, []string{"10.17.0.1"}, true, false)
	n := GetNode(id)
	if n == nil {
		t.Fatal("node missing")
	}
	if n.ObservedAt.IsZero() || n.Confidence != 1.0 {
		t.Fatalf("metadata not set: %+v", n)
	}
}

func TestRecordNetworkFactsInvalidDrop(t *testing.T) {
	id := "invalid-drop-test"
	RecordNetworkFacts(id, []string{"10.19.0.0/24"}, "internal", nil, false, nil, true, nil, []string{"10.19.0.1"}, true, false, true)
	n := GetNode(id)
	if n == nil || !n.StatefulInvalidDrop {
		t.Fatalf("invalid drop not recorded: %+v", n)
	}
}
