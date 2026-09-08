//go:build decoyd

package main

import (
	"testing"
	"time"
)

// TestRetainHitBounded (audit RC-L1): the retained hit log must stop growing
// at maxRetainedHits while newer hits keep streaming to stdout.
func TestRetainHitBounded(t *testing.T) {
	var hits []decoyHit
	// Record a monotonically increasing RemoteIP suffix as the append order
	// marker (ports are a poor proxy past 65535).
	for i := 0; i < maxRetainedHits+100; i++ {
		h := decoyHit{Port: i, Timestamp: time.Unix(int64(i), 0)}
		hits = retainHit(hits, h)
	}
	if len(hits) != maxRetainedHits {
		t.Fatalf("retained hits = %d, want cap %d", len(hits), maxRetainedHits)
	}
	// Append-only until cap: oldest kept, newest 100 dropped.
	if hits[0].Port != 0 {
		t.Errorf("first retained port = %d, want 0", hits[0].Port)
	}
	if hits[len(hits)-1].Port != maxRetainedHits-1 {
		t.Errorf("last retained port = %d, want %d", hits[len(hits)-1].Port, maxRetainedHits-1)
	}
}

// TestRetainHitAppendsUnderCap: before the cap, hits accumulate.
func TestRetainHitAppendsUnderCap(t *testing.T) {
	var hits []decoyHit
	hits = retainHit(hits, decoyHit{Port: 1})
	hits = retainHit(hits, decoyHit{Port: 2})
	if len(hits) != 2 {
		t.Fatalf("len = %d, want 2", len(hits))
	}
}
