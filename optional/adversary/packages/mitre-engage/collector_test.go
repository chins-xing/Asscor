package mitreengage

import (
	"testing"
	"time"
)

func TestCollectorQualityFilter(t *testing.T) {
	c := NewCollector(QualityDecoyAccess, 100)

	// Low-value port scan — should be dropped (below quality floor).
	c.Record(CaptureInfo{SourceIP: "1.2.3.4", TriggerType: "honeypot", Quality: QualityPortScan, Timestamp: time.Now()})

	// High-value decoy access — should be retained.
	c.Record(CaptureInfo{SourceIP: "5.6.7.8", TriggerType: "honeytoken", Quality: QualityDecoyAccess, Timestamp: time.Now()})

	if c.Count() != 1 {
		t.Fatalf("expected 1 retained capture (port scan filtered), got %d", c.Count())
	}
}

func TestCollectorHighValue(t *testing.T) {
	c := NewCollector(QualityPortScan, 100)

	c.Record(CaptureInfo{SourceIP: "1.1.1.1", TriggerType: "honeypot", Quality: QualityPortScan, Timestamp: time.Now()})
	c.Record(CaptureInfo{SourceIP: "2.2.2.2", TriggerType: "honeytoken", Quality: QualityDecoyAccess, Timestamp: time.Now()})
	c.Record(CaptureInfo{SourceIP: "3.3.3.3", TriggerType: "honey_credential", Quality: QualityCredentialUse, Timestamp: time.Now()})

	if c.Count() != 3 {
		t.Fatalf("expected 3 captures, got %d", c.Count())
	}

	high := c.HighValue(QualityCredentialUse)
	if len(high) != 1 {
		t.Fatalf("expected 1 high-value capture (credential use), got %d", len(high))
	}
	if high[0].SourceIP != "3.3.3.3" {
		t.Errorf("expected source 3.3.3.3, got %s", high[0].SourceIP)
	}
}

func TestCollectorQualitySorting(t *testing.T) {
	c := NewCollector(QualityPortScan, 100)

	c.Record(CaptureInfo{SourceIP: "low", Quality: QualityPortScan, Timestamp: time.Now()})
	c.Record(CaptureInfo{SourceIP: "high", Quality: QualityCredentialUse, Timestamp: time.Now()})
	c.Record(CaptureInfo{SourceIP: "mid", Quality: QualityDecoyAccess, Timestamp: time.Now()})

	caps := c.Captures()
	if len(caps) != 3 {
		t.Fatalf("expected 3, got %d", len(caps))
	}
	if caps[0].SourceIP != "high" || caps[1].SourceIP != "mid" || caps[2].SourceIP != "low" {
		t.Errorf("expected sort [high mid low], got [%s %s %s]", caps[0].SourceIP, caps[1].SourceIP, caps[2].SourceIP)
	}
}
