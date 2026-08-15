package mitreengage

import (
	"sort"
	"sync"
	"time"
)

// CaptureQuality ranks the intelligence value of a capture. The design goal is
// to balance capture quantity with quality — prioritize high-value captures
// (real attacker activity) over low-value ones (automated port scans).
type CaptureQuality float64

const (
	// QualityPortScan is a low-value automated scan hit.
	QualityPortScan CaptureQuality = 0.15
	// QualityDecoyAccess is a medium-value decoy file/credential access.
	QualityDecoyAccess CaptureQuality = 0.55
	// QualityCredentialUse is a high-value honey credential usage attempt.
	QualityCredentialUse CaptureQuality = 0.85
)

// CaptureInfo is the structured intelligence collected AFTER a decoy triggers.
// This is the core value of MITRE Engage — not the decoy itself, but the
// attacker behavior it reveals.
type CaptureInfo struct {
	SourceIP    string         `json:"source_ip"`
	SourcePort  string         `json:"source_port,omitempty"`
	Timestamp   time.Time      `json:"timestamp"`
	TriggerType string         `json:"trigger_type"`         // "honeypot" | "honeytoken" | "honey_credential"
	Credential  string         `json:"credential,omitempty"` // what the attacker tried (username/password)
	File        string         `json:"file,omitempty"`       // what decoy file was touched
	Technique   string         `json:"technique,omitempty"`  // inferred ATT&CK technique (e.g. T1078, T1110)
	Quality     CaptureQuality `json:"quality"`              // 0..1 intelligence value
}

// Collector aggregates capture intelligence. It deduplicates low-value noise
// and surfaces high-value attacker behavior.
type Collector struct {
	mu         sync.Mutex
	captures   []CaptureInfo
	minQuality CaptureQuality // captures below this threshold are dropped
	maxSize    int            // ring buffer bound
}

// NewCollector creates a capture collector with quality floor and size bound.
func NewCollector(minQuality CaptureQuality, maxSize int) *Collector {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &Collector{minQuality: minQuality, maxSize: maxSize}
}

// Record adds a capture, dropping those below the quality floor.
// Low-value automated scans are filtered here to balance quality vs quantity.
func (c *Collector) Record(cap CaptureInfo) {
	if cap.Quality < c.minQuality {
		return // drop low-value noise — balance capture quantity with quality
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.captures = append(c.captures, cap)
	if len(c.captures) > c.maxSize {
		c.captures = c.captures[len(c.captures)-c.maxSize:]
	}
}

// Captures returns all retained captures sorted by quality descending.
func (c *Collector) Captures() []CaptureInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]CaptureInfo, len(c.captures))
	copy(out, c.captures)
	sort.Slice(out, func(i, j int) bool { return out[i].Quality > out[j].Quality })
	return out
}

// HighValue returns captures above the given quality threshold (e.g. only
// credential-use evidence, excluding port-scan noise).
func (c *Collector) HighValue(threshold CaptureQuality) []CaptureInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []CaptureInfo
	for _, cap := range c.captures {
		if cap.Quality >= threshold {
			out = append(out, cap)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Quality > out[j].Quality })
	return out
}

// Count returns the number of retained captures (post quality filter).
func (c *Collector) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.captures)
}
