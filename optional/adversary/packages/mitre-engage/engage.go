package mitreengage

import (
	"context"
	"sync"

	"github.com/asscor/asscor/internal/kernel"
)

// EngageBlocker is a lightweight MITRE Engage active-defense extension.
//
// Design emphasis (v0.2): the honeypot is deliberately light — it is NOT the
// primary defense (attackers easily recognize cheap decoys). The real value is
// the COLLECTED INTELLIGENCE after a decoy triggers. We balance capture
// quantity with quality: filter out automated port scans, surface high-value
// attacker behavior (credential use, decoy access).
type EngageBlocker struct {
	mu        sync.Mutex
	honey     *honeypot
	tokens    *honeytokenDeployer
	collector *Collector
	blocked   map[string]bool
	ports     []int
	onCapture func(CaptureInfo)
}

// NewEngageBlocker creates an active-defense blocker centered on intelligence
// collection. decoyRoot is where high-fidelity decoy files live.
func NewEngageBlocker(decoyRoot string) *EngageBlocker {
	b := &EngageBlocker{
		blocked:   make(map[string]bool),
		ports:     CommonAttackPorts,
		collector: NewCollector(QualityPortScan, 1000), // drop pure port scans
	}
	b.honey = NewHoneypot(nil)
	b.tokens = NewHoneytokenDeployer(decoyRoot, nil)
	return b
}

// SetPorts overrides decoy listen ports (useful for tests/ephemeral).
func (b *EngageBlocker) SetPorts(ports []int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ports = ports
}

// SetCaptureHook wires a callback fired on every retained (quality-filtered)
// capture. A caller can publish to locate.threat_active to feed attribution.
func (b *EngageBlocker) SetCaptureHook(fn func(CaptureInfo)) {
	b.onCapture = fn
}

// Block deploys decoys and arms intelligence collection (kernel.Blocker impl).
func (b *EngageBlocker) Block(ctx context.Context, loc *kernel.AttackerLocation) (*kernel.BlockResult, error) {
	if loc == nil {
		return &kernel.BlockResult{Blocked: false, Err: "nil location"}, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	// Honeypot is auxiliary — record connection sources as LOW-value captures.
	b.honey.onHit = func(hit honeypotHit) {
		b.recordCapture(CaptureInfo{
			SourceIP:    hit.RemoteIP,
			SourcePort:  hit.RemotePort,
			Timestamp:   hit.Timestamp,
			TriggerType: "honeypot",
			Quality:     QualityPortScan,
		})
	}
	if err := b.honey.Start(b.ports); err != nil {
		return &kernel.BlockResult{Blocked: false, Err: err.Error()}, err
	}

	// High-fidelity decoys are the PRIMARY collection source.
	b.tokens.onHit = func(hit honeytokenHit) {
		b.recordCapture(CaptureInfo{
			SourceIP:    loc.FootholdHost,
			Timestamp:   hit.Timestamp,
			TriggerType: "honeytoken",
			File:        hit.Path,
			Quality:     QualityDecoyAccess,
		})
	}
	specs := []DecoySpec{
		{Path: ".ssh/id_rsa.bak", Content: "-----BEGIN OPENSSH PRIVATE KEY-----\n(decoy)\n-----END OPENSSH PRIVATE KEY-----\n", Kind: "credential"},
		{Path: "backup/db_credentials.txt", Content: "DB_HOST=" + loc.FootholdHost + "\nDB_PASS=honey-token\n", Kind: "credential"},
	}
	if err := b.tokens.Deploy(specs); err != nil {
		b.honey.Stop()
		return &kernel.BlockResult{Blocked: false, Err: err.Error()}, err
	}

	b.blocked[loc.FootholdHost] = true
	return &kernel.BlockResult{Blocked: true, RuleID: "mitre-engage-decoy"}, nil
}

func (b *EngageBlocker) recordCapture(cap CaptureInfo) {
	if b.collector != nil {
		b.collector.Record(cap)
	}
	if b.onCapture != nil {
		b.onCapture(cap)
	}
}

// Unblock removes decoys and stops collection (kernel.Blocker impl).
func (b *EngageBlocker) Unblock(ctx context.Context, loc *kernel.AttackerLocation) error {
	if loc == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.honey.Stop()
	b.tokens.Remove()
	delete(b.blocked, loc.FootholdHost)
	return nil
}

// IsBlocked reports whether a host has active decoys (kernel.Blocker impl).
func (b *EngageBlocker) IsBlocked(ctx context.Context, hostID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.blocked[hostID]
}

// Captures returns quality-filtered captures (intelligence, not raw noise).
func (b *EngageBlocker) Captures() []CaptureInfo {
	if b.collector == nil {
		return nil
	}
	return b.collector.Captures()
}

// HighValue returns captures above the given quality threshold.
func (b *EngageBlocker) HighValue(threshold CaptureQuality) []CaptureInfo {
	if b.collector == nil {
		return nil
	}
	return b.collector.HighValue(threshold)
}

// Compile-time assertion that EngageBlocker satisfies kernel.Blocker.
var _ kernel.Blocker = (*EngageBlocker)(nil)
