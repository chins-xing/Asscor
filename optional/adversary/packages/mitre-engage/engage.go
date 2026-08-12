package mitreengage

import (
	"context"
	"sync"

	"github.com/asscor/asscor/internal/kernel"
)

// EngageBlocker is a lightweight MITRE Engage implementation of kernel.Blocker.
// It combines:
//   - honeypot (port decoys)  → MITRE Engage "Expose" goal
//   - honeytoken (file decoys) → MITRE Engage "Elicit" goal
//
// Zero heavyweight dependencies; pure Go stdlib for the deception primitives.
type EngageBlocker struct {
	mu      sync.Mutex
	honey   *honeypot
	tokens  *honeytokenDeployer
	blocked map[string]bool
	ports   []int
}

// NewEngageBlocker creates an active-defense blocker with optional hit hooks.
func NewEngageBlocker(decoyRoot string) *EngageBlocker {
	b := &EngageBlocker{
		blocked: make(map[string]bool),
		ports:   CommonAttackPorts,
	}
	b.honey = NewHoneypot(nil)
	b.tokens = NewHoneytokenDeployer(decoyRoot, nil)
	return b
}

// SetPorts overrides the decoy ports to listen on (useful for tests/ephemeral).
func (b *EngageBlocker) SetPorts(ports []int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ports = ports
}

// SetHitHooks wires callbacks fired when a decoy is triggered. A caller can
// publish these to the kernel's locate.threat_active extension point.
func (b *EngageBlocker) SetHitHooks(onPortHit func(honeypotHit), onTokenHit func(honeytokenHit)) {
	b.honey = NewHoneypot(onPortHit)
	b.tokens = NewHoneytokenDeployer(b.tokens.root, onTokenHit)
}

// Block deploys decoys against the attacker location (kernel.Blocker impl).
func (b *EngageBlocker) Block(ctx context.Context, loc *kernel.AttackerLocation) (*kernel.BlockResult, error) {
	if loc == nil {
		return &kernel.BlockResult{Blocked: false, Err: "nil location"}, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	// Deploy port decoys on the active subnets (all ports globally — honeypot
	// binds on this host; in a real deployment this runs on a decoy host).
	if err := b.honey.Start(b.ports); err != nil {
		return &kernel.BlockResult{Blocked: false, Err: err.Error()}, err
	}

	// Deploy file decoys on the foothold host.
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

// Unblock removes decoys (kernel.Blocker impl).
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

// Hits returns recorded decoy hits — evidence of attacker exposure.
func (b *EngageBlocker) Hits() []honeypotHit {
	return b.honey.Hits()
}

// Compile-time assertion that EngageBlocker satisfies kernel.Blocker.
var _ kernel.Blocker = (*EngageBlocker)(nil)
