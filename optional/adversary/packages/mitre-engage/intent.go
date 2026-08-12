package mitreengage

import (
	"context"
	"sync"
)

// Intent classifies the attacker's inferred objective (from ATT&CK technique
// mapping). Each intent maps to a lightweight deception plan — the goal is to
// make the attacker "feel there is a breach point", not to perfectly simulate
// real assets ("good enough" principle).
type Intent string

const (
	// IntentLateralMovement — attacker probing for remote access (T1021).
	IntentLateralMovement Intent = "lateral_movement"
	// IntentCredentialAccess — attacker hunting credentials (T1003).
	IntentCredentialAccess Intent = "credential_access"
	// IntentExfiltration — attacker stealing data (T1041).
	IntentExfiltration Intent = "exfiltration"
	// IntentWebExploit — attacker probing web apps (T1190).
	IntentWebExploit Intent = "web_exploit"
	// IntentDiscovery — attacker scanning the network (T1046).
	IntentDiscovery Intent = "discovery"
)

// DeceptionPlan describes the lightweight decoys to deploy for an intent.
type DeceptionPlan struct {
	Intent Intent
	Ports  []int       // suspicious services to expose (active exposure)
	Tokens []DecoySpec // fake intelligence to drop (deception info)
}

// deceptionPlans maps each intent to a "good enough" decoy set — all pure
// Go stdlib, zero heavyweight honeypot frameworks.
var deceptionPlans = map[Intent]DeceptionPlan{
	IntentLateralMovement: {
		Intent: IntentLateralMovement,
		Ports:  []int{22, 3389, 5985}, // fake SSH / RDP / WinRM
		Tokens: []DecoySpec{
			{Path: ".ssh/id_rsa.bak", Content: "-----BEGIN OPENSSH PRIVATE KEY-----\n(decoy)\n-----END OPENSSH PRIVATE KEY-----\n", Kind: "credential"},
		},
	},
	IntentCredentialAccess: {
		Intent: IntentCredentialAccess,
		Ports:  []int{},
		Tokens: []DecoySpec{
			{Path: "backup/credentials.txt", Content: "admin:Spring2026!\nservice:honeytoken\n", Kind: "credential"},
			{Path: ".config/db.conf", Content: "DB_PASS=decoy-password\n", Kind: "credential"},
		},
	},
	IntentExfiltration: {
		Intent: IntentExfiltration,
		Ports:  []int{},
		Tokens: []DecoySpec{
			{Path: "documents/customer_data.csv", Content: "id,name,ssn\n1,decoy,000-00-0000\n", Kind: "file"},
			{Path: "archive/financials.xlsx", Content: "(decoy financial data)", Kind: "file"},
		},
	},
	IntentWebExploit: {
		Intent: IntentWebExploit,
		Ports:  []int{8080, 8443}, // fake web / TLS web
		Tokens: []DecoySpec{
			{Path: "www/index.html", Content: "<html>(decoy)</html>\n", Kind: "file"},
		},
	},
	IntentDiscovery: {
		Intent: IntentDiscovery,
		Ports:  []int{21, 23, 445, 9200, 6379}, // common scan targets
		Tokens: []DecoySpec{},
	},
}

// GuideResult reports what a guidance round deployed.
type GuideResult struct {
	Intent   Intent
	Ports    []int
	Tokens   []string
	Captures []CaptureInfo
}

// IntentGuider is an intent-driven lightweight deception engine. Given an
// inferred intent, it actively exposes suspicious services (fake ports) and
// drops fake intelligence (decoy files) so the attacker reveals themselves.
type IntentGuider struct {
	mu        sync.Mutex
	honey     *honeypot
	tokens    *honeytokenDeployer
	collector *Collector
	deployed  map[Intent]bool
}

// NewIntentGuider creates an intent-driven guider with a quality-filtered collector.
func NewIntentGuider(decoyRoot string) *IntentGuider {
	g := &IntentGuider{
		deployed:  make(map[Intent]bool),
		collector: NewCollector(QualityPortScan, 1000),
	}
	g.honey = NewHoneypot(func(hit honeypotHit) {
		g.collector.Record(CaptureInfo{
			SourceIP:    hit.RemoteIP,
			SourcePort:  hit.RemotePort,
			Timestamp:   hit.Timestamp,
			TriggerType: "honeypot",
			Quality:     QualityPortScan,
		})
	})
	g.tokens = NewHoneytokenDeployer(decoyRoot, func(hit honeytokenHit) {
		g.collector.Record(CaptureInfo{
			Timestamp:   hit.Timestamp,
			TriggerType: "honeytoken",
			File:        hit.Path,
			Quality:     QualityDecoyAccess,
		})
	})
	return g
}

// Guide deploys the deception plan for an intent (idempotent per intent).
func (g *IntentGuider) Guide(ctx context.Context, intent Intent) (*GuideResult, error) {
	plan, ok := deceptionPlans[intent]
	if !ok {
		plan = deceptionPlans[IntentDiscovery]
	}

	g.mu.Lock()
	if g.deployed[intent] {
		g.mu.Unlock()
		return &GuideResult{Intent: intent}, nil // already guided for this intent
	}
	g.deployed[intent] = true
	g.mu.Unlock()

	// Good-enough principle: port-bind failures (already in use) are non-fatal —
	// the honeytokens still deploy, and the attacker still sees "a breach point".
	_ = g.honey.Start(plan.Ports)
	if err := g.tokens.Deploy(plan.Tokens); err != nil {
		return nil, err
	}

	return &GuideResult{
		Intent: intent,
		Ports:  plan.Ports,
		Tokens: g.tokens.Decoys(),
	}, nil
}

// RemoveAll tears down all deployed decoys.
func (g *IntentGuider) RemoveAll() {
	g.honey.Stop()
	g.tokens.Remove()
	g.mu.Lock()
	g.deployed = make(map[Intent]bool)
	g.mu.Unlock()
}

// Captures returns quality-filtered captures (intelligence for the next round).
func (g *IntentGuider) Captures() []CaptureInfo {
	return g.collector.Captures()
}

// HighValue returns captures above the given quality threshold.
func (g *IntentGuider) HighValue(threshold CaptureQuality) []CaptureInfo {
	return g.collector.HighValue(threshold)
}
