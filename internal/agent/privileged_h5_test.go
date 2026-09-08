//go:build linux

package agent

import (
	"strings"
	"testing"
	"time"
)

// TestIsolationExceptionRules covers audit H-5: isolation must install ACCEPT
// rules for established traffic and the management ports (SSH 22 by default
// plus any configured IsolationKeepPorts) so an isolate trigger can never
// sever the operator's own management channel.
func TestIsolationExceptionRules(t *testing.T) {
	cfg := PrivilegedConfig{IsolationKeepPorts: []int{22022, 8443}}
	p := &PrivilegedAgent{cfg: cfg}

	rules := p.isolationExceptionRules()
	if len(rules) != 4 { // established + 22 + 22022 + 8443
		t.Fatalf("got %d exception rules, want 4: %v", len(rules), rules)
	}

	joined := ""
	for _, r := range rules {
		joined += strings.Join(r, " ") + "\n"
	}
	for _, want := range []string{
		"INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"--dport 22 -j ACCEPT",
		"--dport 22022 -j ACCEPT",
		"--dport 8443 -j ACCEPT",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("exception rules missing %q:\n%s", want, joined)
		}
	}
}

// TestIsolationKeepPortsDeduplicate22: a configured port equal to the default
// SSH 22 must not produce a duplicate rule.
func TestIsolationKeepPortsDeduplicate22(t *testing.T) {
	p := &PrivilegedAgent{cfg: PrivilegedConfig{IsolationKeepPorts: []int{22, 2222, 22}}}
	rules := p.isolationExceptionRules()
	if len(rules) != 3 { // established + 22 + 2222
		t.Fatalf("got %d rules, want 3 (dedup of 22): %v", len(rules), rules)
	}
}

// TestIsolationCooldown: after a successful isolation the agent refuses a
// second isolate inside the cooldown window (audit H-5 — no firewall churn
// from repeated/looped triggers), and de-isolation resets the window.
func TestIsolationCooldown(t *testing.T) {
	p := &PrivilegedAgent{}
	// Simulate a recent successful isolation without touching iptables.
	p.lastIsolation = time.Now().Add(-5 * time.Second)
	if !p.isolationOnCooldown() {
		t.Fatal("recent isolation must be on cooldown")
	}

	// De-isolation resets the window.
	p.lastIsolation = time.Time{}
	if p.isolationOnCooldown() {
		t.Error("zero lastIsolation must not be on cooldown")
	}

	// Older than the window → not on cooldown.
	p.lastIsolation = time.Now().Add(-(isolationCooldown + time.Minute))
	if p.isolationOnCooldown() {
		t.Error("isolation older than the cooldown window must not be on cooldown")
	}
}
