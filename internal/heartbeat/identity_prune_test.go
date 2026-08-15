//go:build heartbeat

package heartbeat

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/asscor/asscor/internal/kernel"
)

// TestPruneKeepsIdentityAnchor reproduces the remote impersonation bug found
// on the live server: after a kernel restart the binding was reloaded from
// disk, but the liveness monitor pruned the record (zero LastSeen, agent not
// yet reconnected) before the agent came back — taking CertFingerprint with
// it. The next registration, even with a foreign certificate, was then
// treated as first contact and re-bound, silently overwriting the persisted
// identity. The anchor must survive monitor cycles.
func TestPruneKeepsIdentityAnchor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heartbeat_identity.json")

	// Run 1: bind host-a → fp-a (persist).
	m1 := New()
	m1.identityPath = path
	if !m1.BindAgentCert("host-a", "fp-a") {
		t.Fatal("run1 bind failed")
	}

	// Run 2 (kernel restart): reload the binding, then run the liveness
	// monitor before the agent reconnects — exactly the remote scenario.
	m2 := New()
	m2.identityPath = path
	m2.agents = make(map[string]*kernel.AgentRecord)
	m2.loadIdentityLocked()
	if rec := m2.agents["host-a"]; rec == nil || rec.CertFingerprint != "fp-a" {
		t.Fatalf("reload failed: %+v", rec)
	}
	m2.checkTimeouts()
	m2.pruneDeadAgents()

	// The anchor must survive the monitor cycles.
	rec := m2.agents["host-a"]
	if rec == nil {
		t.Fatal("prune must not delete a record carrying an identity binding")
	}
	if rec.CertFingerprint != "fp-a" {
		t.Fatalf("binding lost after prune: %q", rec.CertFingerprint)
	}

	// Legit reconnect with the bound cert must still match.
	if !m2.BindAgentCert("host-a", "fp-a") {
		t.Error("re-register with bound cert must match after reload + prune")
	}

	// The impersonation (foreign cert) must still be rejected.
	if m2.VerifyAgentCert("host-a", "fp-evil") {
		t.Error("different cert must fail verification after reload + prune")
	}
	if m2.BindAgentCert("host-a", "fp-evil") {
		t.Error("different cert must not re-bind after reload + prune")
	}
	if m2.agents["host-a"].CertFingerprint != "fp-a" {
		t.Errorf("binding must remain fp-a, got %q", m2.agents["host-a"].CertFingerprint)
	}

	// The persisted file must still hold the original binding.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("identity file gone: %v", err)
	}
	want := `{"host-a":"fp-a"}`
	if string(data) != want {
		t.Errorf("persisted identity must stay %s, got %s", want, string(data))
	}
}

// TestPruneKeepsAnchorOfLongOfflineBoundHost: even a bound host that has been
// offline for hours (beyond the 1h prune cutoff) keeps its identity anchor —
// liveness pruning and identity anchoring are orthogonal concerns.
func TestPruneKeepsAnchorOfLongOfflineBoundHost(t *testing.T) {
	m := New()
	m.agents = make(map[string]*kernel.AgentRecord)
	m.BindAgentCert("host-a", "fp-a")
	rec := m.agents["host-a"]
	rec.Active = true
	rec.LastSeen = time.Now().Add(-2 * time.Hour)

	m.pruneDeadAgents()

	if _, ok := m.agents["host-a"]; !ok {
		t.Fatal("bound host offline for hours must keep its identity anchor")
	}
	if m.VerifyAgentCert("host-a", "fp-evil") {
		t.Error("foreign cert must still be rejected for a long-offline bound host")
	}
}

// TestPruneRemovesUnboundDeadRecord: liveness pruning still works for records
// that carry no identity binding.
func TestPruneRemovesUnboundDeadRecord(t *testing.T) {
	m := New()
	m.agents = make(map[string]*kernel.AgentRecord)
	m.RegisterAgent("host-x", "hx", "v1")
	rec := m.agents["host-x"]
	rec.Active = false
	rec.LastSeen = time.Now().Add(-2 * time.Hour)

	m.pruneDeadAgents()

	if _, ok := m.agents["host-x"]; ok {
		t.Error("unbound dead record should still be pruned")
	}
}

// TestCheckTimeoutsSkipsNeverSeenAnchor: a binding restored from disk has a
// zero LastSeen until the agent connects; the monitor must not mark it timed
// out (and fire spurious alerts) at kernel boot.
func TestCheckTimeoutsSkipsNeverSeenAnchor(t *testing.T) {
	m := New()
	m.timeout = 60 * time.Second
	m.agents = make(map[string]*kernel.AgentRecord)
	m.agents["host-a"] = &kernel.AgentRecord{HostID: "host-a", CertFingerprint: "fp-a", Active: true}

	m.checkTimeouts()

	if rec := m.agents["host-a"]; !rec.Active {
		t.Error("a never-seen restored anchor must not be marked timed out at boot")
	}
}

// TestBoundHostTimeoutFiresButAnchorSurvives: once a bound host has actually
// connected, going offline does fire the timeout (Active=false), yet the
// anchor still survives the subsequent prune.
func TestBoundHostTimeoutFiresButAnchorSurvives(t *testing.T) {
	m := New()
	m.timeout = 60 * time.Second
	m.agents = make(map[string]*kernel.AgentRecord)
	m.BindAgentCert("host-a", "fp-a")
	m.RegisterAgent("host-a", "h-a", "v1") // LastSeen = now, Active = true
	rec := m.agents["host-a"]
	rec.LastSeen = time.Now().Add(-2 * time.Hour) // offline beyond timeout AND beyond prune cutoff

	m.checkTimeouts()
	m.pruneDeadAgents()

	if _, ok := m.agents["host-a"]; !ok {
		t.Fatal("anchor must survive timeout + prune")
	}
	if m.VerifyAgentCert("host-a", "fp-evil") {
		t.Error("foreign cert must still be rejected after timeout + prune")
	}
}
