//go:build heartbeat

package heartbeat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/asscor/asscor/internal/kernel"
)

// TestIdentityBindingPersistsAcrossRestart verifies host_id ↔ cert-fingerprint
// bindings survive a kernel restart (persisted to disk and reloaded).
func TestIdentityBindingPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heartbeat_identity.json")

	// First "kernel run": bind host-a → fp-a.
	m1 := New()
	m1.identityPath = path
	if !m1.BindAgentCert("host-a", "fp-a") {
		t.Fatal("initial bind failed")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("identity file not persisted: %v", err)
	}
	if !m1.VerifyAgentCert("host-a", "fp-a") {
		t.Fatal("binding should verify before restart")
	}

	// Second "kernel run" (restart): reload persisted bindings.
	m2 := New()
	m2.identityPath = path
	m2.agents = make(map[string]*kernel.AgentRecord)
	m2.loadIdentityLocked()

	if !m2.VerifyAgentCert("host-a", "fp-a") {
		t.Error("binding must survive restart (reloaded from disk)")
	}
	if m2.VerifyAgentCert("host-a", "fp-evil") {
		t.Error("after restart, a different certificate must still be rejected")
	}
	if !m2.BindAgentCert("host-a", "fp-a") {
		t.Error("re-bind of the same fingerprint after restart should succeed")
	}
	if m2.BindAgentCert("host-a", "fp-evil") {
		t.Error("re-bind of a different fingerprint after restart must be rejected")
	}
}

// TestIdentityBindingPersistEmptyPath: no data dir configured → no persistence,
// bindings stay in memory only.
func TestIdentityBindingPersistEmptyPath(t *testing.T) {
	m := New()
	if !m.BindAgentCert("host-a", "fp-a") {
		t.Fatal("bind failed")
	}
	m.saveIdentityLocked() // must not panic or write anywhere
}
