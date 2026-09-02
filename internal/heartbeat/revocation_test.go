//go:build heartbeat

package heartbeat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/asscor/asscor/internal/kernel"
)

// TestRevokeCertRejectsAtAllCheckpoints: after revocation, the fingerprint is
// rejected by verification, binding, and listing — and the host it was bound
// to is unbound so it can re-register with a new certificate.
func TestRevokeCertRejectsAtAllCheckpoints(t *testing.T) {
	m := New()
	m.agents = make(map[string]*kernel.AgentRecord)
	if !m.BindAgentCert("host-a", "fp-a") {
		t.Fatal("initial bind failed")
	}

	if err := m.RevokeCert("fp-a", "compromised"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if !m.IsCertRevoked("fp-a") {
		t.Error("fp-a must be marked revoked")
	}
	if m.VerifyAgentCert("host-a", "fp-a") {
		t.Error("revoked fingerprint must never verify, even with matching binding")
	}
	if m.BindAgentCert("host-a", "fp-a") {
		t.Error("revoked fingerprint must not re-bind")
	}
	if rec := m.agents["host-a"]; rec == nil || rec.CertFingerprint != "" {
		t.Errorf("host bound to the revoked cert must be unbound, got %+v", rec)
	}

	revoked := m.ListRevokedCerts()
	if len(revoked) != 1 || revoked[0].Fingerprint != "fp-a" || revoked[0].Reason != "compromised" {
		t.Errorf("unexpected revocation list: %+v", revoked)
	}
}

// TestRevokeCertAllowsRebindWithNewCert: after revoking a compromised
// certificate, the same host can re-register with a freshly issued one.
func TestRevokeCertAllowsRebindWithNewCert(t *testing.T) {
	m := New()
	m.agents = make(map[string]*kernel.AgentRecord)
	m.BindAgentCert("host-a", "fp-a")

	if err := m.RevokeCert("fp-a", "stolen"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Old (revoked) cert still rejected, new cert binds as first contact.
	if m.BindAgentCert("host-a", "fp-a") {
		t.Error("revoked cert must not re-bind")
	}
	if !m.BindAgentCert("host-a", "fp-new") {
		t.Error("new cert must bind after the old one was revoked")
	}
	if rec := m.agents["host-a"]; rec == nil || rec.CertFingerprint != "fp-new" {
		t.Errorf("binding must be fp-new, got %+v", rec)
	}
}

// TestRevokeCertDoubleRevokeAndUnrevoke: double revoke errors; unrevoke
// restores usability; double unrevoke errors.
func TestRevokeCertDoubleRevokeAndUnrevoke(t *testing.T) {
	m := New()
	m.agents = make(map[string]*kernel.AgentRecord)
	if err := m.RevokeCert("fp-a", ""); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := m.RevokeCert("fp-a", ""); err == nil {
		t.Error("second revoke must error")
	}

	if err := m.UnrevokeCert("fp-a"); err != nil {
		t.Fatalf("unrevoke: %v", err)
	}
	if m.IsCertRevoked("fp-a") {
		t.Error("fp-a must not be revoked after unrevoke")
	}
	if err := m.UnrevokeCert("fp-a"); err == nil {
		t.Error("unrevoke of a non-revoked fingerprint must error")
	}
	if err := m.UnrevokeCert("fp-never"); err == nil {
		t.Error("unrevoke of an unknown fingerprint must error")
	}
}

// TestRevokeCertPersistsAcrossRestart: revocations survive a kernel restart
// (persisted to revoked_certificates.json and reloaded).
func TestRevokeCertPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "heartbeat_identity.json")
	revPath := filepath.Join(dir, "revoked_certificates.json")

	// Run 1: bind + revoke (persist).
	m1 := New()
	m1.identityPath = idPath
	m1.revokedPath = revPath
	if !m1.BindAgentCert("host-a", "fp-a") {
		t.Fatal("bind failed")
	}
	if err := m1.RevokeCert("fp-a", "compromised"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := os.Stat(revPath); err != nil {
		t.Fatalf("revocation file not persisted: %v", err)
	}

	// Run 2 (kernel restart): reload both.
	m2 := New()
	m2.identityPath = idPath
	m2.revokedPath = revPath
	m2.agents = make(map[string]*kernel.AgentRecord)
	m2.revoked = make(map[string]kernel.RevokedCertInfo)
	m2.loadIdentityLocked()
	m2.loadRevokedLocked()

	if !m2.IsCertRevoked("fp-a") {
		t.Error("revocation must survive restart (reloaded from disk)")
	}
	if m2.VerifyAgentCert("host-a", "fp-a") {
		t.Error("revoked fingerprint must still be rejected after restart")
	}
	// The unbound state must also survive: host-a has no binding after reload
	// (either no record or an empty CertFingerprint).
	if rec := m2.agents["host-a"]; rec != nil && rec.CertFingerprint != "" {
		t.Errorf("unbound-after-revoke state must persist, got %+v", rec)
	}
	// Re-provisioning with a fresh cert must work after restart.
	if !m2.BindAgentCert("host-a", "fp-new") {
		t.Error("host must be able to re-register with a new cert after restart")
	}
}

// TestRevokeCertInvalidFingerprints: empty fingerprint cannot be revoked.
func TestRevokeCertInvalidFingerprints(t *testing.T) {
	m := New()
	m.agents = make(map[string]*kernel.AgentRecord)
	if err := m.RevokeCert("", "x"); err == nil {
		t.Error("revoking an empty fingerprint must error")
	}
	if err := m.UnrevokeCert(""); err == nil {
		t.Error("unrevoking an empty fingerprint must error")
	}
}

// TestVerifyAgentCertRevokedUnboundHost: a revoked certificate is rejected
// even for a host that was never bound to it (first-contact is not granted to
// revoked fingerprints).
func TestVerifyAgentCertRevokedUnboundHost(t *testing.T) {
	m := New()
	m.agents = make(map[string]*kernel.AgentRecord)
	if err := m.RevokeCert("fp-evil", ""); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if m.VerifyAgentCert("host-new", "fp-evil") {
		t.Error("revoked fingerprint must not verify even for an unbound host")
	}
	if m.BindAgentCert("host-new", "fp-evil") {
		t.Error("revoked fingerprint must not bind to a new host")
	}
}

// TestResetIdentityBindingsClearsAllAnchors: after a certificate-fleet rebuild
// (CA replacement / mass rotation), every stale host↔certificate binding must
// be clearable so agents can re-register with freshly issued certificates
// (A-1 cluster incident recovery). Revocations survive the reset.
func TestResetIdentityBindingsClearsAllAnchors(t *testing.T) {
	dir := t.TempDir()
	m := New()
	m.identityPath = filepath.Join(dir, "heartbeat_identity.json")
	m.agents = make(map[string]*kernel.AgentRecord)
	m.BindAgentCert("host-a", "fp-old-a")
	m.BindAgentCert("host-b", "fp-old-b")
	if err := m.RevokeCert("fp-stolen", "compromised"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	n, err := m.ResetIdentityBindings()
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if n != 2 {
		t.Errorf("cleared = %d, want 2", n)
	}

	// Bindings gone: agents can re-register first-contact with new certs.
	if rec := m.agents["host-a"]; rec == nil || rec.CertFingerprint != "" {
		t.Errorf("host-a binding must be cleared, got %+v", rec)
	}
	if !m.BindAgentCert("host-a", "fp-new-a") {
		t.Error("host-a must re-bind with a fresh cert after reset")
	}
	if !m.BindAgentCert("host-b", "fp-new-b") {
		t.Error("host-b must re-bind with a fresh cert after reset")
	}

	// Revocations are an independent security ledger — they survive.
	if !m.IsCertRevoked("fp-stolen") {
		t.Error("revocation list must survive a binding reset")
	}
	if m.VerifyAgentCert("host-new", "fp-stolen") {
		t.Error("revoked fingerprint must stay rejected after a binding reset")
	}
}

// TestResetIdentityBindingsPersistsAndReloads: the cleared state is written
// to disk; a kernel restart reloads an empty binding set, and only fresh
// certificates can bind afterwards.
func TestResetIdentityBindingsPersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heartbeat_identity.json")

	m1 := New()
	m1.identityPath = path
	m1.agents = make(map[string]*kernel.AgentRecord)
	m1.BindAgentCert("host-a", "fp-old")
	if _, err := m1.ResetIdentityBindings(); err != nil {
		t.Fatalf("reset: %v", err)
	}

	// Disk must reflect the cleared state (no stale fp-old binding).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("identity file must exist after reset: %v", err)
	}
	if got := string(data); got == `{"host-a":"fp-old"}` {
		t.Error("reset must persist the cleared bindings, not the stale ones")
	}

	// Run 2 (kernel restart): reload — no binding may come back.
	m2 := New()
	m2.identityPath = path
	m2.agents = make(map[string]*kernel.AgentRecord)
	m2.loadIdentityLocked()
	if rec := m2.agents["host-a"]; rec != nil && rec.CertFingerprint != "" {
		t.Errorf("stale binding restored after restart, got %+v", rec)
	}
	if !m2.BindAgentCert("host-a", "fp-fresh") {
		t.Error("fresh cert must bind after restart with cleared bindings")
	}
}

// TestResetIdentityBindingsNoDataDir: without an initialized data dir there
// is nothing to reset — the call must fail loudly rather than silently no-op.
func TestResetIdentityBindingsNoDataDir(t *testing.T) {
	m := New()
	m.agents = make(map[string]*kernel.AgentRecord)
	if _, err := m.ResetIdentityBindings(); err == nil {
		t.Error("reset without a data dir must error")
	}
}
