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
