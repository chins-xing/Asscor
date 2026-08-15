//go:build heartbeat

package heartbeat

import (
	"testing"

	"github.com/asscor/asscor/internal/kernel"
)

// TestBindAgentCertFirstRegistration binds a host to its certificate.
func TestBindAgentCertFirstRegistration(t *testing.T) {
	m := New()
	if !m.BindAgentCert("host-a", "fp-a") {
		t.Error("first registration should bind")
	}
	rec := m.agents["host-a"]
	if rec == nil || rec.CertFingerprint != "fp-a" {
		t.Errorf("binding not stored: %+v", rec)
	}
}

// TestBindAgentCertRejectsSameHostDifferentCert: a host already bound to one
// certificate cannot switch to another (impersonation attempt).
func TestBindAgentCertRejectsSameHostDifferentCert(t *testing.T) {
	m := New()
	m.BindAgentCert("host-a", "fp-a")
	if m.BindAgentCert("host-a", "fp-b") {
		t.Error("host bound to fp-a must reject fp-b")
	}
	if rec := m.agents["host-a"]; rec.CertFingerprint != "fp-a" {
		t.Errorf("binding must stay fp-a, got %q", rec.CertFingerprint)
	}
}

// TestBindAgentCertRejectsCertUsedByAnotherHost: one certificate, one
// identity — a certificate bound to host-a cannot register as host-b.
func TestBindAgentCertRejectsCertUsedByAnotherHost(t *testing.T) {
	m := New()
	m.BindAgentCert("host-a", "fp-a")
	if m.BindAgentCert("host-b", "fp-a") {
		t.Error("certificate fp-a already bound to host-a must not bind host-b")
	}
	if _, ok := m.agents["host-b"]; ok {
		t.Error("host-b must not be registered with a foreign certificate")
	}
}

// TestVerifyAgentCert: verification passes for the bound fingerprint, fails
// for a different one, and passes when host is not yet bound (first contact).
func TestVerifyAgentCert(t *testing.T) {
	m := New()

	// Not bound yet → first contact allowed.
	if !m.VerifyAgentCert("host-new", "fp-x") {
		t.Error("unbound host should verify (first contact)")
	}

	m.BindAgentCert("host-a", "fp-a")
	if !m.VerifyAgentCert("host-a", "fp-a") {
		t.Error("matching fingerprint should verify")
	}
	if m.VerifyAgentCert("host-a", "fp-evil") {
		t.Error("different fingerprint must fail verification")
	}
	if !m.VerifyAgentCert("host-b", "fp-b") {
		t.Error("unbound host should verify")
	}
}

// TestBindAgentCertEmptyFingerprint: no mTLS (development) skips binding and
// always succeeds.
func TestBindAgentCertEmptyFingerprint(t *testing.T) {
	m := New()
	if !m.BindAgentCert("host-a", "") {
		t.Error("empty fingerprint (no mTLS) must succeed")
	}
	if !m.VerifyAgentCert("host-a", "") {
		t.Error("empty fingerprint must always verify")
	}
	if rec := m.agents["host-a"]; rec != nil && rec.CertFingerprint != "" {
		t.Errorf("empty fingerprint must not store a binding, got %q", rec.CertFingerprint)
	}
}

// TestRegisterAgentPreservesBinding: re-registration keeps the cert binding.
func TestRegisterAgentPreservesBinding(t *testing.T) {
	m := New()
	m.BindAgentCert("host-a", "fp-a")
	m.RegisterAgent("host-a", "h-a", "v0.2.3")
	rec := m.agents["host-a"]
	if rec == nil || rec.CertFingerprint != "fp-a" {
		t.Errorf("re-registration must preserve cert binding: %+v", rec)
	}
	if rec.Hostname != "h-a" || rec.Version != "v0.2.3" {
		t.Errorf("re-registration must update metadata: %+v", rec)
	}
}

// TestHeartbeatInterfaceSatisfied ensures the module satisfies the extended
// kernel.HeartbeatInterface contract.
func TestHeartbeatInterfaceSatisfied(t *testing.T) {
	var _ kernel.HeartbeatInterface = New()
}
