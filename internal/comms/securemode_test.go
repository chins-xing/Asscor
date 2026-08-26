//go:build comms && heartbeat

package comms

import (
	"context"
	"testing"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/heartbeat"
	"github.com/asscor/asscor/internal/securemode"
)

// newSecureIdentityService builds a KernelServiceImpl with the heartbeat
// identity module AND a real secure-mode controller (its SecretRegistry is
// what the Heartbeat handler writes into).
func newSecureIdentityService(t *testing.T) *KernelServiceImpl {
	t.Helper()
	svc := &KernelServiceImpl{heartbeat: heartbeat.New()}
	svc.SetSecureMode(securemode.NewController(t.TempDir(), nil))
	return svc
}

// TestHeartbeatRegistersSecureModeSecret: an agent that reports its ephemeral
// password on the heartbeat is registered under its mTLS certificate
// fingerprint (spec §10.1).
func TestHeartbeatRegistersSecureModeSecret(t *testing.T) {
	svc := newSecureIdentityService(t)
	if _, err := svc.Register(ctxWithFP("fp-a"), &apiv1.RegisterRequest{HostId: "host-a", Hostname: "h-a", Version: "v0.2.3"}); err != nil {
		t.Fatalf("register: %v", err)
	}

	resp, err := svc.Heartbeat(ctxWithFP("fp-a"), &apiv1.HeartbeatRequest{
		HostId:     "host-a",
		SecureMode: &apiv1.SecureModeReport{Password: "agent-ephemeral-pw"},
	})
	if err != nil || !resp.Ok {
		t.Fatalf("heartbeat with secure-mode report failed (err=%v, ok=%v)", err, resp != nil && resp.Ok)
	}

	s, ok := svc.secureMode.Secrets.Lookup("fp-a")
	if !ok {
		t.Fatal("agent password must be registered under the presenting fingerprint")
	}
	if s.Password != "agent-ephemeral-pw" || s.AgentID != "host-a" {
		t.Errorf("registered secret = %+v, want password=agent-ephemeral-pw agent=host-a", s)
	}
}

// TestHeartbeatSecureModeMismatchedCertRejected: a forged host_id presenting a
// DIFFERENT certificate never reaches the registration — the transport-layer
// identity check (VerifyAgentCert) rejects it first (spec §10.1 / P1-2).
func TestHeartbeatSecureModeMismatchedCertRejected(t *testing.T) {
	svc := newSecureIdentityService(t)
	if _, err := svc.Register(ctxWithFP("fp-a"), &apiv1.RegisterRequest{HostId: "host-a", Hostname: "h-a", Version: "v0.2.3"}); err != nil {
		t.Fatalf("register: %v", err)
	}

	resp, err := svc.Heartbeat(ctxWithFP("fp-evil"), &apiv1.HeartbeatRequest{
		HostId:     "host-a",
		SecureMode: &apiv1.SecureModeReport{Password: "forged-pw"},
	})
	if err == nil || (resp != nil && resp.Ok) {
		t.Fatalf("mismatched cert heartbeat must be rejected (err=%v, ok=%v)", err, resp != nil && resp.Ok)
	}
	if _, ok := svc.secureMode.Secrets.Lookup("fp-evil"); ok {
		t.Error("forged fingerprint must not be registered")
	}
	if _, ok := svc.secureMode.Secrets.Lookup("fp-a"); ok {
		t.Error("the legitimately bound fingerprint must not be polluted by a forged report")
	}
}

// TestHeartbeatSecureModeEmptyFingerprintSkipped: without mTLS (development)
// there is no certificate fingerprint to key the registration on, so the
// report is skipped with a warning — the heartbeat itself keeps succeeding
// (no infinite retry loop on the agent side).
func TestHeartbeatSecureModeEmptyFingerprintSkipped(t *testing.T) {
	svc := newSecureIdentityService(t)
	// No mTLS: registration binds no fingerprint; heartbeats pass.
	if _, err := svc.Register(context.Background(), &apiv1.RegisterRequest{HostId: "host-dev", Hostname: "h", Version: "v0.2.3"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	resp, err := svc.Heartbeat(context.Background(), &apiv1.HeartbeatRequest{
		HostId:     "host-dev",
		SecureMode: &apiv1.SecureModeReport{Password: "dev-pw"},
	})
	if err != nil || !resp.Ok {
		t.Fatalf("empty-fingerprint heartbeat must stay ok (err=%v, ok=%v)", err, resp != nil && resp.Ok)
	}
	if svc.secureMode.Secrets.Size() != 0 {
		t.Error("nothing may be registered without a fingerprint")
	}
}

// TestHeartbeatSecureModeNoController: with the securemode tag off
// (SetSecureMode never called) a report is ignored and the heartbeat succeeds.
func TestHeartbeatSecureModeNoController(t *testing.T) {
	svc := newIdentityService() // no SetSecureMode
	if _, err := svc.Register(ctxWithFP("fp-a"), &apiv1.RegisterRequest{HostId: "host-a", Hostname: "h-a", Version: "v0.2.3"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	resp, err := svc.Heartbeat(ctxWithFP("fp-a"), &apiv1.HeartbeatRequest{
		HostId:     "host-a",
		SecureMode: &apiv1.SecureModeReport{Password: "pw"},
	})
	if err != nil || !resp.Ok {
		t.Fatalf("heartbeat without secure-mode controller must succeed (err=%v, ok=%v)", err, resp != nil && resp.Ok)
	}
}

// TestHeartbeatSecureModeEmptyPassword: an empty password in the report is
// ignored (never registered, never errors).
func TestHeartbeatSecureModeEmptyPassword(t *testing.T) {
	svc := newSecureIdentityService(t)
	if _, err := svc.Register(ctxWithFP("fp-a"), &apiv1.RegisterRequest{HostId: "host-a", Hostname: "h-a", Version: "v0.2.3"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	resp, err := svc.Heartbeat(ctxWithFP("fp-a"), &apiv1.HeartbeatRequest{
		HostId:     "host-a",
		SecureMode: &apiv1.SecureModeReport{Password: ""},
	})
	if err != nil || !resp.Ok {
		t.Fatalf("empty-password report must not fail the heartbeat (err=%v, ok=%v)", err, resp != nil && resp.Ok)
	}
	if _, ok := svc.secureMode.Secrets.Lookup("fp-a"); ok {
		t.Error("empty password must not be registered")
	}
}

// TestHeartbeatSecureModeRejectsFingerprintlessForgery: without a fingerprint
// in the context the kernel must not register the secret under an EMPTY key —
// the report is skipped (same guard as the empty-fingerprint test, verifying
// the fingerprint is mandatory for registration).
func TestHeartbeatSecureModeFingerprintIsMandatory(t *testing.T) {
	svc := newSecureIdentityService(t)
	if _, err := svc.Register(ctxWithFP("fp-a"), &apiv1.RegisterRequest{HostId: "host-a", Hostname: "h-a", Version: "v0.2.3"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Report WITHOUT a fingerprint key in context (attacker strips mTLS).
	resp, err := svc.Heartbeat(context.Background(), &apiv1.HeartbeatRequest{
		HostId:     "host-a",
		SecureMode: &apiv1.SecureModeReport{Password: "pw"},
	})
	if err != nil || !resp.Ok {
		t.Fatalf("fingerprint-less report must be skipped, not error (err=%v, ok=%v)", err, resp != nil && resp.Ok)
	}
	if _, ok := svc.secureMode.Secrets.Lookup(""); ok {
		t.Error("a secret must never be registered under an empty fingerprint")
	}
	if _, ok := svc.secureMode.Secrets.Lookup("fp-a"); ok {
		t.Error("fp-a must not be registered by a fingerprint-less report")
	}
}
