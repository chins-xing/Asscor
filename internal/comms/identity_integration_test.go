//go:build comms && heartbeat

package comms

import (
	"context"
	"testing"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/heartbeat"
	"github.com/asscor/asscor/internal/kernel"
)

func newIdentityService() *KernelServiceImpl {
	return &KernelServiceImpl{heartbeat: heartbeat.New()}
}

func ctxWithFP(fp string) context.Context {
	return context.WithValue(context.Background(), kernel.CtxPeerCertFingerprint, fp)
}

// TestRegisterBindsCertFingerprint: a certificate fingerprint is bound to the
// host on first registration and the agent is accepted.
func TestRegisterBindsCertFingerprint(t *testing.T) {
	svc := newIdentityService()
	resp, err := svc.Register(ctxWithFP("fp-a"), &apiv1.RegisterRequest{HostId: "host-a", Hostname: "h-a", Version: "v0.2.3"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !resp.Accepted {
		t.Error("first registration with a fresh certificate should be accepted")
	}
	rec := svc.heartbeat.GetAgent("host-a")
	if rec == nil || rec.CertFingerprint != "fp-a" {
		t.Errorf("cert fingerprint not bound: %+v", rec)
	}
}

// TestRegisterRejectsHostWithDifferentCert: a host already bound to one
// certificate must reject a different certificate (impersonation).
func TestRegisterRejectsHostWithDifferentCert(t *testing.T) {
	svc := newIdentityService()
	if _, err := svc.Register(ctxWithFP("fp-a"), &apiv1.RegisterRequest{HostId: "host-a", Hostname: "h-a", Version: "v0.2.3"}); err != nil {
		t.Fatalf("first register: %v", err)
	}
	resp, err := svc.Register(ctxWithFP("fp-evil"), &apiv1.RegisterRequest{HostId: "host-a", Hostname: "h-a", Version: "v0.2.3"})
	if err == nil || resp.Accepted {
		t.Errorf("host bound to fp-a must reject fp-evil (err=%v, accepted=%v)", err, resp != nil && resp.Accepted)
	}
}

// TestRegisterRejectsCertUsedByOtherHost: one certificate, one identity — a
// certificate bound to host-a cannot register as host-b.
func TestRegisterRejectsCertUsedByOtherHost(t *testing.T) {
	svc := newIdentityService()
	if _, err := svc.Register(ctxWithFP("fp-a"), &apiv1.RegisterRequest{HostId: "host-a", Hostname: "h-a", Version: "v0.2.3"}); err != nil {
		t.Fatalf("register host-a: %v", err)
	}
	resp, err := svc.Register(ctxWithFP("fp-a"), &apiv1.RegisterRequest{HostId: "host-b", Hostname: "h-b", Version: "v0.2.3"})
	if err == nil || resp.Accepted {
		t.Errorf("certificate bound to host-a must not register host-b (err=%v, accepted=%v)", err, resp != nil && resp.Accepted)
	}
}

// TestHeartbeatVerifiesCertFingerprint: after binding, a matching certificate
// heartbeats successfully; a different one is rejected.
func TestHeartbeatVerifiesCertFingerprint(t *testing.T) {
	svc := newIdentityService()
	if _, err := svc.Register(ctxWithFP("fp-a"), &apiv1.RegisterRequest{HostId: "host-a", Hostname: "h-a", Version: "v0.2.3"}); err != nil {
		t.Fatalf("register: %v", err)
	}

	if resp, err := svc.Heartbeat(ctxWithFP("fp-a"), &apiv1.HeartbeatRequest{HostId: "host-a"}); err != nil || !resp.Ok {
		t.Errorf("matching cert heartbeat should succeed (err=%v, ok=%v)", err, resp != nil && resp.Ok)
	}
	if resp, err := svc.Heartbeat(ctxWithFP("fp-evil"), &apiv1.HeartbeatRequest{HostId: "host-a"}); err == nil || resp.Ok {
		t.Errorf("mismatched cert heartbeat must be rejected (err=%v, ok=%v)", err, resp != nil && resp.Ok)
	}
}

// TestRegisterWithoutFingerprint: no mTLS (development mode) skips identity
// binding and accepts registrations.
func TestRegisterWithoutFingerprint(t *testing.T) {
	svc := newIdentityService()
	resp, err := svc.Register(context.Background(), &apiv1.RegisterRequest{HostId: "host-dev", Hostname: "h", Version: "v0.2.3"})
	if err != nil || !resp.Accepted {
		t.Errorf("no-fingerprint registration should succeed (err=%v, accepted=%v)", err, resp != nil && resp.Accepted)
	}
}
