//go:build comms

package comms

import (
	"context"
	"testing"

	"github.com/chins-xing/asscor/internal/kernel"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func agentCtx(fp, cn string) context.Context {
	ctx := context.WithValue(context.Background(), kernel.CtxPeerCertFingerprint, fp)
	return context.WithValue(ctx, kernel.CtxPeerCertCommonName, cn)
}

func TestAgentServiceAuthorizeHost(t *testing.T) {
	svc := &AgentServiceImpl{verifyHost: func(hostID, fp string) bool {
		return hostID == "host-a" && fp == "fp-a"
	}}
	agent := agentCtx("fp-a", "ASSCOR Agent host-a")
	if err := svc.authorizeHost(agent, "host-a"); err != nil {
		t.Fatalf("bound host must be allowed: %v", err)
	}
	if err := svc.authorizeHost(agent, "host-b"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-host access = %v, want PermissionDenied", err)
	}

	// A host with no binding at all must also be denied for an agent cert.
	unbound := agentCtx("fp-a", "ASSCOR Agent host-a")
	if err := svc.authorizeHost(unbound, "host-unbound"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unbound host must be denied, got %v", err)
	}

	// Operator/other certs keep legacy cross-host access.
	op := agentCtx("fp-op", "ASSCOR Operator")
	if err := svc.authorizeHost(op, "host-b"); err != nil {
		t.Fatalf("operator must not be host-scoped: %v", err)
	}

	// mTLS disabled: no fingerprint → no scoping (development).
	if err := svc.authorizeHost(context.Background(), "host-b"); err != nil {
		t.Fatalf("empty fingerprint must not be scoped: %v", err)
	}

	// No verifier configured: legacy behaviour.
	legacy := &AgentServiceImpl{}
	if err := legacy.authorizeHost(agent, "host-b"); err != nil {
		t.Fatalf("nil verifier must not scope: %v", err)
	}
}
