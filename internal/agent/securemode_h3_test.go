package agent

import (
	"strings"
	"testing"

	apiv1 "github.com/asscor/asscor/api/v1"
)

// TestInitSecureModeRefusesSkipVerify covers audit RC-H3: the secure-mode
// state machine (which reports the ephemeral unlock secret to the kernel)
// must refuse to start when TLS certificate verification is disabled — an
// unverified channel could be an impersonated kernel capturing the secret.
func TestInitSecureModeRefusesSkipVerify(t *testing.T) {
	v, _ := newSecureTestVault(t)
	cfg := DefaultConfig()
	cfg.TLSEnabled = true
	cfg.TLSSkipVerify = true
	a := NewAgent(cfg)

	err := a.InitSecureMode(v)
	if err == nil {
		t.Fatal("InitSecureMode with --tls-skip-verify must fail closed")
	}
	if !strings.Contains(err.Error(), "skip-verify") {
		t.Errorf("error should explain the skip-verify refusal, got %q", err.Error())
	}
}

// TestAttachSecureModeReportSkipVerifyNoPassword: even if a secure state
// somehow exists under skip-verify, the heartbeat report must not carry the
// password (belt-and-braces behind InitSecureMode).
func TestAttachSecureModeReportSkipVerifyNoPassword(t *testing.T) {
	v, _ := newSecureTestVault(t)
	cfg := DefaultConfig()
	cfg.TLSEnabled = true
	cfg.TLSSkipVerify = true
	a := NewAgent(cfg)
	// Bypass InitSecureMode's refusal to exercise the report guard directly.
	a.secure = &secureState{vault: v, password: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	a.secure.reported = false

	req := &apiv1.HeartbeatRequest{}
	a.attachSecureModeReport(req)
	if req.SecureMode != nil && req.SecureMode.Password != "" {
		t.Errorf("password must never be reported under skip-verify, got %+v", req.SecureMode)
	}
}
