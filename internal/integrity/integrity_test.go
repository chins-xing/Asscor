//go:build integrity

package integrity

import (
	"os"
	"testing"

	"github.com/asscor/asscor/internal/model"
)

func TestSigner_SignVerifies(t *testing.T) {
	EnableSigning(true)
	s := GetSigner()

	r := &model.AssessmentResult{
		HostID:     "test-host",
		Hostname:   "test",
		FinalScore: 85.5,
		Acceptable: true,
		Threshold:  80,
		SPCScore:   0.95,
		DomainScores: model.DomainScores{
			AttackSurface:      90,
			BusinessContinuity: 85,
			OperationTrust:     80,
			Resilience:         75,
			KernelSecurity:     95,
		},
		Checks: make([]model.CheckResult, 10),
	}

	s.Sign(r)
	if r.Signature == "" {
		t.Fatal("expected non-empty signature after Sign")
	}
	if !s.Verify(r) {
		t.Fatal("Verify failed on freshly signed result")
	}

	// Tamper: change final_score without re-signing.
	r.FinalScore = 100
	if s.Verify(r) {
		t.Fatal("Verify should fail after tampering final_score")
	}
}

func TestSigner_DisabledSkips(t *testing.T) {
	EnableSigning(false)
	s := GetSigner()

	r := &model.AssessmentResult{HostID: "test", FinalScore: 50, Checks: []model.CheckResult{{}}}
	s.Sign(r)
	if r.Signature != "" {
		t.Fatal("expected empty signature when signing disabled")
	}
	EnableSigning(true)
}

func TestSigner_NilResult(t *testing.T) {
	s := GetSigner()
	s.Sign(nil) // must not panic
	if s.Verify(nil) {
		t.Fatal("Verify on nil should return false")
	}
}

func TestGetSigner_Singleton(t *testing.T) {
	a := GetSigner()
	b := GetSigner()
	if a != b {
		t.Fatal("GetSigner() should return the same instance")
	}
}

func TestConfigToggles(t *testing.T) {
	EnableSigning(false)
	if IsSigningEnabled() {
		t.Fatal("signing should be disabled")
	}
	EnableSigning(true)
	if !IsSigningEnabled() {
		t.Fatal("signing should be enabled")
	}

	EnableAlgoVerify(false)
	if IsAlgoVerifyEnabled() {
		t.Fatal("algo verify should be disabled")
	}
	EnableAlgoVerify(true)
	if !IsAlgoVerifyEnabled() {
		t.Fatal("algo verify should be enabled")
	}

	EnableAntiDebug(false)
	if IsAntiDebugEnabled() {
		t.Fatal("anti-debug should default to disabled")
	}
	EnableAntiDebug(true)
	if !IsAntiDebugEnabled() {
		t.Fatal("anti-debug should be enabled")
	}
	EnableAntiDebug(false)
}

func TestVerifyAlgo(t *testing.T) {
	EnableAlgoVerify(true)
	if !VerifyAlgo() {
		t.Fatal("VerifyAlgo should pass in record mode (expectedAlgoDigest is empty)")
	}
}

func TestIsDebugged_Stub(t *testing.T) {
	_ = IsDebugged() // must not panic on any platform
}

func TestMain(m *testing.M) {
	os.Remove("certs/ASSCOR-assessment-key")
	code := m.Run()
	os.Remove("certs/ASSCOR-assessment-key")
	os.Exit(code)
}
