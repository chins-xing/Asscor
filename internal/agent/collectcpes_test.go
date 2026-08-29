package agent

import (
	"strings"
	"testing"
	"time"

	apiv1 "github.com/asscor/asscor/api/v1"
)

// ---------------------------------------------------------------------------
// collectCPEs — cached-package fallback (gap report §2.7, low priority).
// ---------------------------------------------------------------------------

// TestCollectCPEsFromCachedPackages: with cached packages preset, collectCPEs
// generates CPEs for known vendor/products and skips unknown ones.
func TestCollectCPEsFromCachedPackages(t *testing.T) {
	a := &Agent{cachedPackages: []string{"openssl 3.0.7", "nginx 1.24.0", "totally-unknown-pkg 9.9"}}
	cpes := a.collectCPEs()
	if len(cpes) != 2 {
		t.Fatalf("cpes = %v, want 2 known-product CPEs", cpes)
	}
	joined := strings.Join(cpes, ",")
	if !strings.Contains(joined, "cpe:2.3:a:openssl:openssl:3.0.7") {
		t.Errorf("openssl CPE missing: %v", cpes)
	}
	if !strings.Contains(joined, "cpe:2.3:a:nginx:nginx:1.24.0") {
		t.Errorf("nginx CPE missing: %v", cpes)
	}
}

// TestCollectCPEsNilShortCircuit: nil cachedPackages must short-circuit to nil
// (no CPE generation, no error).
func TestCollectCPEsNilShortCircuit(t *testing.T) {
	a := &Agent{}
	if got := a.collectCPEs(); got != nil {
		t.Errorf("collectCPEs with nil cache = %v, want nil", got)
	}
}

// TestCollectCPEsEmptyCache: an empty (but non-nil) cached list yields no CPEs
// and must not panic.
func TestCollectCPEsEmptyCache(t *testing.T) {
	a := &Agent{cachedPackages: []string{}}
	if got := a.collectCPEs(); got == nil || len(got) != 0 {
		t.Errorf("collectCPEs with empty cache = %v, want empty non-nil", got)
	}
}

// ---------------------------------------------------------------------------
// verifyCommandSignature — future timestamp behavior locked in (gap report
// §4.1): the current implementation only rejects EXPIRED timestamps; a future
// timestamp passes. This test pins the current behavior — whether to add an
// upper-bound future offset is a design decision, not changed here.
// ---------------------------------------------------------------------------

func TestVerifyCommandSignatureFutureTimestampAccepted(t *testing.T) {
	cmd := &apiv1.Command{
		CommandId: "cmd-future",
		Command:   "go version",
		Params: map[string]string{
			"_timestamp": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		},
	}
	signCommand(cmd, "secret")
	a := &Agent{cfg: AgentConfig{HMACKey: "secret"}}
	if !a.verifyCommandSignature(cmd) {
		t.Error("future timestamp currently passes (no upper-bound check); behavior pinned — see gap report §4.1")
	}
}
