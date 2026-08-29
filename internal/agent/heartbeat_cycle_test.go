package agent

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/model"
)

// ---------------------------------------------------------------------------
// heartbeatCycle — full-cycle integration tests driven by the in-process
// testKernel (JSON-over-TCP). The agent's client is injected directly and
// Connect()ed so the whole request→response→state-mutation path of one cycle
// is exercised without a real kernel (gap report §2.2).
// ---------------------------------------------------------------------------

// heartbeatCapture records the decoded HeartbeatRequest payloads the kernel
// saw, in order. The handler runs on a kernel goroutine while heartbeatCycle
// runs on the test goroutine, so all access is mutex-guarded.
type heartbeatCapture struct {
	mu  sync.Mutex
	req []*apiv1.HeartbeatRequest
}

func (c *heartbeatCapture) add(env map[string]interface{}) {
	b, err := json.Marshal(env["payload"])
	if err != nil {
		return
	}
	var req apiv1.HeartbeatRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return
	}
	c.mu.Lock()
	c.req = append(c.req, &req)
	c.mu.Unlock()
}

func (c *heartbeatCapture) get(i int) *apiv1.HeartbeatRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i < 0 || i >= len(c.req) {
		return nil
	}
	return c.req[i]
}

func (c *heartbeatCapture) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.req)
}

// newHeartbeatCycleAgent builds a minimal agent wired to the testKernel with
// one fast checker, ready for direct heartbeatCycle calls. sessionID is set
// directly because heartbeatCycle does not register (runOnce does).
func newHeartbeatCycleAgent(t *testing.T, k *testKernel, cfg AgentConfig) *Agent {
	t.Helper()
	cfg.TLSEnabled = false
	if cfg.CheckIntervalSec == 0 {
		cfg.CheckIntervalSec = 3600
	}
	if cfg.CheckTimeoutSec == 0 {
		cfg.CheckTimeoutSec = 1
	}
	a := &Agent{
		cfg: cfg,
		checkers: []model.CheckItem{
			testCheckItem("HB-001", func() (bool, string) { return true, "ok" }),
		},
	}
	a.client = NewClient(k.addr(), nil)
	if err := a.client.Connect(); err != nil {
		t.Fatalf("connect testKernel: %v", err)
	}
	t.Cleanup(func() { a.client.Close() })
	a.sessionID = "sess-1"
	return a
}

// okHeartbeatHandler answers every Heartbeat with {"ok": true} and records the
// request envelope.
func okHeartbeatHandler(cap *heartbeatCapture) func(env map[string]interface{}) map[string]interface{} {
	return func(env map[string]interface{}) map[string]interface{} {
		cap.add(env)
		return okEnv(map[string]interface{}{"ok": true})
	}
}

// TestHeartbeatCycleEnvelopeAndIncrementalSend covers the core cycle contract:
// the request envelope carries HostId/SessionId/Result with complete CheckResult
// fields, packages/CPEs are sent incrementally (first send, unchanged skip,
// changed resend), and check results flow to the kernel.
func TestHeartbeatCycleEnvelopeAndIncrementalSend(t *testing.T) {
	cap := &heartbeatCapture{}
	k := newTestKernel(t, okHeartbeatHandler(cap))

	cfg := DefaultConfig()
	cfg.HostID = "host-1"
	cfg.Hostname = "h1.example"
	a := newHeartbeatCycleAgent(t, k, cfg)
	a.cachedPackages = []string{"openssl 3.0.7"}

	// First cycle: full envelope + first full packages/CPEs send.
	if err := a.heartbeatCycle(); err != nil {
		t.Fatalf("first heartbeatCycle: %v", err)
	}
	req1 := cap.get(0)
	if req1 == nil {
		t.Fatal("kernel saw no heartbeat request")
	}
	if req1.HostId != "host-1" || req1.SessionId != "sess-1" {
		t.Errorf("envelope = %+v, want host_id=host-1 session_id=sess-1", req1)
	}
	if req1.Result == nil || len(req1.Result.Checks) != 1 {
		t.Fatalf("first cycle must carry check results, got %+v", req1.Result)
	}
	c := req1.Result.Checks[0]
	if c.CheckId != "HB-001" || !c.Passed || c.Delta != -5 ||
		c.Domain != model.DomainAttackSurface || c.Name != "Test HB-001" {
		t.Errorf("result check incomplete: %+v", c)
	}
	if req1.NetworkInfo == nil {
		t.Error("network info must be attached to the request")
	}
	if len(req1.Packages) != 1 || req1.Packages[0] != "openssl 3.0.7" {
		t.Errorf("first cycle must send packages, got %v", req1.Packages)
	}
	if len(req1.InstalledCPEs) != 1 ||
		!strings.Contains(req1.InstalledCPEs[0], "cpe:2.3:a:openssl:openssl:3.0.7") {
		t.Errorf("first cycle must send CPEs, got %v", req1.InstalledCPEs)
	}
	if !a.pkgSent || !a.cpeSent {
		t.Error("pkgSent/cpeSent must be set after the first send")
	}

	// Second cycle: unchanged packages/CPEs must be skipped (incremental).
	if err := a.heartbeatCycle(); err != nil {
		t.Fatalf("second heartbeatCycle: %v", err)
	}
	req2 := cap.get(1)
	if req2 == nil {
		t.Fatal("kernel saw no second heartbeat request")
	}
	if req2.Packages != nil {
		t.Errorf("unchanged packages must not be resent, got %v", req2.Packages)
	}
	if req2.InstalledCPEs != nil {
		t.Errorf("unchanged CPEs must not be resent, got %v", req2.InstalledCPEs)
	}
	if req2.Result != nil {
		t.Errorf("no checks ran this cycle, Result must be nil, got %+v", req2.Result)
	}

	// Third cycle: changed package list must be resent (new hash).
	a.cachedPackages = []string{"openssl 3.0.7", "nginx 1.24.0"}
	if err := a.heartbeatCycle(); err != nil {
		t.Fatalf("third heartbeatCycle: %v", err)
	}
	req3 := cap.get(2)
	if req3 == nil {
		t.Fatal("kernel saw no third heartbeat request")
	}
	if len(req3.Packages) != 2 {
		t.Errorf("changed packages must be resent, got %v", req3.Packages)
	}
	if len(req3.InstalledCPEs) != 2 {
		t.Errorf("changed CPEs must be resent, got %v", req3.InstalledCPEs)
	}
}

// TestHeartbeatCyclePendingCommandsAssigned: kernel-issued pending commands
// land in a.pendingCmd for the next cycle's executePendingCommands.
func TestHeartbeatCyclePendingCommandsAssigned(t *testing.T) {
	cap := &heartbeatCapture{}
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		cap.add(env)
		return okEnv(map[string]interface{}{
			"ok": true,
			"pending_commands": []map[string]interface{}{
				{"command_id": "pc-1", "command": "go version", "params": map[string]string{}, "signature": nil},
			},
		})
	})
	a := newHeartbeatCycleAgent(t, k, DefaultConfig())

	if err := a.heartbeatCycle(); err != nil {
		t.Fatalf("heartbeatCycle: %v", err)
	}
	if len(a.pendingCmd) != 1 || a.pendingCmd[0].CommandId != "pc-1" {
		t.Errorf("pendingCmd must be assigned from the kernel, got %+v", a.pendingCmd)
	}
}

// TestHeartbeatCycleCheckConfigApplied: a CheckConfig in the heartbeat response
// triggers applySyncedCheckConfig — the synced user check joins the checkers
// and the version fingerprint is recorded.
func TestHeartbeatCycleCheckConfigApplied(t *testing.T) {
	cap := &heartbeatCapture{}
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		cap.add(env)
		return okEnv(map[string]interface{}{
			"ok": true,
			"check_config": map[string]interface{}{
				"version": "v1",
				"user_checks": map[string]string{
					"user_check.mysql.id":      "CU-MYSQL-050",
					"user_check.mysql.domain":  "business_continuity",
					"user_check.mysql.name":    "MySQL Running",
					"user_check.mysql.command": "systemctl is-active mysqld",
				},
			},
		})
	})
	a := newHeartbeatCycleAgent(t, k, DefaultConfig())
	if a.syncedCfgVersion != "" {
		t.Fatalf("fresh agent must have no synced version, got %q", a.syncedCfgVersion)
	}

	if err := a.heartbeatCycle(); err != nil {
		t.Fatalf("heartbeatCycle: %v", err)
	}
	if a.syncedCfgVersion != "v1" {
		t.Errorf("syncedCfgVersion = %q, want v1", a.syncedCfgVersion)
	}
	found := false
	for _, c := range a.checkers {
		if c.ID == "CU-MYSQL-050" {
			found = true
		}
	}
	if !found {
		t.Errorf("synced user check missing from checkers: %+v", a.checkers)
	}
	// applySyncedCheckConfig rebuilds the checker set from the registry +
	// synced config (kernel is the single source of truth), so the pre-cycle
	// test-injected checker is replaced, not appended to.
	for _, c := range a.checkers {
		if c.ID == "HB-001" {
			t.Errorf("checkers must be rebuilt from synced config, stale HB-001 survived: %+v", a.checkers)
		}
	}
}

// TestHeartbeatCycleOkFalseResetsSession: a rejected heartbeat (Ok=false)
// clears the sessionID and surfaces an error so runOnce can retry/re-register.
func TestHeartbeatCycleOkFalseResetsSession(t *testing.T) {
	cap := &heartbeatCapture{}
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		cap.add(env)
		return okEnv(map[string]interface{}{"ok": false})
	})
	a := newHeartbeatCycleAgent(t, k, DefaultConfig())

	err := a.heartbeatCycle()
	if err == nil {
		t.Fatal("Ok=false heartbeat must return an error")
	}
	if !strings.Contains(err.Error(), "heartbeat rejected") {
		t.Errorf("error = %v, want rejection text", err)
	}
	if a.sessionID != "" {
		t.Errorf("sessionID must be reset on rejection, got %q", a.sessionID)
	}
}

// TestHeartbeatCycleReportPrinted: when the kernel echoes back an
// AssessmentResult and the cycle produced check results, printAssessmentReport
// is invoked (captured on stdout).
func TestHeartbeatCycleReportPrinted(t *testing.T) {
	cap := &heartbeatCapture{}
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		cap.add(env)
		return okEnv(map[string]interface{}{
			"ok": true,
			"assessment_result": map[string]interface{}{
				"final_score": 88.5,
				"acceptable":  true,
			},
		})
	})
	a := newHeartbeatCycleAgent(t, k, DefaultConfig())

	out := captureStdout(t, func() {
		if err := a.heartbeatCycle(); err != nil {
			t.Fatalf("heartbeatCycle: %v", err)
		}
	})
	if !strings.Contains(out, "Final Score: 88.50/100") {
		t.Errorf("assessment report must be printed on a full cycle, got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// heartbeatCycle × secure-mode hooks (RC-specific, gap report ① tail): the
// first-start bootstrap + password report, and the locked-agent unlock via the
// heartbeat response, must be orchestrated inside the cycle.
// ---------------------------------------------------------------------------

// TestHeartbeatCycleSecureFirstStartReportsPassword: a plaintext-config agent
// bootstraps secure mode on its first heartbeat (encrypt + self-generate the
// ephemeral password) and reports the password to the kernel; once accepted,
// the report is not repeated.
func TestHeartbeatCycleSecureFirstStartReportsPassword(t *testing.T) {
	cap := &heartbeatCapture{}
	k := newTestKernel(t, okHeartbeatHandler(cap))

	cfg := DefaultConfig()
	cfg.TLSEnabled = true // mTLS fingerprint keys the registration
	cfg.CheckIntervalSec = 3600
	cfg.CheckTimeoutSec = 1
	a := NewAgent(cfg)
	v, _ := newSecureTestVault(t)
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	a.client = NewClient(k.addr(), nil)
	if err := a.client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { a.client.Close() })
	a.sessionID = "sess-sec"

	if err := a.heartbeatCycle(); err != nil {
		t.Fatalf("heartbeatCycle: %v", err)
	}
	req := cap.get(0)
	if req == nil {
		t.Fatal("kernel saw no heartbeat request")
	}
	if req.SecureMode == nil || len(req.SecureMode.Password) != 64 {
		t.Fatalf("first heartbeat must report the ephemeral password, got %+v", req.SecureMode)
	}
	if req.SecureMode.Password != a.secure.password {
		t.Error("reported password must match the secure state password")
	}
	if !v.IsEncrypted() || v.HasPlaintext() {
		t.Errorf("config must be enc-only after bootstrap: plain=%v enc=%v", v.HasPlaintext(), v.IsEncrypted())
	}
	if !a.secure.reported {
		t.Error("accepted heartbeat must mark the password as reported")
	}

	// A second cycle must NOT re-report the already-registered password.
	if err := a.heartbeatCycle(); err != nil {
		t.Fatalf("second heartbeatCycle: %v", err)
	}
	req2 := cap.get(1)
	if req2 == nil {
		t.Fatal("kernel saw no second heartbeat request")
	}
	if req2.SecureMode != nil {
		t.Errorf("registered password must not be re-reported, got %+v", req2.SecureMode)
	}
}

// TestHeartbeatCycleSecureLockedUnlockViaResponse: a run-mode restart agent
// (enc-only, locked) declares Locked on its heartbeat, receives the registered
// password in the response, unlocks, and reloads the protected config (user
// checks + hmac_key) — all within the cycle (review I-1/I-2).
func TestHeartbeatCycleSecureLockedUnlockViaResponse(t *testing.T) {
	cap := &heartbeatCapture{}
	k := newTestKernel(t, func(env map[string]interface{}) map[string]interface{} {
		cap.add(env)
		return okEnv(map[string]interface{}{
			"ok": true,
			"secure_mode_unlock": map[string]interface{}{
				"password": "registered-pw",
			},
		})
	})

	cfg := DefaultConfig()
	cfg.TLSEnabled = true
	cfg.CheckIntervalSec = 3600
	cfg.CheckTimeoutSec = 1
	a := NewAgent(cfg)
	v, _ := newSecureTestVault(t)
	if err := v.EncryptFile("registered-pw"); err != nil {
		t.Fatal(err)
	}
	if err := a.InitSecureMode(v); err != nil {
		t.Fatal(err)
	}
	if !a.secure.locked {
		t.Fatal("restart agent must start locked")
	}
	baseline := len(a.checkers)
	a.client = NewClient(k.addr(), nil)
	if err := a.client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { a.client.Close() })
	a.sessionID = "sess-lock"

	if err := a.heartbeatCycle(); err != nil {
		t.Fatalf("heartbeatCycle: %v", err)
	}
	req := cap.get(0)
	if req == nil {
		t.Fatal("kernel saw no heartbeat request")
	}
	if req.SecureMode == nil || !req.SecureMode.Locked || req.SecureMode.Password != "" {
		t.Errorf("locked agent must declare Locked with no password, got %+v", req.SecureMode)
	}
	if a.secure.locked || a.secure.password != "registered-pw" {
		t.Errorf("agent must be unlocked with the issued password, got %+v", a.secure)
	}
	found := false
	for _, c := range a.checkers {
		if c.ID == "CU-MYSQL-001" {
			found = true
		}
	}
	if len(a.checkers) != baseline+1 || !found {
		t.Errorf("protected user check must reload after unlock (checkers=%d found=%v, baseline=%d)", len(a.checkers), found, baseline)
	}
}
