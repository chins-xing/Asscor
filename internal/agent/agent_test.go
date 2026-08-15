package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"net"
	"strings"
	"testing"
	"time"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/common"
	"github.com/asscor/asscor/internal/model"
)

// ---------------------------------------------------------------------------
// DefaultConfig / NewAgent
// ---------------------------------------------------------------------------

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.KernelAddr != "localhost:50051" {
		t.Errorf("KernelAddr = %q, want localhost:50051", cfg.KernelAddr)
	}
	if cfg.HeartbeatSec != 30 || cfg.CheckIntervalSec != 300 || cfg.CheckTimeoutSec != 10 {
		t.Errorf("unexpected timing defaults: heartbeat=%d check=%d timeout=%d",
			cfg.HeartbeatSec, cfg.CheckIntervalSec, cfg.CheckTimeoutSec)
	}
	if cfg.MaxRetries != 3 || cfg.ReconnectSec != 5 {
		t.Errorf("unexpected retry defaults: max=%d reconnect=%d", cfg.MaxRetries, cfg.ReconnectSec)
	}
	if !cfg.TLSEnabled || cfg.TLSSkipVerify {
		t.Errorf("TLS defaults wrong: enabled=%v skip=%v", cfg.TLSEnabled, cfg.TLSSkipVerify)
	}
	if cfg.HostID == "" || cfg.Hostname == "" {
		t.Error("HostID/Hostname should default to hostname")
	}
}

func TestNewAgent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HMACKey = "test-key"
	a := NewAgent(cfg)
	if a == nil {
		t.Fatal("NewAgent returned nil")
	}
	if !a.hmacKeyConfigured {
		t.Error("hmacKeyConfigured should be true when HMACKey set")
	}
	if a.privClient == nil {
		t.Error("privClient should be initialized")
	}
}

func TestNewAgentNoHMACKey(t *testing.T) {
	t.Setenv("ASSCOR_HMAC_KEY", "")
	cfg := DefaultConfig()
	cfg.HMACKey = ""
	a := NewAgent(cfg)
	if a.hmacKeyConfigured {
		t.Error("hmacKeyConfigured should be false when no key configured")
	}
}

// TestNewAgentAppendsUserCheckItems verifies configuration-defined checks
// ([user_check.*] in agent.ini) are appended to the compiled-in checkers.
func TestNewAgentAppendsUserCheckItems(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UserCheckItems = []model.CheckItem{
		testCheckItem("CU-001", func() (bool, string) { return true, "user-defined" }),
		testCheckItem("CU-002", func() (bool, string) { return false, "user-fail" }),
	}
	a := NewAgent(cfg)

	found := map[string]bool{}
	for _, c := range a.checkers {
		found[c.ID] = true
	}
	if !found["CU-001"] || !found["CU-002"] {
		t.Errorf("user check items not appended to checkers: got %v", found)
	}
}

// TestNewAgentAppliesCheckDeltas verifies [check_deltas] overrides from the
// agent config replace the compiled-in Delta for matching check IDs.
func TestNewAgentAppliesCheckDeltas(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UserCheckItems = []model.CheckItem{
		testCheckItem("CU-DELTA-001", func() (bool, string) { return true, "x" }), // Delta -5 by default
		testCheckItem("CU-DELTA-002", func() (bool, string) { return false, "y" }),
	}
	cfg.CheckDeltas = map[string]float64{"CU-DELTA-001": -12, "CU-DELTA-002": 2}
	a := NewAgent(cfg)

	deltas := map[string]float64{}
	for _, c := range a.checkers {
		deltas[c.ID] = c.Delta
	}
	if deltas["CU-DELTA-001"] != -12 {
		t.Errorf("CU-DELTA-001 delta = %v, want -12 (overridden)", deltas["CU-DELTA-001"])
	}
	if deltas["CU-DELTA-002"] != 2 {
		t.Errorf("CU-DELTA-002 delta = %v, want 2 (overridden)", deltas["CU-DELTA-002"])
	}
}

// TestRunChecksPreservesSource verifies the user-source marker survives the
// check execution pipeline (runChecks → CheckResult.Source).
func TestRunChecksPreservesSource(t *testing.T) {
	a := &Agent{
		checkers: []model.CheckItem{
			testCheckItem("CU-SRC-001", func() (bool, string) { return true, "user-check" }),
		},
	}
	// Mark the checker as user-defined (ParseUserChecks sets this).
	a.checkers[0].Source = model.CheckSourceUser

	results := a.runChecks()
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Source != model.CheckSourceUser {
		t.Errorf("Source = %q, want %q (marker must propagate through runChecks)", results[0].Source, model.CheckSourceUser)
	}
}

// ---------------------------------------------------------------------------
// applySyncedCheckConfig — kernel → agent check configuration sync
// ---------------------------------------------------------------------------

func TestApplySyncedCheckConfig(t *testing.T) {
	a := NewAgent(DefaultConfig())
	before := len(a.checkers)

	cc := &apiv1.AgentCheckConfig{
		UserChecks: map[string]string{
			"user_check.sync1.id":        "CU-SYNC-001",
			"user_check.sync1.domain":    "resilience",
			"user_check.sync1.name":      "Synced Check",
			"user_check.sync1.command":   "true",
			"user_check.sync2.id":        "CU-SYNC-002",
			"user_check.sync2.domain":    "operation_trust",
			"user_check.sync2.name":      "Synced File Check",
			"user_check.sync2.file_path": "/etc/hostname",
		},
		CheckDeltas: map[string]float64{"CU-SYNC-001": -7},
		Version:     "v1",
	}
	a.applySyncedCheckConfig(cc)

	if len(a.checkers) != before+2 {
		t.Errorf("checkers = %d, want %d (2 synced checks added)", len(a.checkers), before+2)
	}
	if a.syncedCfgVersion != "v1" {
		t.Errorf("syncedCfgVersion = %q, want v1", a.syncedCfgVersion)
	}
	// Synced delta override applied.
	for _, c := range a.checkers {
		if c.ID == "CU-SYNC-001" && c.Delta != -7 {
			t.Errorf("CU-SYNC-001 delta = %v, want -7 (synced override)", c.Delta)
		}
		if c.ID == "CU-SYNC-001" && c.Source != model.CheckSourceUser {
			t.Errorf("CU-SYNC-001 Source = %q, want user", c.Source)
		}
	}
}

func TestApplySyncedCheckConfigSkipsUnchangedVersion(t *testing.T) {
	a := NewAgent(DefaultConfig())
	before := len(a.checkers)

	cc := &apiv1.AgentCheckConfig{
		UserChecks: map[string]string{
			"user_check.s.id":      "CU-S-001",
			"user_check.s.domain":  "resilience",
			"user_check.s.name":    "S",
			"user_check.s.command": "true",
		},
		Version: "v1",
	}
	a.applySyncedCheckConfig(cc)
	if len(a.checkers) != before+1 {
		t.Fatalf("first apply should add 1 check, got %d (was %d)", len(a.checkers), before)
	}

	// Same version: no-op even if content differs (fingerprint governs).
	a.applySyncedCheckConfig(&apiv1.AgentCheckConfig{UserChecks: cc.UserChecks, Version: "v1"})
	if len(a.checkers) != before+1 {
		t.Errorf("unchanged version must not reapply, checkers = %d", len(a.checkers))
	}
}

func TestApplySyncedCheckConfigNil(t *testing.T) {
	a := NewAgent(DefaultConfig())
	before := len(a.checkers)
	a.applySyncedCheckConfig(nil)
	a.applySyncedCheckConfig(&apiv1.AgentCheckConfig{Version: ""})
	if len(a.checkers) != before {
		t.Errorf("nil/empty config must be a no-op, checkers = %d (was %d)", len(a.checkers), before)
	}
}

// TestApplySyncedCheckConfigAllowedCommands verifies kernel-synced commands
// extend the execution allowlist (the builtin baseline is preserved).
func TestApplySyncedCheckConfigAllowedCommands(t *testing.T) {
	a := NewAgent(DefaultConfig())
	cc := &apiv1.AgentCheckConfig{
		AllowedCommands: []string{"zx-sync-auditctl", "zx-sync-ausearch"},
		Version:         "v-cmd-1",
	}
	a.applySyncedCheckConfig(cc)

	if !common.IsCommandAllowed("zx-sync-auditctl") {
		t.Error("synced command should be allowed after applySyncedCheckConfig")
	}
	if !common.IsCommandAllowed("zx-sync-ausearch") {
		t.Error("second synced command should be allowed")
	}
	// Builtin baseline preserved.
	if !common.IsCommandAllowed("systemctl") {
		t.Error("builtin baseline must survive command extension")
	}
	// checkers unchanged (no user checks in this config) but version recorded.
	if a.syncedCfgVersion != "v-cmd-1" {
		t.Errorf("syncedCfgVersion = %q, want v-cmd-1", a.syncedCfgVersion)
	}
}

// ---------------------------------------------------------------------------
// truncateCommandOutput
// ---------------------------------------------------------------------------

func TestTruncateCommandOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "short", input: "ok", want: "ok"},
		{name: "exact boundary", input: strings.Repeat("a", 512), want: strings.Repeat("a", 512)},
		{name: "over boundary", input: strings.Repeat("a", 513), want: strings.Repeat("a", 512) + "... (truncated)"},
		{name: "long output", input: strings.Repeat("x", 5000), want: strings.Repeat("x", 512) + "... (truncated)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncateCommandOutput(tt.input); got != tt.want {
				t.Errorf("truncateCommandOutput() = %d bytes, want %d", len(got), len(tt.want))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// splitPkgNameVersion
// ---------------------------------------------------------------------------

func TestSplitPkgNameVersion(t *testing.T) {
	tests := []struct {
		pkg      string
		wantName string
		wantVer  string
	}{
		{"openssl 3.0.7-17.el9_2", "openssl", "3.0.7"},
		{"nginx 1.22.1-1.el9", "nginx", "1.22.1"},
		{"bash-5.1.8-6.el9", "bash", "5.1.8"},
		// Known limitation (documented, not fixed here): multi-dash package
		// names in bare `rpm -qa` output (no --queryformat) are split at the
		// FIRST dash, so "kernel-core-6.1.0..." → ("kernel","core"). The normal
		// path (rpm -qa --queryformat "%{NAME} %{VERSION}-%{RELEASE}") emits
		// space-separated lines and splits correctly.
		{"kernel-core-6.1.0-10.el9.x86_64", "kernel", "core"},
		{"python3 3.9.16-1.el9", "python3", "3.9.16"},
		{"no-version-pkg", "no-version-pkg", "*"},
		{"name-with-dash-no-digit", "name-with-dash-no-digit", "*"},
		{"", "", ""},
		{"   ", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			gotName, gotVer := splitPkgNameVersion(tt.pkg)
			if gotName != tt.wantName || gotVer != tt.wantVer {
				t.Errorf("splitPkgNameVersion(%q) = (%q, %q), want (%q, %q)",
					tt.pkg, gotName, gotVer, tt.wantName, tt.wantVer)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// lookupVendorProduct
// ---------------------------------------------------------------------------

func TestLookupVendorProduct(t *testing.T) {
	tests := []struct {
		pkg         string
		wantVendor  string
		wantProduct string
		found       bool
	}{
		{"openssl", "openssl", "openssl", true},
		{"openssl-libs", "openssl", "openssl", true}, // suffix stripped
		{"nginx", "nginx", "nginx", true},
		{"kernel-core", "linux", "linux_kernel", true},
		{"nodejs", "nodejs", "node.js", true},
		{"python3", "python", "python", true},
		{"totally-unknown-package", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			got := lookupVendorProduct(tt.pkg)
			if tt.found {
				if got == nil {
					t.Fatalf("lookupVendorProduct(%q) = nil, want entry", tt.pkg)
				}
				if got.vendor != tt.wantVendor || got.product != tt.wantProduct {
					t.Errorf("lookupVendorProduct(%q) = (%q, %q), want (%q, %q)",
						tt.pkg, got.vendor, got.product, tt.wantVendor, tt.wantProduct)
				}
			} else if got != nil {
				t.Errorf("lookupVendorProduct(%q) = %v, want nil", tt.pkg, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// generateCPEsFromPackages
// ---------------------------------------------------------------------------

func TestGenerateCPEsFromPackages(t *testing.T) {
	packages := []string{
		"openssl 3.0.7-17.el9_2",
		"nginx 1.22.1-1.el9",
		"unknown-pkg 9.9.9",
		"openssl 3.0.7-17.el9_2", // duplicate
	}
	cpes := generateCPEsFromPackages(packages)

	if len(cpes) != 2 {
		t.Fatalf("got %d CPEs, want 2 (unknown skipped, duplicate deduped): %v", len(cpes), cpes)
	}
	wantOpenSSL := "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*"
	wantNginx := "cpe:2.3:a:nginx:nginx:1.22.1:*:*:*:*:*:*:*"
	for _, cpe := range cpes {
		if cpe != wantOpenSSL && cpe != wantNginx {
			t.Errorf("unexpected CPE: %q", cpe)
		}
	}
}

func TestGenerateCPEsFromPackagesEmpty(t *testing.T) {
	if cpes := generateCPEsFromPackages(nil); len(cpes) != 0 {
		t.Errorf("nil packages should yield no CPEs, got %v", cpes)
	}
}

// ---------------------------------------------------------------------------
// parsePackageList
// ---------------------------------------------------------------------------

func TestParsePackageList(t *testing.T) {
	input := "\n  openssl 3.0.7  \nnginx 1.22.1\n\n  \n"
	a := &Agent{}
	pkgs := a.parsePackageList(input)
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2: %v", len(pkgs), pkgs)
	}
	if pkgs[0] != "openssl 3.0.7" || pkgs[1] != "nginx 1.22.1" {
		t.Errorf("unexpected parsed packages: %v", pkgs)
	}
}

// ---------------------------------------------------------------------------
// inferZone
// ---------------------------------------------------------------------------

func TestInferZone(t *testing.T) {
	tests := []struct {
		name string
		ips  []string
		want string
	}{
		{"private only", []string{"192.168.1.10", "10.0.0.5"}, "internal"},
		{"loopback only", []string{"127.0.0.1"}, "internal"},
		{"public only", []string{"8.8.8.8", "1.1.1.1"}, "public"},
		{"mixed private and public", []string{"192.168.1.10", "8.8.8.8"}, "dmz"},
		{"invalid ips ignored", []string{"not-an-ip"}, "internal"},
		{"empty", nil, "internal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agent{}
			if got := a.inferZone(tt.ips); got != tt.want {
				t.Errorf("inferZone(%v) = %q, want %q", tt.ips, got, tt.want)
			}
		})
	}
}

func TestCollectNetworkInfoZone(t *testing.T) {
	// collectNetworkInfo reads real interfaces; we only assert the returned
	// struct is valid and the zone inference works on its own IPs.
	a := &Agent{}
	info := a.collectNetworkInfo()
	if info == nil {
		t.Fatal("collectNetworkInfo returned nil")
	}
	if len(info.LocalIPs) == 0 {
		t.Skip("no non-loopback IPv4 interfaces available")
	}
	_ = net.ParseIP(info.LocalIPs[0])
	if info.NetworkZone != "internal" && info.NetworkZone != "public" && info.NetworkZone != "dmz" {
		t.Errorf("unexpected zone %q", info.NetworkZone)
	}
}

// ---------------------------------------------------------------------------
// sortedParamKeys — signature stability
// ---------------------------------------------------------------------------

func TestSortedParamKeys(t *testing.T) {
	params := map[string]string{"zeta": "1", "alpha": "2", "_timestamp": "now"}
	keys := sortedParamKeys(params)
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(keys))
	}
	if keys[0] != "_timestamp" || keys[1] != "alpha" || keys[2] != "zeta" {
		t.Errorf("keys not sorted: %v", keys)
	}
}

// ---------------------------------------------------------------------------
// verifyCommandSignature — HMAC command authentication (core security logic)
// ---------------------------------------------------------------------------

// signCommand reproduces the exact HMAC construction used by commander:
// HMAC-SHA256(CommandId:Command:key1=val1:key2=val2...) over sorted params.
func signCommand(cmd *apiv1.Command, key string) {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(cmd.CommandId + ":" + cmd.Command))
	keys := sortedParamKeys(cmd.Params)
	for _, k := range keys {
		mac.Write([]byte(":" + k + "=" + cmd.Params[k]))
	}
	cmd.Signature = mac.Sum(nil)
}

func newSignedCommand(key string) *apiv1.Command {
	return &apiv1.Command{
		CommandId: "cmd-001",
		Command:   "systemctl is-active sshd",
		Params: map[string]string{
			"_timestamp": time.Now().UTC().Format(time.RFC3339),
			"host_id":    "web-01",
		},
	}
}

func TestVerifyCommandSignatureValid(t *testing.T) {
	cmd := newSignedCommand("secret")
	signCommand(cmd, "secret")

	a := &Agent{cfg: AgentConfig{HMACKey: "secret"}}
	if !a.verifyCommandSignature(cmd) {
		t.Error("valid signature + fresh timestamp should be accepted")
	}
}

func TestVerifyCommandSignatureWrongKey(t *testing.T) {
	cmd := newSignedCommand("secret")
	signCommand(cmd, "secret")

	a := &Agent{cfg: AgentConfig{HMACKey: "other-key"}}
	if a.verifyCommandSignature(cmd) {
		t.Error("signature made with different key must be rejected")
	}
}

func TestVerifyCommandSignatureTamperedCommand(t *testing.T) {
	cmd := newSignedCommand("secret")
	signCommand(cmd, "secret")
	cmd.Command = "rm -rf /" // tampered after signing

	a := &Agent{cfg: AgentConfig{HMACKey: "secret"}}
	if a.verifyCommandSignature(cmd) {
		t.Error("tampered command must be rejected")
	}
}

func TestVerifyCommandSignatureNoSignature(t *testing.T) {
	cmd := newSignedCommand("secret")
	cmd.Signature = nil

	a := &Agent{cfg: AgentConfig{HMACKey: "secret"}}
	if a.verifyCommandSignature(cmd) {
		t.Error("command without signature must be rejected")
	}
}

func TestVerifyCommandSignatureExpiredTimestamp(t *testing.T) {
	cmd := &apiv1.Command{
		CommandId: "cmd-expired",
		Command:   "systemctl status sshd",
		Params: map[string]string{
			"_timestamp": time.Now().Add(-6 * time.Minute).UTC().Format(time.RFC3339),
		},
	}
	signCommand(cmd, "secret")

	a := &Agent{cfg: AgentConfig{HMACKey: "secret"}}
	if a.verifyCommandSignature(cmd) {
		t.Error("expired timestamp (6 min old, window is 5 min) must be rejected")
	}
}

func TestVerifyCommandSignatureNoTimestamp(t *testing.T) {
	cmd := &apiv1.Command{
		CommandId: "cmd-nots",
		Command:   "systemctl status sshd",
		Params:    map[string]string{"host_id": "web-01"},
	}
	signCommand(cmd, "secret")

	a := &Agent{cfg: AgentConfig{HMACKey: "secret"}}
	if a.verifyCommandSignature(cmd) {
		t.Error("command missing _timestamp must be rejected")
	}
}

func TestVerifyCommandSignatureNoKeyConfigured(t *testing.T) {
	t.Setenv("ASSCOR_HMAC_KEY", "")
	cmd := newSignedCommand("secret")
	signCommand(cmd, "secret")

	a := &Agent{cfg: AgentConfig{HMACKey: ""}}
	if a.verifyCommandSignature(cmd) {
		t.Error("command must be rejected when no HMAC key is configured")
	}
}

func TestVerifyCommandSignatureInvalidTimestampFormat(t *testing.T) {
	cmd := &apiv1.Command{
		CommandId: "cmd-badts",
		Command:   "systemctl status sshd",
		Params:    map[string]string{"_timestamp": "not-a-timestamp"},
	}
	signCommand(cmd, "secret")

	a := &Agent{cfg: AgentConfig{HMACKey: "secret"}}
	if a.verifyCommandSignature(cmd) {
		t.Error("invalid timestamp format must be rejected")
	}
}

// ---------------------------------------------------------------------------
// extractPackagesFromChecks — keyword → package inference
// ---------------------------------------------------------------------------

func TestExtractPackagesFromChecks(t *testing.T) {
	a := &Agent{
		checkers: []model.CheckItem{
			{ID: "OT-001", Name: "SSH service secure", Description: "OpenSSH server config hardened"},
			{ID: "BC-001", Name: "Nginx running", Description: "Web server process active"},
			{ID: "AS-001", Name: "Fail2ban enabled", Description: "brute force protection"},
			{ID: "AS-002", Name: "unrelated check", Description: "no keyword here"},
		},
	}
	pkgs := a.extractPackagesFromChecks()
	want := map[string]bool{"openssh": true, "ssh": true, "nginx": true, "fail2ban": true}
	got := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		got[p] = true
	}
	for p := range want {
		if !got[p] {
			t.Errorf("expected package %q extracted, got %v", p, pkgs)
		}
	}
	for _, p := range pkgs {
		if !want[p] {
			t.Errorf("unexpected package %q extracted, got %v", p, pkgs)
		}
	}
}

func TestExtractPackagesFromChecksEmpty(t *testing.T) {
	a := &Agent{}
	if pkgs := a.extractPackagesFromChecks(); len(pkgs) != 0 {
		t.Errorf("no checkers should yield no packages, got %v", pkgs)
	}
}

// ---------------------------------------------------------------------------
// collectPackages — cache short-circuit
// ---------------------------------------------------------------------------

func TestCollectPackagesUsesCache(t *testing.T) {
	cached := []string{"openssl 3.0.7"}
	a := &Agent{cachedPackages: cached}
	got := a.collectPackages()
	if len(got) != 1 || got[0] != cached[0] {
		t.Errorf("collectPackages should return cached packages, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Stop / IsRunning
// ---------------------------------------------------------------------------

func TestStopAndIsRunning(t *testing.T) {
	a := &Agent{}
	if a.IsRunning() {
		t.Error("IsRunning should be false initially")
	}
	a.Stop()
	if a.IsRunning() {
		t.Error("IsRunning should be false after Stop")
	}
}

// ---------------------------------------------------------------------------
// runChecks / runCheckWithTimeout / checkTimeout
// ---------------------------------------------------------------------------

func testCheckItem(id string, fn func() (bool, string)) model.CheckItem {
	return model.CheckItem{
		ID:            id,
		Domain:        model.DomainAttackSurface,
		Name:          "Test " + id,
		Delta:         -5,
		ComplianceRef: "L3-TEST",
		Check:         fn,
	}
}

func TestCheckTimeoutFallback(t *testing.T) {
	a := &Agent{cfg: AgentConfig{CheckTimeoutSec: 0}}
	if got := a.checkTimeout(); got != 60*time.Second {
		t.Errorf("checkTimeout with 0 config = %v, want 60s", got)
	}
	a = &Agent{cfg: AgentConfig{CheckTimeoutSec: 5}}
	if got := a.checkTimeout(); got != 5*time.Second {
		t.Errorf("checkTimeout with 5 config = %v, want 5s", got)
	}
}

func TestRunChecksBasic(t *testing.T) {
	a := &Agent{
		checkers: []model.CheckItem{
			testCheckItem("C-001", func() (bool, string) { return true, "ok" }),
			testCheckItem("C-002", func() (bool, string) { return false, "bad" }),
			testCheckItem("C-003", func() (bool, string) { panic("boom") }),
		},
	}
	results := a.runChecks()
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	// Results must preserve checker order.
	if results[0].CheckID != "C-001" || !results[0].Passed {
		t.Errorf("results[0] = %+v, want C-001 passed", results[0])
	}
	if results[1].CheckID != "C-002" || results[1].Passed {
		t.Errorf("results[1] = %+v, want C-002 failed", results[1])
	}
	// Panic must be recovered by model.CheckItem.Run() and reported as failure.
	if results[2].CheckID != "C-003" || results[2].Passed {
		t.Errorf("results[2] = %+v, want C-003 failed after panic", results[2])
	}
	if !strings.Contains(results[2].Detail, "panic") {
		t.Errorf("results[2].Detail = %q, want panic mention", results[2].Detail)
	}
	// Metadata must survive through runChecks.
	for _, r := range results {
		if r.Domain != model.DomainAttackSurface || r.Delta != -5 || r.ComplianceRef != "L3-TEST" {
			t.Errorf("result %s lost metadata: %+v", r.CheckID, r)
		}
	}
}

func TestRunChecksTimeout(t *testing.T) {
	a := &Agent{
		cfg: AgentConfig{CheckTimeoutSec: 1},
		checkers: []model.CheckItem{
			testCheckItem("C-SLOW", func() (bool, string) {
				time.Sleep(3 * time.Second)
				return true, "too late"
			}),
		},
	}
	results := a.runChecks()
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.Passed {
		t.Error("slow check should be reported as failed (timeout)")
	}
	if !strings.Contains(r.Detail, "timed out") {
		t.Errorf("Detail = %q, want timeout mention", r.Detail)
	}
	// The timeout result must retain full scoring metadata so the kernel can
	// attribute the failure to the right domain/weight.
	if r.CheckID != "C-SLOW" || r.Domain != model.DomainAttackSurface ||
		r.Delta != -5 || r.ComplianceRef != "L3-TEST" || r.Name == "" {
		t.Errorf("timeout result lost metadata: %+v", r)
	}
}

func TestRunChecksEmpty(t *testing.T) {
	a := &Agent{}
	results := a.runChecks()
	if len(results) != 0 {
		t.Errorf("empty checkers should yield empty results (no root checks registered without checks tag), got %d", len(results))
	}
}

func TestRunCheckWithTimeoutCompletes(t *testing.T) {
	a := &Agent{cfg: AgentConfig{CheckTimeoutSec: 5}}
	item := testCheckItem("C-FAST", func() (bool, string) { return true, "fast" })
	r := a.runCheckWithTimeout(item, a.checkTimeout())
	if !r.Passed || r.Detail != "fast" {
		t.Errorf("fast check should complete normally: %+v", r)
	}
}
