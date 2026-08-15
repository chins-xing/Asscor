package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"net"
	"strings"
	"testing"
	"time"

	apiv1 "github.com/asscor/asscor/api/v1"
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
