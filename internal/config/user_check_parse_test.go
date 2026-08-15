package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asscor/asscor/internal/checks"
	"github.com/asscor/asscor/internal/model"
)

// TestParse_UserCheckSections verifies the full ini → AdapterConfig → registry
// path for [user_check] and [user_check.<name>] sections. Previously the
// buildAdapterConfig step dropped user_check.* sections entirely, so
// RegisterUserChecks could never see them (registration silently no-op'd).
func TestParse_UserCheckSections(t *testing.T) {
	content := `
[agent]
kernel_addr = 127.0.0.1:50051

[user_check.mysql]
id = CU-MYSQL-001
domain = business_continuity
name = MySQL Running
description = check mysqld active
command = systemctl is-active mysqld
delta = -8

[user_check]
id = CU-SINGLE-001
domain = operation_trust
name = Single Section Check
command = echo ok
delta = -3
`
	cfg, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Named section must be flattened to user_check.mysql.id style keys.
	if _, ok := cfg.AdapterConfig["user_check.mysql.id"]; !ok {
		t.Fatalf("user_check.mysql section not flattened into AdapterConfig: %v", cfg.AdapterConfig)
	}
	// Bare [user_check] section must be flattened as user_check.default.*.
	if _, ok := cfg.AdapterConfig["user_check.default.id"]; !ok {
		t.Fatalf("bare [user_check] section not flattened as user_check.default.*: %v", cfg.AdapterConfig)
	}

	// Register and verify both checks are actually registered.
	RegisterUserChecks(cfg)

	if item, ok := checks.GetByID("CU-MYSQL-001"); !ok {
		t.Error("CU-MYSQL-001 was not registered from [user_check.mysql] section")
	} else {
		if item.Domain != "business_continuity" || item.Delta != -8 {
			t.Errorf("CU-MYSQL-001 metadata wrong: %+v", item)
		}
	}
	if _, ok := checks.GetByID("CU-SINGLE-001"); !ok {
		t.Error("CU-SINGLE-001 was not registered from bare [user_check] section")
	}
}

// TestParseUserChecks_CommandOutputMatch verifies the output_match semantics
// with a real shell command (echo) and that the pure function returns items
// without registry side effects.
func TestParseUserChecks_CommandOutputMatch(t *testing.T) {
	items := ParseUserChecks(map[string]string{
		"user_check.ec.id":           "CU-OUT-001",
		"user_check.ec.domain":       "attack_surface",
		"user_check.ec.name":         "Echo Check",
		"user_check.ec.command":      "echo hello-world",
		"user_check.ec.output_match": "hello",
	})
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	item := items[0]
	if item.Check == nil {
		t.Fatal("Check is nil")
	}
	// user_check commands execute via `sh -c`; skip actual execution when the
	// shell is unavailable (e.g. Windows dev boxes) — Linux/CI covers it.
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available on this platform, skipping execution")
	}
	passed, detail := item.Check()
	if !passed {
		t.Errorf("echo check should pass, detail: %s", detail)
	}

	// Pure function must not register into the global registry.
	if _, ok := checks.GetByID("CU-OUT-001"); ok {
		t.Error("ParseUserChecks should not register into the checks registry (pure)")
	}
}

// TestParseUserChecks_FileRegex verifies the file_path + file_regex path.
func TestParseUserChecks_FileRegex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(path, []byte("server {\n  listen 443 ssl;\n}\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	items := ParseUserChecks(map[string]string{
		"user_check.fr.id":         "CU-FILE-001",
		"user_check.fr.domain":     "operation_trust",
		"user_check.fr.name":       "TLS Enabled",
		"user_check.fr.file_path":  path,
		"user_check.fr.file_regex": "listen\\s+443\\s+ssl",
	})
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	passed, detail := items[0].Check()
	if !passed {
		t.Errorf("file regex check should pass, detail: %s", detail)
	}
}

// TestParseUserChecks_SkipInvalid mirrors the registry test but on the pure
// function: entries missing id/domain/name or command/file_path are dropped.
func TestParseUserChecks_SkipInvalid(t *testing.T) {
	items := ParseUserChecks(map[string]string{
		"user_check.bad.id":         "CU-SKIP-X",
		"user_check.bad2.id":        "CU-SKIP-Y",
		"user_check.bad2.domain":    "resilience",
		"user_check.bad2.name":      "No command or file",
		"user_check.good.id":        "CU-KEEP",
		"user_check.good.domain":    "resilience",
		"user_check.good.name":      "Keep Me",
		"user_check.good.command":   "true",
		"user_check.malformed_only": "no suffix split",
	})
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1 (only CU-KEEP valid)", len(items))
	}
	if items[0].ID != "CU-KEEP" {
		t.Errorf("unexpected item: %+v", items[0])
	}
}

// TestParseUserChecks_MissingFile ensures a missing file path reports failure
// with a readable detail (not a panic).
func TestParseUserChecks_MissingFile(t *testing.T) {
	items := ParseUserChecks(map[string]string{
		"user_check.mf.id":        "CU-MF-001",
		"user_check.mf.domain":    "operation_trust",
		"user_check.mf.name":      "Missing File",
		"user_check.mf.file_path": filepath.Join(t.TempDir(), "does-not-exist.conf"),
	})
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	passed, detail := items[0].Check()
	if passed {
		t.Error("missing file check should fail")
	}
	if !strings.Contains(detail, "cannot read") {
		t.Errorf("detail = %q, want 'cannot read' mention", detail)
	}
}

// TestParseUserChecks_RejectsNonCUPrefix enforces the reserved CU- prefix:
// a user check attempting to use a builtin-style ID (e.g. AS-999) is rejected
// so it can never collide with compiled-in platform checks.
func TestParseUserChecks_RejectsNonCUPrefix(t *testing.T) {
	items := ParseUserChecks(map[string]string{
		"user_check.collide.id":      "AS-999", // builtin-style prefix
		"user_check.collide.domain":  "attack_surface",
		"user_check.collide.name":    "Collide",
		"user_check.collide.command": "true",
		"user_check.valid.id":        "CU-OK-001",
		"user_check.valid.domain":    "resilience",
		"user_check.valid.name":      "Valid",
		"user_check.valid.command":   "true",
	})
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1 (AS-999 rejected, CU-OK-001 kept): %+v", len(items), items)
	}
	if items[0].ID != "CU-OK-001" {
		t.Errorf("unexpected item: %+v", items[0])
	}
}

// TestParseUserChecks_SetsUserSource verifies every returned item carries the
// user source marker, distinguishing it from builtin checks.
func TestParseUserChecks_SetsUserSource(t *testing.T) {
	items := ParseUserChecks(map[string]string{
		"user_check.src.id":        "CU-SRC-001",
		"user_check.src.domain":    "operation_trust",
		"user_check.src.name":      "Source Check",
		"user_check.src.file_path": filepath.Join(t.TempDir(), "x.conf"),
	})
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	if items[0].Source != model.CheckSourceUser {
		t.Errorf("Source = %q, want %q", items[0].Source, model.CheckSourceUser)
	}
}

// TestParseUserChecks_CommandAllowlist verifies the command first-token
// allowlist: safe read-only commands (echo / systemctl) are accepted, while
// high-risk commands (curl / rm / sh recursion / sudo / python) are rejected
// at construction time.
func TestParseUserChecks_CommandAllowlist(t *testing.T) {
	base := map[string]string{
		"user_check.allowed.id":      "CU-ALLOW-001",
		"user_check.allowed.domain":  "resilience",
		"user_check.allowed.name":    "Allowed",
		"user_check.allowed.command": "echo ok",
		"user_check.common.id":       "CU-COMMON-001",
		"user_check.common.domain":   "resilience",
		"user_check.common.name":     "Common Whitelist",
		"user_check.common.command":  "systemctl is-active sshd",
		"user_check.net.id":          "CU-NET-001",
		"user_check.net.domain":      "resilience",
		"user_check.net.name":        "Network Egress",
		"user_check.net.command":     "curl http://evil.example",
		"user_check.rm.id":           "CU-RM-001",
		"user_check.rm.domain":       "resilience",
		"user_check.rm.name":         "Destructive",
		"user_check.rm.command":      "rm -rf /",
		"user_check.sh.id":           "CU-SH-001",
		"user_check.sh.domain":       "resilience",
		"user_check.sh.name":         "Shell Recursion",
		"user_check.sh.command":      "sh -c 'reboot'",
		"user_check.sudo.id":         "CU-SUDO-001",
		"user_check.sudo.domain":     "resilience",
		"user_check.sudo.name":       "Privilege Escalation",
		"user_check.sudo.command":    "sudo rm /etc/shadow",
		"user_check.py.id":           "CU-PY-001",
		"user_check.py.domain":       "resilience",
		"user_check.py.name":         "Interpreter",
		"user_check.py.command":      "python3 -c 'import os; os.system(\"x\")'",
	}
	items := ParseUserChecks(base)

	got := map[string]string{}
	for _, it := range items {
		got[it.ID] = it.Name
	}
	if got["CU-ALLOW-001"] != "Allowed" {
		t.Errorf("echo command should be allowed, got %v", got)
	}
	if got["CU-COMMON-001"] != "Common Whitelist" {
		t.Errorf("systemctl command (common whitelist) should be allowed, got %v", got)
	}
	for _, rejected := range []string{"CU-NET-001", "CU-RM-001", "CU-SH-001", "CU-SUDO-001", "CU-PY-001"} {
		if _, ok := got[rejected]; ok {
			t.Errorf("command %q should have been rejected, got %v", rejected, got)
		}
	}
}

// TestRequireMTLS verifies the [comms] require_mtls policy: default true,
// explicit false values disable enforcement, other values keep it enabled.
func TestRequireMTLS(t *testing.T) {
	if !RequireMTLS(nil) {
		t.Error("nil config must default to require_mtls=true")
	}
	if !RequireMTLS(map[string]string{}) {
		t.Error("empty config must default to require_mtls=true")
	}
	if !RequireMTLS(map[string]string{"comms.require_mtls": "true"}) {
		t.Error("require_mtls=true must enforce mTLS")
	}
	for _, v := range []string{"false", "no", "0", "off"} {
		if RequireMTLS(map[string]string{"comms.require_mtls": v}) {
			t.Errorf("require_mtls=%q must disable enforcement", v)
		}
	}
	if !RequireMTLS(map[string]string{"comms.require_mtls": "yes"}) {
		t.Error("require_mtls=yes must enforce mTLS (unknown values default to true)")
	}
}

// TestParse_CommsSection verifies [comms] is collected into AdapterConfig so
// RequireMTLS can read it from a real config file.
func TestParse_CommsSection(t *testing.T) {
	cfg, err := Parse("[comms]\nrequire_mtls = true\n[agent]\nfoo = bar\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if v := cfg.AdapterConfig["comms.require_mtls"]; v != "true" {
		t.Errorf("comms.require_mtls = %q, want true (collected from [comms] section)", v)
	}
	if !RequireMTLS(cfg.AdapterConfig) {
		t.Error("parsed [comms] require_mtls=true should enforce mTLS")
	}
}

// TestIsUserCheckCommandAllowed unit-tests the first-token matcher directly.
func TestIsUserCheckCommandAllowed(t *testing.T) {
	allowed := []string{
		"echo hello",
		"systemctl is-active sshd",
		"/usr/bin/ss -tlnp",     // common whitelist with path prefix
		"'cat' /etc/os-release", // quoted first token
		"true",
		"ss -tlnp | grep :22", // pipe after allowed first token
	}
	for _, c := range allowed {
		if !isUserCheckCommandAllowed(c) {
			t.Errorf("command %q should be allowed", c)
		}
	}
	rejected := []string{
		"curl http://x",
		"wget http://x",
		"rm -rf /",
		"sh -c x",
		"bash x",
		"sudo reboot",
		"python3 x",
		"perl -e x",
		"nc -l 4444",
		"git clone http://x",
		"",
	}
	for _, c := range rejected {
		if isUserCheckCommandAllowed(c) {
			t.Errorf("command %q should be rejected", c)
		}
	}
}
