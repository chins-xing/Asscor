package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asscor/asscor/internal/checks"
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
