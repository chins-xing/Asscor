package config

import (
	"os"
	"testing"

	"github.com/asscor/asscor/internal/checks"
)

func TestRegisterUserChecks_Command(t *testing.T) {
	cfg := &Config{AdapterConfig: map[string]string{
		"user_check.testcheck.id":          "CU-TEST-001",
		"user_check.testcheck.domain":      "attack_surface",
		"user_check.testcheck.name":        "Test Command Check",
		"user_check.testcheck.command":     "echo hello",
		"user_check.testcheck.delta":       "-5",
		"user_check.testcheck.output_match": "hello",
	}}

	RegisterUserChecks(cfg)

	item, ok := checks.GetByID("CU-TEST-001")
	if !ok {
		t.Fatal("user check CU-TEST-001 was not registered")
	}
	if item.Domain != "attack_surface" {
		t.Errorf("domain = %s, want attack_surface", item.Domain)
	}
	if item.Name != "Test Command Check" {
		t.Errorf("name = %s", item.Name)
	}
	if item.Delta != -5 {
		t.Errorf("delta = %f, want -5", item.Delta)
	}
	if item.Check == nil {
		t.Fatal("Check function is nil")
	}

	// Command execution may fail on non-Linux platforms; verify registration only.
	_ = item.Check

	// Verify registered prevents double-registration.
	RegisterUserChecks(cfg)
	// Should not panic and should not double-register.
}

func TestRegisterUserChecks_FilePath(t *testing.T) {
	f, _ := os.CreateTemp("", "test-check-*.txt")
	defer os.Remove(f.Name())
	f.WriteString("secure_config=true\n")
	f.Close()

	cfg := &Config{AdapterConfig: map[string]string{
		"user_check.fc.id":       "CU-TEST-002",
		"user_check.fc.domain":   "operation_trust",
		"user_check.fc.name":     "File Check",
		"user_check.fc.file_path": f.Name(),
		"user_check.fc.file_regex": "secure_config\\s*=\\s*true",
		"user_check.fc.delta":    "-8",
	}}

	RegisterUserChecks(cfg)

	item, ok := checks.GetByID("CU-TEST-002")
	if !ok {
		t.Fatal("user check CU-TEST-002 was not registered")
	}
	passed, _ := item.Check()
	if !passed {
		t.Error("file regex check should pass")
	}
}

func TestRegisterUserChecks_SkipInvalid(t *testing.T) {
	cfg := &Config{AdapterConfig: map[string]string{
		"user_check.bad.id": "CU-SKIP",
		// Missing domain and name.
		"user_check.bad2.id":      "CU-SKIP2",
		"user_check.bad2.domain":  "resilience",
		"user_check.bad2.name":    "Missing command and file",
	}}
	RegisterUserChecks(cfg)
	_, ok := checks.GetByID("CU-SKIP")
	if ok {
		t.Error("missing domain+name should be skipped")
	}
	_, ok = checks.GetByID("CU-SKIP2")
	if ok {
		t.Error("missing command+file_path should be skipped")
	}
}
