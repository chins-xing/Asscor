//go:build comms

package comms

import (
	"testing"

	"github.com/asscor/asscor/internal/config"
)

func TestBuildAgentCheckConfig(t *testing.T) {
	cfg := &config.Config{
		AdapterConfig: map[string]string{
			"user_check.mysql.id":        "CU-MYSQL-001",
			"user_check.mysql.domain":    "business_continuity",
			"user_check.mysql.name":      "MySQL Running",
			"user_check.mysql.command":   "systemctl is-active mysqld",
			"user_check.audit.id":        "CU-AUDIT-001",
			"user_check.audit.domain":    "operation_trust",
			"user_check.audit.name":      "Audit Log",
			"user_check.audit.file_path": "/var/log/audit/audit.log",
			"unrelated.key":              "ignored",
		},
		CheckDeltas: map[string]float64{"AS-001": -12, "CU-MYSQL-001": -9},
	}

	svc := &KernelServiceImpl{cfg: cfg}
	cc := svc.buildAgentCheckConfig()
	if cc == nil {
		t.Fatal("buildAgentCheckConfig returned nil for configured kernel")
	}
	if len(cc.UserChecks) != 8 {
		t.Errorf("UserChecks = %d keys, want 8 (only user_check.* keys)", len(cc.UserChecks))
	}
	if _, ok := cc.UserChecks["user_check.mysql.id"]; !ok {
		t.Error("user_check.mysql.id missing from synced config")
	}
	if _, ok := cc.UserChecks["unrelated.key"]; ok {
		t.Error("non user_check.* keys must not be synced")
	}
	if cc.CheckDeltas["AS-001"] != -12 || cc.CheckDeltas["CU-MYSQL-001"] != -9 {
		t.Errorf("CheckDeltas not copied: %v", cc.CheckDeltas)
	}
	if cc.Version == "" {
		t.Error("Version must be non-empty for configured content")
	}
}

func TestBuildAgentCheckConfigNilConfig(t *testing.T) {
	svc := &KernelServiceImpl{}
	if cc := svc.buildAgentCheckConfig(); cc != nil {
		t.Errorf("nil config should yield nil check config, got %+v", cc)
	}
}

func TestBuildAgentCheckConfigEmpty(t *testing.T) {
	svc := &KernelServiceImpl{cfg: &config.Config{}}
	if cc := svc.buildAgentCheckConfig(); cc != nil {
		t.Errorf("empty config should yield nil check config, got %+v", cc)
	}
}

func TestAgentCheckConfigVersionStable(t *testing.T) {
	userChecks := map[string]string{
		"user_check.a.id": "CU-A-001",
		"user_check.b.id": "CU-B-001",
	}
	deltas := map[string]float64{"AS-001": -10}

	v1 := agentCheckConfigVersion(userChecks, deltas)
	v2 := agentCheckConfigVersion(userChecks, deltas)
	if v1 != v2 {
		t.Errorf("version not stable for identical content: %q vs %q", v1, v2)
	}

	// Map iteration order must not affect the fingerprint.
	reordered := map[string]string{
		"user_check.b.id": "CU-B-001",
		"user_check.a.id": "CU-A-001",
	}
	if v3 := agentCheckConfigVersion(reordered, deltas); v3 != v1 {
		t.Errorf("version depends on map iteration order: %q vs %q", v3, v1)
	}

	changed := map[string]string{
		"user_check.a.id": "CU-A-001",
		"user_check.b.id": "CU-B-002", // different value
	}
	if v4 := agentCheckConfigVersion(changed, deltas); v4 == v1 {
		t.Error("version must change when content changes")
	}
}
