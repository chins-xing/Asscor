package checks

import (
	"runtime"
	"testing"

	"github.com/argus-security/argus/internal/checks/linux"
)

func TestGetAll_ContainsEFChecks(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("EF checks are Linux-specific; skipping registry test on non-Linux")
	}

	items := GetAll()

	var foundEF001, foundEF002 bool
	for _, item := range items {
		if item.ID == "EF-001" {
			foundEF001 = true
			if item.Delta != 0 {
				t.Errorf("EF-001 Delta should be 0 (edge factor, not domain score), got %.1f", item.Delta)
			}
			if item.Domain != "attack_surface" {
				t.Errorf("EF-001 domain should be attack_surface, got %s", item.Domain)
			}
		}
		if item.ID == "EF-002" {
			foundEF002 = true
			if item.Delta != 0 {
				t.Errorf("EF-002 Delta should be 0 (edge factor, not domain score), got %.1f", item.Delta)
			}
			if item.Domain != "attack_surface" {
				t.Errorf("EF-002 domain should be attack_surface, got %s", item.Domain)
			}
		}
	}

	if !foundEF001 {
		t.Error("GetAll() must contain EF-001 (双因素认证)")
	}
	if !foundEF002 {
		t.Error("GetAll() must contain EF-002 (三因素认证)")
	}

	t.Logf("GetAll() returned %d check items, EF-001=%v, EF-002=%v", len(items), foundEF001, foundEF002)
}

func TestLinuxAll_ContainsEFChecks(t *testing.T) {
	items := linux.All()

	var foundEF001, foundEF002 bool
	for _, item := range items {
		switch item.ID {
		case "EF-001":
			foundEF001 = true
		case "EF-002":
			foundEF002 = true
		}
	}

	if !foundEF001 {
		t.Error("linux.All() must contain EF-001")
	}
	if !foundEF002 {
		t.Error("linux.All() must contain EF-002")
	}
}

func TestEF001_ID(t *testing.T) {
	items := linux.All()
	for _, item := range items {
		if item.ID == "EF-001" {
			if item.Name != "双因素认证" {
				t.Errorf("EF-001 name mismatch: got %s", item.Name)
			}
			return
		}
	}
	t.Error("EF-001 not found in linux.All()")
}

func TestEF002_ID(t *testing.T) {
	items := linux.All()
	for _, item := range items {
		if item.ID == "EF-002" {
			if item.Name != "三因素认证" {
				t.Errorf("EF-002 name mismatch: got %s", item.Name)
			}
			return
		}
	}
	t.Error("EF-002 not found in linux.All()")
}

func TestAllCheckItems_HaveComplianceRef(t *testing.T) {
	items := linux.All()

	if len(items) == 0 {
		t.Fatal("linux.All() returned 0 items")
	}

	missingRef := make([]string, 0)
	for _, item := range items {
		if item.ComplianceRef == "" {
			missingRef = append(missingRef, item.ID)
		}
	}

	if len(missingRef) > 0 {
		t.Errorf("complianceRef missing for %d check items: %v", len(missingRef), missingRef)
	}

	t.Logf("Verified %d check items: all have ComplianceRef populated", len(items))
}

func TestCheckItem_Run_PropagatesComplianceRef(t *testing.T) {
	items := linux.All()

	if len(items) == 0 {
		t.Fatal("linux.All() returned 0 items")
	}

	for _, item := range items {
		result := item.Run()

		if result.ComplianceRef != item.ComplianceRef {
			t.Errorf("%s: CheckResult.ComplianceRef=%q, want %q (from CheckItem)",
				item.ID, result.ComplianceRef, item.ComplianceRef)
		}
	}
}

func TestComplianceRef_KnownMappings(t *testing.T) {
	items := linux.All()
	refMap := make(map[string]string)
	for _, item := range items {
		refMap[item.ID] = item.ComplianceRef
	}

	tests := []struct {
		checkID string
		wantRef string
	}{
		{"EF-001", "L3-CE-04"},
		{"EF-002", "L4-CE-01"},
		{"AS-001", "L3-CE-21"},
		{"AS-002", "L3-CE-23"},
		{"AS-003", "L3-CE-01"},
		{"OT-001", "L3-CE-07"},
		{"OT-004", "L3-CE-32"},
		{"RS-001", "L3-CE-26"},
		{"BC-005", "L3-CE-36"},
	}

	for _, tt := range tests {
		t.Run(tt.checkID, func(t *testing.T) {
			got, ok := refMap[tt.checkID]
			if !ok {
				t.Errorf("%s not found in linux.All()", tt.checkID)
				return
			}
			if got != tt.wantRef {
				t.Errorf("%s: ComplianceRef=%q, want %q", tt.checkID, got, tt.wantRef)
			}
		})
	}
}

func TestCheckItemRun_ConfiguresAllFields(t *testing.T) {
	items := linux.All()
	for _, item := range items {
		result := item.Run()

		if result.CheckID != item.ID {
			t.Errorf("%s: CheckID mismatch: got %q", item.ID, result.CheckID)
		}
		if result.Domain != item.Domain {
			t.Errorf("%s: Domain mismatch: got %q, want %q", item.ID, result.Domain, item.Domain)
		}
		if result.Name != item.Name {
			t.Errorf("%s: Name mismatch: got %q, want %q", item.ID, result.Name, item.Name)
		}
		if result.Delta != item.Delta {
			t.Errorf("%s: Delta mismatch: got %.1f, want %.1f", item.ID, result.Delta, item.Delta)
		}
		if result.ComplianceRef != item.ComplianceRef {
			t.Errorf("%s: ComplianceRef mismatch: got %q, want %q",
				item.ID, result.ComplianceRef, item.ComplianceRef)
		}
	}

	t.Logf("All %d check items: Run() correctly propagates all fields", len(items))
}
