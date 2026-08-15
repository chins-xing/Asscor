//go:build sourcemanager

package sourcemanager

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/asscor/asscor/internal/kernel"
)

func TestSourceManagerModule_DeploySource(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	spec := kernel.SourceSpec{
		ID:       "trivy",
		Name:     "Trivy",
		Category: kernel.SourceCategoryScanner,
		Priority: kernel.SourcePriorityP0,
		Version:  "0.50.0",
	}
	cfg := kernel.SourceConfig{Settings: map[string]string{"target_images": "nginx:latest"}}

	err := m.DeploySource(context.Background(), spec, cfg)
	if err != nil {
		t.Fatalf("DeploySource failed: %v", err)
	}

	status, ok := m.GetSourceStatus("trivy")
	if !ok {
		t.Fatal("source not found after deploy")
	}
	if status.State != kernel.SourceStateInstalled {
		t.Errorf("expected state installed, got %s", status.State)
	}
	if status.Enabled {
		t.Error("source should not be enabled after deploy")
	}
	if status.Version != "0.50.0" {
		t.Errorf("expected version 0.50.0, got %s", status.Version)
	}
}

func TestSourceManagerModule_DeployDuplicate(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	spec := kernel.SourceSpec{ID: "trivy", Name: "Trivy", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0, Version: "1.0"}
	m.DeploySource(context.Background(), spec, kernel.SourceConfig{})

	err := m.DeploySource(context.Background(), spec, kernel.SourceConfig{})
	if err == nil {
		t.Error("expected error for duplicate deploy")
	}
}

func TestSourceManagerModule_EnableDisable(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	spec := kernel.SourceSpec{ID: "nuclei", Name: "Nuclei", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0, Version: "3.0"}
	m.DeploySource(context.Background(), spec, kernel.SourceConfig{})

	err := m.EnableSource(context.Background(), "nuclei")
	if err != nil {
		t.Fatalf("EnableSource failed: %v", err)
	}

	status, _ := m.GetSourceStatus("nuclei")
	if !status.Enabled {
		t.Error("source should be enabled")
	}
	if status.State != kernel.SourceStateEnabled {
		t.Errorf("expected state enabled, got %s", status.State)
	}

	err = m.DisableSource(context.Background(), "nuclei")
	if err != nil {
		t.Fatalf("DisableSource failed: %v", err)
	}

	status, _ = m.GetSourceStatus("nuclei")
	if status.Enabled {
		t.Error("source should be disabled")
	}
	if status.State != kernel.SourceStateDisabled {
		t.Errorf("expected state disabled, got %s", status.State)
	}
}

func TestSourceManagerModule_EnableAlreadyEnabled(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	spec := kernel.SourceSpec{ID: "lynis", Name: "Lynis", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0, Version: "3.0"}
	m.DeploySource(context.Background(), spec, kernel.SourceConfig{})
	m.EnableSource(context.Background(), "lynis")

	err := m.EnableSource(context.Background(), "lynis")
	if err == nil {
		t.Error("expected error for enabling already enabled source")
	}
}

func TestSourceManagerModule_UpdateSource(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	spec := kernel.SourceSpec{ID: "trivy", Name: "Trivy", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0, Version: "0.49.0"}
	m.DeploySource(context.Background(), spec, kernel.SourceConfig{})
	m.EnableSource(context.Background(), "trivy")

	err := m.UpdateSource(context.Background(), "trivy", "0.50.0")
	if err != nil {
		t.Fatalf("UpdateSource failed: %v", err)
	}

	status, _ := m.GetSourceStatus("trivy")
	if status.Version != "0.50.0" {
		t.Errorf("expected version 0.50.0, got %s", status.Version)
	}

	specOut, _ := m.GetSourceSpec("trivy")
	if specOut.Version != "0.50.0" {
		t.Errorf("spec version should be 0.50.0, got %s", specOut.Version)
	}
}

func TestSourceManagerModule_UninstallSource(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	spec := kernel.SourceSpec{ID: "aide", Name: "AIDE", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP2, Version: "1.0"}
	m.DeploySource(context.Background(), spec, kernel.SourceConfig{})

	err := m.UninstallSource(context.Background(), "aide", false)
	if err != nil {
		t.Fatalf("UninstallSource failed: %v", err)
	}

	_, ok := m.GetSourceStatus("aide")
	if ok {
		t.Error("source should not exist after uninstall")
	}
}

func TestSourceManagerModule_UninstallNotFound(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	err := m.UninstallSource(context.Background(), "nonexistent", false)
	if err == nil {
		t.Error("expected error for uninstalling nonexistent source")
	}
}

func TestSourceManagerModule_ConfigureSource(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	spec := kernel.SourceSpec{ID: "netbox", Name: "NetBox", Category: kernel.SourceCategoryManagement, Priority: kernel.SourcePriorityP0, Version: "3.5"}
	m.DeploySource(context.Background(), spec, kernel.SourceConfig{})

	newCfg := kernel.SourceConfig{Settings: map[string]string{
		"api_url":   "https://netbox.internal",
		"api_token": "secret123",
	}}
	err := m.ConfigureSource(context.Background(), "netbox", newCfg)
	if err != nil {
		t.Fatalf("ConfigureSource failed: %v", err)
	}

	cfg, ok := m.GetSourceConfig("netbox")
	if !ok {
		t.Fatal("config not found")
	}
	if cfg.Settings["api_url"] != "https://netbox.internal" {
		t.Errorf("unexpected api_url: %s", cfg.Settings["api_url"])
	}
}

func TestSourceManagerModule_ListSources(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	m.DeploySource(context.Background(), kernel.SourceSpec{ID: "trivy", Name: "Trivy", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0, Version: "1.0"}, kernel.SourceConfig{})
	m.DeploySource(context.Background(), kernel.SourceSpec{ID: "netbox", Name: "NetBox", Category: kernel.SourceCategoryManagement, Priority: kernel.SourcePriorityP0, Version: "3.5"}, kernel.SourceConfig{})
	m.DeploySource(context.Background(), kernel.SourceSpec{ID: "nuclei", Name: "Nuclei", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0, Version: "3.0"}, kernel.SourceConfig{})

	all := m.ListAllSources()
	if len(all) != 3 {
		t.Errorf("expected 3 sources, got %d", len(all))
	}

	scanners := m.ListSources(kernel.SourceCategoryScanner)
	if len(scanners) != 2 {
		t.Errorf("expected 2 scanners, got %d", len(scanners))
	}

	mgmt := m.ListSources(kernel.SourceCategoryManagement)
	if len(mgmt) != 1 {
		t.Errorf("expected 1 management source, got %d", len(mgmt))
	}
}

func TestSourceManagerModule_AuditLog(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	spec := kernel.SourceSpec{ID: "trivy", Name: "Trivy", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0, Version: "1.0"}
	m.DeploySource(context.Background(), spec, kernel.SourceConfig{})
	m.EnableSource(context.Background(), "trivy")
	m.DisableSource(context.Background(), "trivy")

	allLogs := m.GetAuditLog("", 0)
	if len(allLogs) != 3 {
		t.Errorf("expected 3 audit entries, got %d", len(allLogs))
	}

	trivyLogs := m.GetAuditLog("trivy", 2)
	if len(trivyLogs) != 2 {
		t.Errorf("expected 2 trivy entries, got %d", len(trivyLogs))
	}
}

func TestSourceManagerModule_HealthCheck(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	err := m.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("empty manager should be healthy, got: %v", err)
	}

	m.DeploySource(context.Background(), kernel.SourceSpec{ID: "trivy", Name: "Trivy", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0, Version: "1.0"}, kernel.SourceConfig{})

	err = m.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("installed source should be healthy, got: %v", err)
	}
}

func TestSourceManagerModule_DeployValidation(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	tests := []struct {
		name    string
		spec    kernel.SourceSpec
		wantErr bool
	}{
		{
			name:    "empty id",
			spec:    kernel.SourceSpec{Name: "Test", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0},
			wantErr: true,
		},
		{
			name:    "empty name",
			spec:    kernel.SourceSpec{ID: "test", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0},
			wantErr: true,
		},
		{
			name:    "invalid category",
			spec:    kernel.SourceSpec{ID: "test", Name: "Test", Category: "invalid", Priority: kernel.SourcePriorityP0},
			wantErr: true,
		},
		{
			name:    "invalid priority",
			spec:    kernel.SourceSpec{ID: "test", Name: "Test", Category: kernel.SourceCategoryScanner, Priority: "P9"},
			wantErr: true,
		},
		{
			name:    "valid spec",
			spec:    kernel.SourceSpec{ID: "test", Name: "Test", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP1},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.DeploySource(context.Background(), tt.spec, kernel.SourceConfig{})
			if (err != nil) != tt.wantErr {
				t.Errorf("DeploySource() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSourceManagerModule_StatePersistence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sm_state")

	m1 := New()
	m1.stateDir = dir

	spec := kernel.SourceSpec{ID: "trivy", Name: "Trivy", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0, Version: "1.0"}
	m1.DeploySource(context.Background(), spec, kernel.SourceConfig{})
	m1.EnableSource(context.Background(), "trivy")
	m1.saveState()

	m2 := New()
	m2.stateDir = dir
	m2.loadState()

	status, ok := m2.GetSourceStatus("trivy")
	if !ok {
		t.Fatal("source not found after reload")
	}
	if status.ID != "trivy" {
		t.Errorf("expected id trivy, got %s", status.ID)
	}
	if !status.Enabled {
		t.Error("source should be enabled after reload")
	}

	spec2, ok := m2.GetSourceSpec("trivy")
	if !ok {
		t.Fatal("spec not found after reload")
	}
	if spec2.Name != "Trivy" {
		t.Errorf("expected name Trivy, got %s", spec2.Name)
	}
}

func TestSourceManagerModule_DependencyCheck(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	parentSpec := kernel.SourceSpec{ID: "netbox", Name: "NetBox", Category: kernel.SourceCategoryManagement, Priority: kernel.SourcePriorityP0, Version: "3.5"}
	m.DeploySource(context.Background(), parentSpec, kernel.SourceConfig{})
	m.EnableSource(context.Background(), "netbox")

	childSpec := kernel.SourceSpec{
		ID:        "wazuh_siem",
		Name:      "Wazuh SIEM",
		Category:  kernel.SourceCategoryManagement,
		Priority:  kernel.SourcePriorityP1,
		Version:   "4.7",
		DependsOn: []string{"netbox"},
	}

	err := m.DeploySource(context.Background(), childSpec, kernel.SourceConfig{})
	if err != nil {
		t.Fatalf("DeploySource with satisfied dependency failed: %v", err)
	}

	orphanSpec := kernel.SourceSpec{
		ID:        "broken",
		Name:      "Broken",
		Category:  kernel.SourceCategoryScanner,
		Priority:  kernel.SourcePriorityP1,
		Version:   "1.0",
		DependsOn: []string{"nonexistent"},
	}

	err = m.DeploySource(context.Background(), orphanSpec, kernel.SourceConfig{})
	if err == nil {
		t.Error("expected error for unsatisfied dependency")
	}
}

func TestSourceManagerModule_UninstallWithDependent(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	parentSpec := kernel.SourceSpec{ID: "netbox", Name: "NetBox", Category: kernel.SourceCategoryManagement, Priority: kernel.SourcePriorityP0, Version: "3.5"}
	m.DeploySource(context.Background(), parentSpec, kernel.SourceConfig{})
	m.EnableSource(context.Background(), "netbox")

	childSpec := kernel.SourceSpec{
		ID:        "wazuh_siem",
		Name:      "Wazuh SIEM",
		Category:  kernel.SourceCategoryManagement,
		Priority:  kernel.SourcePriorityP1,
		Version:   "4.7",
		DependsOn: []string{"netbox"},
	}
	m.DeploySource(context.Background(), childSpec, kernel.SourceConfig{})
	m.EnableSource(context.Background(), "wazuh_siem")

	err := m.UninstallSource(context.Background(), "netbox", false)
	if err == nil {
		t.Error("expected error when uninstalling source with enabled dependents")
	}

	m.DisableSource(context.Background(), "wazuh_siem")
	err = m.UninstallSource(context.Background(), "netbox", false)
	if err != nil {
		t.Errorf("should allow uninstall when dependents are disabled: %v", err)
	}
}

func TestSourceManagerModule_AuditLogRotation(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	for i := 0; i < 10001; i++ {
		m.appendAuditLog("test", "src", "op", "detail", true)
	}

	if len(m.auditLog) > 5000 {
		t.Errorf("audit log should be trimmed, got %d entries", len(m.auditLog))
	}
}

func TestSourceManagerModule_GetSourceNotFound(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	_, ok := m.GetSourceStatus("nonexistent")
	if ok {
		t.Error("should not find nonexistent source")
	}

	_, ok = m.GetSourceSpec("nonexistent")
	if ok {
		t.Error("should not find nonexistent spec")
	}

	_, ok = m.GetSourceConfig("nonexistent")
	if ok {
		t.Error("should not find nonexistent config")
	}
}

func TestSourceManagerModule_SaveStateNoDir(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "nonexistent", "deep", "path")

	m.DeploySource(context.Background(), kernel.SourceSpec{ID: "test", Name: "Test", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0, Version: "1.0"}, kernel.SourceConfig{})

	m.saveState()

	if _, err := os.Stat(filepath.Join(m.stateDir, "source_manager_state.json")); os.IsNotExist(err) {
		t.Error("state file should be created")
	}
}

func TestSourceManagerModule_DisableNotEnabled(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	m.DeploySource(context.Background(), kernel.SourceSpec{ID: "trivy", Name: "Trivy", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0, Version: "1.0"}, kernel.SourceConfig{})

	err := m.DisableSource(context.Background(), "trivy")
	if err == nil {
		t.Error("expected error for disabling not-enabled source")
	}
}

func TestSourceManagerModule_UpdateNotInstalled(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	err := m.UpdateSource(context.Background(), "nonexistent", "1.0")
	if err == nil {
		t.Error("expected error for updating nonexistent source")
	}
}

func TestSourceManagerModule_EnableNotInstalled(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	m.specs["ghost"] = kernel.SourceSpec{ID: "ghost", Name: "Ghost"}
	m.statuses["ghost"] = kernel.SourceStatus{ID: "ghost", State: kernel.SourceStateNotInstalled}

	err := m.EnableSource(context.Background(), "ghost")
	if err == nil {
		t.Error("expected error for enabling not-installed source")
	}
}

func TestSourceManagerModule_LifecycleStates(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	if m.State() != kernel.PluginUnregistered {
		t.Errorf("expected unregistered, got %v", m.State())
	}

	m.state = kernel.PluginInitialized
	if m.State() != kernel.PluginInitialized {
		t.Errorf("expected initialized, got %v", m.State())
	}
}

func TestSourceManagerModule_Info(t *testing.T) {
	m := New()
	info := m.Info()

	if info.Name != "source_manager" {
		t.Errorf("expected name source_manager, got %s", info.Name)
	}
	if info.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", info.Version)
	}
}

func TestSourceManagerModule_Priority(t *testing.T) {
	m := New()
	if m.Priority() != 55 {
		t.Errorf("expected priority 55, got %d", m.Priority())
	}
}

func TestSourceManagerModule_Dependencies(t *testing.T) {
	m := New()
	deps := m.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("expected 1 dependency, got %d", len(deps))
	}
	if deps[0].Name != "adapter_integration" {
		t.Errorf("expected adapter_integration dependency, got %s", deps[0].Name)
	}
}

func TestSourceManagerModule_ConfigureNonExistent(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	err := m.ConfigureSource(context.Background(), "nonexistent", kernel.SourceConfig{Settings: map[string]string{"key": "val"}})
	if err == nil {
		t.Error("expected error for configuring nonexistent source")
	}
}

func TestSourceManagerModule_EnableNonExistent(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	err := m.EnableSource(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for enabling nonexistent source")
	}
}

func TestSourceManagerModule_DisableNonExistent(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	err := m.DisableSource(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for disabling nonexistent source")
	}
}

func TestSourceManagerModule_AuditLogTimeOrder(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	m.DeploySource(context.Background(), kernel.SourceSpec{ID: "trivy", Name: "Trivy", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0, Version: "1.0"}, kernel.SourceConfig{})
	m.EnableSource(context.Background(), "trivy")

	logs := m.GetAuditLog("trivy", 0)
	if len(logs) < 2 {
		t.Fatalf("expected at least 2 log entries, got %d", len(logs))
	}

	if logs[0].Timestamp.Before(logs[1].Timestamp) {
		t.Error("audit log entries should be in reverse chronological order (newest first)")
	}
}

func TestSourceManagerModule_StatusFieldsAfterDeploy(t *testing.T) {
	m := New()
	m.stateDir = filepath.Join(t.TempDir(), "sm_state")

	before := time.Now()
	m.DeploySource(context.Background(), kernel.SourceSpec{ID: "trivy", Name: "Trivy", Category: kernel.SourceCategoryScanner, Priority: kernel.SourcePriorityP0, Version: "1.0"}, kernel.SourceConfig{})
	after := time.Now()

	status, _ := m.GetSourceStatus("trivy")
	if status.InstalledAt.Before(before) || status.InstalledAt.After(after) {
		t.Errorf("installed_at timestamp out of range: %v", status.InstalledAt)
	}
	if status.SyncCount != 0 {
		t.Errorf("expected sync_count 0, got %d", status.SyncCount)
	}
	if status.ErrorCount != 0 {
		t.Errorf("expected error_count 0, got %d", status.ErrorCount)
	}
	if status.Findings != 0 {
		t.Errorf("expected findings 0, got %d", status.Findings)
	}
}
