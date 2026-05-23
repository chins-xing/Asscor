package kernel

import (
	"context"
	"testing"

	apiv1 "github.com/argus-security/argus/api/v1"
)

func TestSourceManagerServiceImpl_ListSources(t *testing.T) {
	m := NewSourceManagerModule()
	m.stateDir = t.TempDir()

	m.DeploySource(context.Background(), SourceSpec{ID: "trivy", Name: "Trivy", Category: SourceCategoryScanner, Priority: SourcePriorityP0, Version: "1.0"}, SourceConfig{})
	m.DeploySource(context.Background(), SourceSpec{ID: "netbox", Name: "NetBox", Category: SourceCategoryManagement, Priority: SourcePriorityP0, Version: "3.5"}, SourceConfig{})

	svc := NewSourceManagerServiceImpl(m)

	resp, err := svc.ListSources(context.Background(), &apiv1.ListSourcesRequest{})
	if err != nil {
		t.Fatalf("ListSources failed: %v", err)
	}
	if len(resp.Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(resp.Sources))
	}

	resp, err = svc.ListSources(context.Background(), &apiv1.ListSourcesRequest{Category: "scanner"})
	if err != nil {
		t.Fatalf("ListSources with category failed: %v", err)
	}
	if len(resp.Sources) != 1 {
		t.Errorf("expected 1 scanner, got %d", len(resp.Sources))
	}
	if resp.Sources[0].Id != "trivy" {
		t.Errorf("expected trivy, got %s", resp.Sources[0].Id)
	}
}

func TestSourceManagerServiceImpl_GetSource(t *testing.T) {
	m := NewSourceManagerModule()
	m.stateDir = t.TempDir()

	m.DeploySource(context.Background(), SourceSpec{ID: "trivy", Name: "Trivy", Category: SourceCategoryScanner, Priority: SourcePriorityP0, Version: "1.0"}, SourceConfig{})

	svc := NewSourceManagerServiceImpl(m)

	resp, err := svc.GetSource(context.Background(), &apiv1.GetSourceRequest{Id: "trivy"})
	if err != nil {
		t.Fatalf("GetSource failed: %v", err)
	}
	if resp.Status.Id != "trivy" {
		t.Errorf("expected trivy, got %s", resp.Status.Id)
	}
	if resp.Spec.Name != "Trivy" {
		t.Errorf("expected Trivy, got %s", resp.Spec.Name)
	}

	_, err = svc.GetSource(context.Background(), &apiv1.GetSourceRequest{Id: "nonexistent"})
	if err == nil {
		t.Error("expected error for nonexistent source")
	}
}

func TestSourceManagerServiceImpl_DeploySource(t *testing.T) {
	m := NewSourceManagerModule()
	m.stateDir = t.TempDir()

	svc := NewSourceManagerServiceImpl(m)

	resp, err := svc.DeploySource(context.Background(), &apiv1.DeploySourceRequest{
		Spec: &apiv1.SourceSpec{
			Id:       "nuclei",
			Name:     "Nuclei",
			Category: "scanner",
			Priority: "P0",
			Version:  "3.0",
		},
		Config: map[string]string{"templates": "cves"},
	})
	if err != nil {
		t.Fatalf("DeploySource failed: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}

	status, ok := m.GetSourceStatus("nuclei")
	if !ok {
		t.Fatal("source not found after deploy")
	}
	if status.State != SourceStateInstalled {
		t.Errorf("expected installed, got %s", status.State)
	}
}

func TestSourceManagerServiceImpl_EnableDisableSource(t *testing.T) {
	m := NewSourceManagerModule()
	m.stateDir = t.TempDir()

	m.DeploySource(context.Background(), SourceSpec{ID: "trivy", Name: "Trivy", Category: SourceCategoryScanner, Priority: SourcePriorityP0, Version: "1.0"}, SourceConfig{})

	svc := NewSourceManagerServiceImpl(m)

	resp, err := svc.EnableSource(context.Background(), &apiv1.EnableSourceRequest{Id: "trivy"})
	if err != nil {
		t.Fatalf("EnableSource failed: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}

	status, _ := m.GetSourceStatus("trivy")
	if !status.Enabled {
		t.Error("source should be enabled")
	}

	disableResp, err := svc.DisableSource(context.Background(), &apiv1.DisableSourceRequest{Id: "trivy"})
	if err != nil {
		t.Fatalf("DisableSource failed: %v", err)
	}
	if !disableResp.Success {
		t.Error("expected success")
	}

	status, _ = m.GetSourceStatus("trivy")
	if status.Enabled {
		t.Error("source should be disabled")
	}
}

func TestSourceManagerServiceImpl_UpdateSource(t *testing.T) {
	m := NewSourceManagerModule()
	m.stateDir = t.TempDir()

	m.DeploySource(context.Background(), SourceSpec{ID: "trivy", Name: "Trivy", Category: SourceCategoryScanner, Priority: SourcePriorityP0, Version: "0.49"}, SourceConfig{})
	m.EnableSource(context.Background(), "trivy")

	svc := NewSourceManagerServiceImpl(m)

	resp, err := svc.UpdateSource(context.Background(), &apiv1.UpdateSourceRequest{Id: "trivy", Version: "0.50"})
	if err != nil {
		t.Fatalf("UpdateSource failed: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}

	status, _ := m.GetSourceStatus("trivy")
	if status.Version != "0.50" {
		t.Errorf("expected version 0.50, got %s", status.Version)
	}
}

func TestSourceManagerServiceImpl_UninstallSource(t *testing.T) {
	m := NewSourceManagerModule()
	m.stateDir = t.TempDir()

	m.DeploySource(context.Background(), SourceSpec{ID: "trivy", Name: "Trivy", Category: SourceCategoryScanner, Priority: SourcePriorityP0, Version: "1.0"}, SourceConfig{})

	svc := NewSourceManagerServiceImpl(m)

	resp, err := svc.UninstallSource(context.Background(), &apiv1.UninstallSourceRequest{Id: "trivy"})
	if err != nil {
		t.Fatalf("UninstallSource failed: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}

	_, ok := m.GetSourceStatus("trivy")
	if ok {
		t.Error("source should be uninstalled")
	}
}

func TestSourceManagerServiceImpl_ConfigureSource(t *testing.T) {
	m := NewSourceManagerModule()
	m.stateDir = t.TempDir()

	m.DeploySource(context.Background(), SourceSpec{ID: "netbox", Name: "NetBox", Category: SourceCategoryManagement, Priority: SourcePriorityP0, Version: "3.5"}, SourceConfig{})

	svc := NewSourceManagerServiceImpl(m)

	resp, err := svc.ConfigureSource(context.Background(), &apiv1.ConfigureSourceRequest{
		Id:       "netbox",
		Settings: map[string]string{"api_url": "https://netbox.local"},
	})
	if err != nil {
		t.Fatalf("ConfigureSource failed: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}

	cfg, _ := m.GetSourceConfig("netbox")
	if cfg.Settings["api_url"] != "https://netbox.local" {
		t.Errorf("unexpected api_url: %s", cfg.Settings["api_url"])
	}
}

func TestSourceManagerServiceImpl_GetAuditLog(t *testing.T) {
	m := NewSourceManagerModule()
	m.stateDir = t.TempDir()

	m.DeploySource(context.Background(), SourceSpec{ID: "trivy", Name: "Trivy", Category: SourceCategoryScanner, Priority: SourcePriorityP0, Version: "1.0"}, SourceConfig{})
	m.EnableSource(context.Background(), "trivy")

	svc := NewSourceManagerServiceImpl(m)

	resp, err := svc.GetAuditLog(context.Background(), &apiv1.SourceAuditLogRequest{SourceId: "trivy"})
	if err != nil {
		t.Fatalf("GetAuditLog failed: %v", err)
	}
	if len(resp.Entries) < 2 {
		t.Errorf("expected at least 2 entries, got %d", len(resp.Entries))
	}
}

func TestBuildSourceManagerServiceDesc(t *testing.T) {
	m := NewSourceManagerModule()
	m.stateDir = t.TempDir()
	svc := NewSourceManagerServiceImpl(m)

	desc := BuildSourceManagerServiceDesc(svc)
	if desc.ServiceName != "argus.v1.SourceManagerService" {
		t.Errorf("unexpected service name: %s", desc.ServiceName)
	}

	expectedMethods := []string{
		"ListSources", "GetSource", "DeploySource",
		"EnableSource", "DisableSource", "UpdateSource",
		"UninstallSource", "ConfigureSource", "GetAuditLog",
	}
	for _, method := range expectedMethods {
		if _, ok := desc.Methods[method]; !ok {
			t.Errorf("missing method: %s", method)
		}
	}
}

func TestSourceManagerServiceImpl_DeploySourceValidation(t *testing.T) {
	m := NewSourceManagerModule()
	m.stateDir = t.TempDir()
	svc := NewSourceManagerServiceImpl(m)

	resp, err := svc.DeploySource(context.Background(), &apiv1.DeploySourceRequest{
		Spec: &apiv1.SourceSpec{Id: "", Name: "Test"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Success {
		t.Error("expected failure for empty id")
	}

	_, err = svc.DeploySource(context.Background(), &apiv1.DeploySourceRequest{
		Spec: nil,
	})
	if err == nil {
		t.Error("expected error for nil spec")
	}
}

func TestConvertSourceStatus(t *testing.T) {
	spec := &SourceSpec{
		ID:          "trivy",
		Name:        "Trivy",
		Category:    SourceCategoryScanner,
		Priority:    SourcePriorityP0,
		Description: "Vulnerability scanner",
	}
	status := &SourceStatus{
		ID:      "trivy",
		State:   SourceStateEnabled,
		Version: "1.0",
		Enabled: true,
	}

	pb := convertSourceStatus(status, spec)
	if pb.Id != "trivy" {
		t.Errorf("expected trivy, got %s", pb.Id)
	}
	if pb.Name != "Trivy" {
		t.Errorf("expected Trivy, got %s", pb.Name)
	}
	if pb.Category != "scanner" {
		t.Errorf("expected scanner, got %s", pb.Category)
	}
	if pb.Priority != "P0" {
		t.Errorf("expected P0, got %s", pb.Priority)
	}
	if pb.State != "enabled" {
		t.Errorf("expected enabled, got %s", pb.State)
	}
	if !pb.Enabled {
		t.Error("expected enabled")
	}
}
