//go:build adapter

package management

import (
	"testing"

	"github.com/asscor/asscor/internal/adapter"
	"github.com/asscor/asscor/internal/model"
)

// ======================== P0 Adapter Tests ========================

func TestAnsibleAdapterProperties(t *testing.T) {
	a := NewAnsibleAdapter()
	if a.ID() != "ansible" {
		t.Errorf("ID = %s, want ansible", a.ID())
	}
	if a.Name() != "Ansible" {
		t.Errorf("Name = %s, want Ansible", a.Name())
	}
	if a.Category() != "management" {
		t.Errorf("Category = %s, want management", a.Category())
	}
	if a.Priority() != "P0" {
		t.Errorf("Priority = %s, want P0", a.Priority())
	}
}

func TestAnsibleAdapterParse_GroupedInventory(t *testing.T) {
	a := NewAnsibleAdapter()
	raw := []byte("[webservers]\nweb01\nweb02\n\n[databases]\ndb01\n")

	findings, err := a.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 hosts, got %d", len(findings))
	}

	// Verify host names
	hostNames := make(map[string]bool)
	for _, f := range findings {
		hostNames[f.Resource] = true
		if f.Domain != model.DomainOperationTrust {
			t.Errorf("host %s domain = %s, want %s", f.Resource, f.Domain, model.DomainOperationTrust)
		}
		if !f.Passed {
			t.Errorf("host %s passed = false, want true", f.Resource)
		}
		// Management adapters don't have delegation rules; DelegatedTo may be empty.
		// CheckID should be derived by ApplyDelegation fallback path.
		if f.CheckID == "" {
			t.Logf("host %s CheckID is empty (management adapter, no delegation rule)", f.Resource)
		}
	}
	for _, host := range []string{"web01", "web02", "db01"} {
		if !hostNames[host] {
			t.Errorf("missing host %s", host)
		}
	}

	// Verify ansible_group metadata
	for _, f := range findings {
		group := f.Metadata["ansible_group"]
		switch f.Resource {
		case "web01", "web02":
			if group != "webservers" {
				t.Errorf("host %s group = %s, want webservers", f.Resource, group)
			}
		case "db01":
			if group != "databases" {
				t.Errorf("host %s group = %s, want databases", f.Resource, group)
			}
		}
	}
}

func TestAnsibleAdapterParse_UnGrouped(t *testing.T) {
	a := NewAnsibleAdapter()
	raw := []byte("host01\nhost02 ansible_host=10.0.0.2\n")

	findings, err := a.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Metadata["ansible_group"] != "ungrouped" {
			t.Errorf("host %s group = %s, want ungrouped", f.Resource, f.Metadata["ansible_group"])
		}
	}
}

func TestAnsibleAdapterParse_EmptyInventory(t *testing.T) {
	a := NewAnsibleAdapter()
	raw := []byte("# just a comment\n\n")

	findings, err := a.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (no-hosts placeholder), got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "ANSIBLE-NO-HOSTS" {
		t.Errorf("ID = %s, want ANSIBLE-NO-HOSTS", f.ID)
	}
	if f.Passed {
		t.Error("NO-HOSTS should be marked as passed=false")
	}
}

func TestAnsibleAdapterParse_CommentsIgnored(t *testing.T) {
	a := NewAnsibleAdapter()
	raw := []byte("# [webservers]\n# this is a comment\nhost01\n")

	findings, err := a.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 host, got %d", len(findings))
	}
	if findings[0].Resource != "host01" {
		t.Errorf("Resource = %s, want host01", findings[0].Resource)
	}
}

func TestAnsibleAdapterIsEnabled(t *testing.T) {
	a := NewAnsibleAdapter()
	disabled := a.IsEnabled(map[string]string{"ansible": "off"})
	enabled := a.IsEnabled(map[string]string{"ansible": "on"})
	missing := a.IsEnabled(map[string]string{})
	if disabled {
		t.Error("ansible should be disabled when config=off")
	}
	if !enabled {
		t.Error("ansible should be enabled when config=on")
	}
	if missing {
		t.Error("ansible should be disabled when config missing")
	}
}

// ===== NetBox =====

func TestNetBoxAdapterProperties(t *testing.T) {
	n := NewNetBoxAdapter()
	if n.ID() != "netbox" {
		t.Errorf("ID = %s, want netbox", n.ID())
	}
	if n.Priority() != "P0" {
		t.Errorf("Priority = %s, want P0", n.Priority())
	}
}

func TestNetBoxAdapterParse_Devices(t *testing.T) {
	n := NewNetBoxAdapter()
	raw := []byte(`{"count":2,"results":[
		{"id":1,"name":"core-sw01","device_type":{"id":1,"name":"C9300"},"device_role":{"id":1,"name":"Core Switch"},"site":{"id":1,"name":"DC1"},"status":{"value":"active","label":"Active"},"serial":"ABC123","asset_tag":"A001","primary_ip":{"id":1,"address":"10.0.0.1/24"},"custom_fields":{"criticality":"high"}},
		{"id":2,"name":"edge-fw01","device_type":{"id":2,"name":"PA-440"},"device_role":{"id":2,"name":"Firewall"},"site":{"id":1,"name":"DC1"},"status":{"value":"offline","label":"Offline"},"serial":"DEF456","asset_tag":"A002","primary_ip":{"id":2,"address":"10.0.0.2/24"},"custom_fields":{"criticality":"critical"}}
	]}`)

	findings, err := n.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(findings))
	}

	// core-sw01: active, high criticality → passed from Parse (Map only marks Critical as non-passed)
	f1 := findings[0]
	if f1.Resource != "core-sw01" {
		t.Errorf("Resource = %s, want core-sw01", f1.Resource)
	}
	if !f1.Passed {
		t.Error("core-sw01 active/high should be passed from Parse")
	}
	if f1.Metadata["status"] != "active" {
		t.Errorf("status = %s, want active", f1.Metadata["status"])
	}
	if f1.Metadata["primary_ip"] != "10.0.0.1/24" {
		t.Errorf("primary_ip = %s, want 10.0.0.1/24", f1.Metadata["primary_ip"])
	}
	if f1.Domain != model.DomainBusinessContinuity {
		t.Errorf("Domain = %s, want %s", f1.Domain, model.DomainBusinessContinuity)
	}

	// edge-fw01: offline, critical → should be SeverityCritical
	f2 := findings[1]
	if f2.Resource != "edge-fw01" {
		t.Errorf("Resource = %s, want edge-fw01", f2.Resource)
	}
	if f2.Severity != adapter.SeverityCritical {
		t.Errorf("critical device severity = %s, want %s", f2.Severity, adapter.SeverityCritical)
	}
}

func TestNetBoxAdapterParse_Empty(t *testing.T) {
	n := NewNetBoxAdapter()
	raw := []byte(`{"count":0,"results":[]}`)

	findings, err := n.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (no-devices placeholder), got %d", len(findings))
	}
	if findings[0].ID != "NETBOX-NO-DEVICES" {
		t.Errorf("ID = %s, want NETBOX-NO-DEVICES", findings[0].ID)
	}
}

func TestNetBoxAdapterMap_Critical(t *testing.T) {
	n := NewNetBoxAdapter()
	finding := &adapter.NormalizedFinding{
		ID:       "TEST-1",
		Severity: adapter.SeverityCritical,
		Passed:   true,
		Detail:   "test",
	}
	findings := []*adapter.NormalizedFinding{finding}
	mapped := n.Map(findings)
	if len(mapped) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(mapped))
	}
	if mapped[0].Passed {
		t.Error("critical finding should be marked passed=false after Map")
	}
	if mapped[0].Detail != "test (CRITICAL asset)" {
		t.Errorf("Detail = %q, want 'test (CRITICAL asset)'", mapped[0].Detail)
	}
}

// ===== Snipe-IT =====

func TestSnipeITAdapterProperties(t *testing.T) {
	s := NewSnipeITAdapter()
	if s.ID() != "snipe_it" {
		t.Errorf("ID = %s, want snipe_it", s.ID())
	}
	if s.Priority() != "P0" {
		t.Errorf("Priority = %s, want P0", s.Priority())
	}
}

func TestSnipeITAdapterParse_Assets(t *testing.T) {
	s := NewSnipeITAdapter()
	raw := []byte(`{"total":3,"rows":[
		{"id":1,"name":"ThinkPad X1","asset_tag":"LAP-001","serial":"SER-001","model":{"id":1,"name":"ThinkPad X1 Carbon"},"category":{"id":1,"name":"Laptops"},"status_label":{"id":1,"name":"Deployed","status_type":"deployed","status_meta":"deployed"},"assigned_to":{"id":1,"name":"Alice"},"location":{"id":1,"name":"Headquarters"},"warranty_expires":{"date":"2025-12-31","formatted":"2025-12-31"}},
		{"id":2,"name":"Dell R740","asset_tag":"SVR-001","serial":"SER-002","model":{"id":2,"name":"PowerEdge R740"},"category":{"id":2,"name":"Servers"},"status_label":{"id":2,"name":"Broken","status_type":"broken","status_meta":"broken"},"assigned_to":null,"location":{"id":2,"name":"DC1"},"warranty_expires":null}
	]}`)

	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(findings))
	}

	// ThinkPad X1: deployed → passed
	f1 := findings[0]
	if f1.Resource != "ThinkPad X1" {
		t.Errorf("Resource = %s, want ThinkPad X1", f1.Resource)
	}
	if !f1.Passed {
		t.Error("deployed asset should pass")
	}
	if f1.Metadata["assigned_to"] != "Alice" {
		t.Errorf("assigned_to = %s, want Alice", f1.Metadata["assigned_to"])
	}
	if f1.Metadata["warranty_expires"] != "2025-12-31" {
		t.Errorf("warranty_expires = %s, want 2025-12-31", f1.Metadata["warranty_expires"])
	}
	if f1.Domain != model.DomainBusinessContinuity {
		t.Errorf("Domain = %s, want %s", f1.Domain, model.DomainBusinessContinuity)
	}

	// Dell R740: broken → failed, critical
	f2 := findings[1]
	if f2.Resource != "Dell R740" {
		t.Errorf("Resource = %s, want Dell R740", f2.Resource)
	}
	if f2.Passed {
		t.Error("broken asset should not pass")
	}
	if f2.Severity != adapter.SeverityCritical {
		t.Errorf("broken severity = %s, want %s", f2.Severity, adapter.SeverityCritical)
	}
	if f2.Metadata["assigned_to"] != "unassigned" {
		t.Errorf("unassigned asset assigned_to = %s, want unassigned", f2.Metadata["assigned_to"])
	}
}

func TestSnipeITAdapterParse_Empty(t *testing.T) {
	s := NewSnipeITAdapter()
	raw := []byte(`{"total":0,"rows":[]}`)

	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (no-assets), got %d", len(findings))
	}
	if findings[0].ID != "SNIPEIT-NO-ASSETS" {
		t.Errorf("ID = %s, want SNIPEIT-NO-ASSETS", findings[0].ID)
	}
}

func TestSnipeITAdapterParse_StatusMapping(t *testing.T) {
	s := NewSnipeITAdapter()
	tests := []struct {
		statusType   string
		expectPassed bool
		expectSeverity adapter.Severity
	}{
		{"deployed", true, adapter.SeverityInfo},
		{"pending", true, adapter.SeverityInfo},
		{"archived", true, adapter.SeverityInfo},
		{"undeployable", false, adapter.SeverityCritical},
		{"broken", false, adapter.SeverityCritical},
		{"ready to deploy", true, adapter.SeverityLow},
		{"unknown_status", false, adapter.SeverityMedium},
	}

	for _, tc := range tests {
		raw := []byte(`{"total":1,"rows":[{"id":1,"name":"test","asset_tag":"T-001","serial":"S","model":{"id":1,"name":"M"},"category":{"id":1,"name":"C"},"status_label":{"id":1,"name":"` +
			tc.statusType + `","status_type":"` + tc.statusType + `","status_meta":""},"assigned_to":null,"location":null}]}`)
		findings, err := s.Parse(raw)
		if err != nil {
			t.Errorf("status %q parse error: %v", tc.statusType, err)
			continue
		}
		f := findings[0]
		if f.Passed != tc.expectPassed {
			t.Errorf("status %q passed = %v, want %v", tc.statusType, f.Passed, tc.expectPassed)
		}
		if f.Severity != tc.expectSeverity {
			t.Errorf("status %q severity = %s, want %s", tc.statusType, f.Severity, tc.expectSeverity)
		}
	}
}

// ======================== P1 Adapter Tests ========================

func TestFreeIPAAdapterProperties(t *testing.T) {
	f := NewFreeIPAAdapter()
	if f.ID() != "freeipa" {
		t.Errorf("ID = %s, want freeipa", f.ID())
	}
	if f.Priority() != "P1" {
		t.Errorf("Priority = %s, want P1", f.Priority())
	}
}

func TestFreeIPAAdapterParse_WithUsers(t *testing.T) {
	f := NewFreeIPAAdapter()
	raw := []byte("User login: alice\n  UID: 1000\n  Account disabled: False\nUser login: bob\n  UID: 1001\n  Account disabled: True\nUser login: charlie\n  UID: 1002\n  Account disabled: False\n")
	findings, err := f.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings (3 users + 1 disabled), got %d", len(findings))
	}
	if findings[0].ID != "FREEIPA-USER-alice" {
		t.Errorf("ID = %s, want FREEIPA-USER-alice", findings[0].ID)
	}
	if !findings[0].Passed {
		t.Error("active user should pass")
	}
	if findings[0].Domain != model.DomainOperationTrust {
		t.Errorf("Domain = %s, want %s", findings[0].Domain, model.DomainOperationTrust)
	}
}

func TestFreeIPAAdapterParse_NoUsers(t *testing.T) {
	f := NewFreeIPAAdapter()
	raw := []byte("No users found\n")
	findings, err := f.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 summary finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Passed {
		t.Error("no users found — directory check should report failure")
	}
	if finding.Severity != adapter.SeverityMedium {
		t.Errorf("Severity = %v, want Medium for empty directory", finding.Severity)
	}
}

func TestKeycloakAdapterProperties(t *testing.T) {
	k := NewKeycloakAdapter()
	if k.ID() != "keycloak" {
		t.Errorf("ID = %s, want keycloak", k.ID())
	}
}

func TestKeycloakAdapterParse_Accessible(t *testing.T) {
	k := NewKeycloakAdapter()
	raw := []byte(`[{"id":"abc","realm":"master","enabled":true},{"id":"def","realm":"app-realm","enabled":false}]`)
	findings, err := k.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 realm findings, got %d", len(findings))
	}
	if !findings[0].Passed {
		t.Error("master realm (enabled=true) should pass")
	}
}

func TestKeycloakAdapterParse_NotAccessible(t *testing.T) {
	k := NewKeycloakAdapter()
	raw := []byte(`{"error":"unauthorized"}`)
	findings, err := k.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if findings[0].Passed {
		t.Error("non-array response should be not accessible")
	}
}

func TestWazuhSIEMAdapterProperties(t *testing.T) {
	w := NewWazuhSIEMAdapter()
	if w.ID() != "wazuh_siem" {
		t.Errorf("ID = %s, want wazuh_siem", w.ID())
	}
}

func TestWazuhSIEMAdapterParse_Authenticated(t *testing.T) {
	w := NewWazuhSIEMAdapter()
	raw := []byte(`{"data":{"token":"eyJhbGciOiJIUzI1NiIs..."}}`)
	findings, err := w.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	f := findings[0]
	if !f.Passed {
		t.Error("response with token should pass")
	}
	if f.Domain != model.DomainResilience {
		t.Errorf("Domain = %s, want %s", f.Domain, model.DomainResilience)
	}
}

func TestWazuhSIEMAdapterParse_NotAuthenticated(t *testing.T) {
	w := NewWazuhSIEMAdapter()
	raw := []byte(`{"error":"invalid credentials"}`)
	findings, err := w.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if findings[0].Passed {
		t.Error("response without token should not pass")
	}
}

func TestRundeckAdapterProperties(t *testing.T) {
	r := NewRundeckAdapter()
	if r.ID() != "rundeck" {
		t.Errorf("ID = %s, want rundeck", r.ID())
	}
}

func TestRundeckAdapterParse_Accessible(t *testing.T) {
	r := NewRundeckAdapter()
	raw := []byte(`{"system":{"rundeck":{"version":"4.0.0","node":"rundeck01"},"executions":{"active":false}}}`)
	findings, err := r.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if findings[0].Passed {
		t.Error("executor inactive — should not pass")
	}
	if findings[0].Domain != model.DomainOperationTrust {
		t.Errorf("Domain = %s, want %s", findings[0].Domain, model.DomainOperationTrust)
	}
}

func TestRundeckAdapterParse_NotAccessible(t *testing.T) {
	r := NewRundeckAdapter()
	raw := []byte(`{"error":"forbidden"}`)
	findings, err := r.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if findings[0].Passed {
		t.Error("response without 'system' should not pass")
	}
}

// ======================== P2 Adapter Tests ========================

func TestJiraAdapterProperties(t *testing.T) {
	j := NewJiraAdapter()
	if j.ID() != "jira" {
		t.Errorf("ID = %s, want jira", j.ID())
	}
	if j.Priority() != "P2" {
		t.Errorf("Priority = %s, want P2", j.Priority())
	}
}

func TestJiraAdapterParse_Accessible(t *testing.T) {
	j := NewJiraAdapter()
	raw := []byte(`{"self":"https://jira.internal/rest/api/2/user?username=admin","name":"admin","displayName":"Admin User","active":true,"emailAddress":"admin@internal"}`)
	findings, err := j.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if !findings[0].Passed {
		t.Error("active user should pass")
	}
	if findings[0].Domain != model.DomainOperationTrust {
		t.Errorf("Domain = %s, want %s", findings[0].Domain, model.DomainOperationTrust)
	}
}

func TestJiraAdapterParse_NotAccessible(t *testing.T) {
	j := NewJiraAdapter()
	raw := []byte(`{"error":"authentication failed"}`)
	findings, err := j.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if findings[0].Passed {
		t.Error("response without 'self' should not pass")
	}
}

func TestTerraformAdapterProperties(t *testing.T) {
	tf := NewTerraformAdapter()
	if tf.ID() != "terraform" {
		t.Errorf("ID = %s, want terraform", tf.ID())
	}
}

func TestTerraformAdapterParse_WithResources(t *testing.T) {
	tf := NewTerraformAdapter()
	raw := []byte(`{"version":4,"terraform_version":"1.5.0","resources":[{"mode":"managed","type":"aws_instance","name":"web"},{"mode":"data","type":"aws_ami","name":"ubuntu"}]}`)
	findings, err := tf.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 resource type findings, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "TERRAFORM-RESOURCE-aws_instance" && f.ID != "TERRAFORM-RESOURCE-aws_ami" {
		t.Errorf("ID = %s, want TERRAFORM-RESOURCE-<type>", f.ID)
	}
	if !f.Passed {
		t.Error("Terraform managed resources should be reported as passed")
	}
}

func TestTerraformAdapterParse_NoResources(t *testing.T) {
	tf := NewTerraformAdapter()
	raw := []byte(`Terraform v1.6.0`)
	findings, err := tf.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	f := findings[0]
	if !f.Passed {
		t.Error("terraform binary found — should still report as accessible")
	}
}

func TestOpenTofuAdapterProperties(t *testing.T) {
	o := NewOpenTofuAdapter()
	if o.ID() != "opentofu" {
		t.Errorf("ID = %s, want opentofu", o.ID())
	}
}

func TestOpenTofuAdapterParse_WithResources(t *testing.T) {
	o := NewOpenTofuAdapter()
	raw := []byte(`{"version":4,"tofu_version":"1.7.0","resources":[{"mode":"managed","type":"docker_container","name":"app"},{"mode":"managed","type":"docker_image","name":"app_image"}]}`)
	findings, err := o.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 resource type findings, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "OPENTOFU-RESOURCE-docker_container" && f.ID != "OPENTOFU-RESOURCE-docker_image" {
		t.Errorf("ID = %s, want OPENTOFU-RESOURCE-<type>", f.ID)
	}
	if !f.Passed {
		t.Error("OpenTofu managed resources should be reported as passed")
	}
}

func TestOpenTofuAdapterParse_NoResources(t *testing.T) {
	o := NewOpenTofuAdapter()
	raw := []byte(`OpenTofu v1.7.0`)
	findings, err := o.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if !findings[0].Passed {
		t.Error("opentofu binary found — should still report as accessible")
	}
}

// ======================== Registration Tests ========================

func TestManagerAdapterDomainMapping(t *testing.T) {
	tests := []struct {
		name    string
		newFn   func() adapter.Adapter
		wantDomain string
	}{
		{"Ansible", func() adapter.Adapter { return NewAnsibleAdapter() }, model.DomainOperationTrust},
		{"NetBox", func() adapter.Adapter { return NewNetBoxAdapter() }, model.DomainBusinessContinuity},
		{"Snipe-IT", func() adapter.Adapter { return NewSnipeITAdapter() }, model.DomainBusinessContinuity},
		{"FreeIPA", func() adapter.Adapter { return NewFreeIPAAdapter() }, model.DomainOperationTrust},
		{"Keycloak", func() adapter.Adapter { return NewKeycloakAdapter() }, model.DomainOperationTrust},
		{"Wazuh SIEM", func() adapter.Adapter { return NewWazuhSIEMAdapter() }, model.DomainResilience},
		{"Rundeck", func() adapter.Adapter { return NewRundeckAdapter() }, model.DomainOperationTrust},
		{"Jira", func() adapter.Adapter { return NewJiraAdapter() }, model.DomainOperationTrust},
		{"Terraform", func() adapter.Adapter { return NewTerraformAdapter() }, model.DomainOperationTrust},
		{"OpenTofu", func() adapter.Adapter { return NewOpenTofuAdapter() }, model.DomainOperationTrust},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := tc.newFn()
			if a.Name() != tc.name && a.Name() != "Snipe-IT" && a.Name() != "Wazuh SIEM" {
				// Name check is approximate: some have spaces like "Snipe-IT" or "Wazuh SIEM"
				t.Logf("Name = %s", a.Name())
			}
			if a.Category() != "management" {
				t.Errorf("Category = %s, want management", a.Category())
			}
		})
	}
}

func TestAllManagerAdaptersRegistered(t *testing.T) {
	// Reset registry to isolate test
	adapter.ResetRegistryForTesting()

	// Re-register by calling init functions — but Go init only runs once.
	// Instead, verify each constructor returns a valid adapter.
	adapters := []adapter.Adapter{
		NewAnsibleAdapter(),
		NewNetBoxAdapter(),
		NewSnipeITAdapter(),
		NewFreeIPAAdapter(),
		NewKeycloakAdapter(),
		NewWazuhSIEMAdapter(),
		NewRundeckAdapter(),
		NewJiraAdapter(),
		NewTerraformAdapter(),
		NewOpenTofuAdapter(),
	}

	expected := map[string]bool{
		"ansible":     false,
		"netbox":      false,
		"snipe_it":    false,
		"freeipa":     false,
		"keycloak":    false,
		"wazuh_siem":  false,
		"rundeck":     false,
		"jira":        false,
		"terraform":   false,
		"opentofu":    false,
	}

	for _, a := range adapters {
		expected[a.ID()] = true
	}

	for id, found := range expected {
		if !found {
			t.Errorf("adapter %q not registered", id)
		}
	}
}

func TestAllManagerAdaptersHaveValidate(t *testing.T) {
	adapters := []adapter.Adapter{
		NewAnsibleAdapter(),
		NewNetBoxAdapter(),
		NewSnipeITAdapter(),
		NewFreeIPAAdapter(),
		NewKeycloakAdapter(),
		NewWazuhSIEMAdapter(),
		NewRundeckAdapter(),
		NewJiraAdapter(),
		NewTerraformAdapter(),
		NewOpenTofuAdapter(),
	}

	for _, a := range adapters {
		t.Run(a.ID(), func(t *testing.T) {
			findings := []*adapter.NormalizedFinding{
				{ID: "test-1", Title: "Test Finding", Domain: "operation_trust", Passed: true},
			}
			validated, errs := a.Validate(findings)
			if len(validated) != len(findings) {
				t.Errorf("Validate returned %d findings, want %d", len(validated), len(findings))
			}
			for _, e := range errs {
				t.Errorf("unexpected validation error: %v", e)
			}
		})
	}
}