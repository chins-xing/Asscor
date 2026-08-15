//go:build spc

package spc

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/model"
)

func TestParseOSCALYAML(t *testing.T) {
	yamlData := []byte(`---
findings:
  item1:
    cve_id: CVE-2024-YAML01
    description: Test YAML vulnerability 1
    cvss_score: 9.8
    cvss_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    epss_score: 0.72
    epss_percentile: 0.95
    in_kev: true
    date_published: "2024-01-15"
    date_modified: "2024-03-20"
    affected_cpes:
      - "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"
    attck_techniques:
      - T1190
    misp_galaxy_tags:
      - "misp-galaxy:mitre-attck-pattern"
    apt_group_assoc:
      - APT29
  item2:
    cve_id: CVE-2024-YAML02
    description: Test YAML vulnerability 2
    cvss_score: 7.5
    in_kev: false
    date_published: "2024-02-10"
`)

	records, err := parseOSCALYAML(yamlData)
	if err != nil {
		t.Fatalf("parseOSCALYAML failed: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	if records[0].CVEID != "CVE-2024-YAML01" {
		t.Errorf("first record CVEID = %s, want CVE-2024-YAML01", records[0].CVEID)
	}
	if records[0].CVSSScore != 9.8 {
		t.Errorf("first record CVSSScore = %.1f, want 9.8", records[0].CVSSScore)
	}
	if !records[0].InKEV {
		t.Error("first record InKEV should be true")
	}
	if len(records[0].AffectedCPEs) != 1 {
		t.Errorf("first record AffectedCPEs len = %d, want 1", len(records[0].AffectedCPEs))
	}
	if len(records[0].AttckTechniques) != 1 || records[0].AttckTechniques[0] != "T1190" {
		t.Errorf("first record AttckTechniques = %v, want [T1190]", records[0].AttckTechniques)
	}
	if len(records[0].APTGroupAssoc) != 1 || records[0].APTGroupAssoc[0] != "APT29" {
		t.Errorf("first record APTGroupAssoc = %v, want [APT29]", records[0].APTGroupAssoc)
	}

	if records[1].CVEID != "CVE-2024-YAML02" {
		t.Errorf("second record CVEID = %s, want CVE-2024-YAML02", records[1].CVEID)
	}
	if records[1].InKEV {
		t.Error("second record InKEV should be false")
	}
}

func TestParseOSCALYAMLEmpty(t *testing.T) {
	_, err := parseOSCALYAML([]byte(`---\nfindings:\n`))
	if err == nil {
		t.Error("expected error for empty YAML findings")
	}
}

func TestParseOSCALXML(t *testing.T) {
	xmlData, err := xml.Marshal(oscalXMLRoot{
		Findings: oscalXMLFindings{
			Finding: []oscalXMLFinding{
				{
					CVEID:         "CVE-2024-XML01",
					Description:   "Test XML vulnerability",
					CVSSScore:     8.5,
					CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					EPSSScore:     0.45,
					InKEV:         true,
					DatePublished: "2024-01-15",
					AffectedCPEs: struct {
						CPE []string `xml:"cpe"`
					}{CPE: []string{"cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"}},
					AttckTechniques: struct {
						Technique []string `xml:"technique"`
					}{Technique: []string{"T1190", "T1210"}},
					APTGroupAssoc: struct {
						Group []string `xml:"group"`
					}{Group: []string{"APT41"}},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("xml marshal: %v", err)
	}

	records, err := parseOSCALXML(xmlData)
	if err != nil {
		t.Fatalf("parseOSCALXML failed: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	if records[0].CVEID != "CVE-2024-XML01" {
		t.Errorf("CVEID = %s, want CVE-2024-XML01", records[0].CVEID)
	}
	if records[0].CVSSScore != 8.5 {
		t.Errorf("CVSSScore = %.1f, want 8.5", records[0].CVSSScore)
	}
	if !records[0].InKEV {
		t.Error("InKEV should be true")
	}
	if len(records[0].AffectedCPEs) != 1 {
		t.Errorf("AffectedCPEs len = %d, want 1", len(records[0].AffectedCPEs))
	}
	if len(records[0].AttckTechniques) != 2 {
		t.Errorf("AttckTechniques len = %d, want 2", len(records[0].AttckTechniques))
	}
	if len(records[0].APTGroupAssoc) != 1 || records[0].APTGroupAssoc[0] != "APT41" {
		t.Errorf("APTGroupAssoc = %v, want [APT41]", records[0].APTGroupAssoc)
	}
}

func TestParseOSCALXMLEmpty(t *testing.T) {
	xmlData, _ := xml.Marshal(oscalXMLRoot{})
	_, err := parseOSCALXML(xmlData)
	if err == nil {
		t.Error("expected error for empty XML findings")
	}
}

func TestImportOSCALJSON(t *testing.T) {
	spc := New()
	spc.SetEnabled(true)

	data := []byte(`[
		{"cve_id":"CVE-2024-JSON01","description":"JSON test vuln","cvss_score":7.5,"in_kev":true,"date_published":"2024-01-01"},
		{"cve_id":"CVE-2024-JSON02","description":"JSON test vuln 2","cvss_score":5.3,"in_kev":false,"date_published":"2024-02-01"}
	]`)

	added, err := spc.ImportOSCAL(data, "json")
	if err != nil {
		t.Fatalf("ImportOSCAL json: %v", err)
	}
	if added != 2 {
		t.Errorf("added = %d, want 2", added)
	}
	if spc.GetCVECount() != 2 {
		t.Errorf("CVECount = %d, want 2", spc.GetCVECount())
	}
}

func TestImportOSCALJSONWrapped(t *testing.T) {
	spc := New()
	spc.SetEnabled(true)

	data := []byte(`{"findings":[
		{"cve_id":"CVE-2024-WRAP01","description":"Wrapped JSON test","cvss_score":9.0}
	]}`)

	added, err := spc.ImportOSCAL(data, "json")
	if err != nil {
		t.Fatalf("ImportOSCAL wrapped json: %v", err)
	}
	if added != 1 {
		t.Errorf("added = %d, want 1", added)
	}
}

func TestImportOSCALInvalidFormat(t *testing.T) {
	spc := New()
	spc.SetEnabled(true)

	_, err := spc.ImportOSCAL([]byte{}, "csv")
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestParseNVDCVE(t *testing.T) {
	spc := New()

	cve := nvdCVE{
		ID:           "CVE-2024-NVD01",
		Published:    "2024-01-15T10:30:00.000",
		LastModified: "2024-03-20T14:00:00.000",
		Descriptions: []nvdLangStr{
			{Lang: "en", Value: "Test NVD vulnerability"},
			{Lang: "es", Value: "Vulnerabilidad de prueba"},
		},
		Metrics: nvdMetrics{
			CVSSMetricV31: []nvdCVSSMetric{
				{
					CVSSData: nvdCVSSData{
						Version:      "3.1",
						VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						BaseScore:    9.8,
						BaseSeverity: "CRITICAL",
					},
				},
			},
		},
		Configurations: []nvdConfig{
			{
				Nodes: []nvdNode{
					{
						CPEMatch: []nvdCPEMatch{
							{
								Vulnerable: true,
								Criteria:   "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*",
							},
						},
					},
				},
			},
		},
		References: []nvdReference{
			{
				URL:  "https://nvd.nist.gov/vuln/detail/CVE-2024-NVD01",
				Tags: []string{"Patch", "ATT&CK:T1190"},
			},
		},
	}

	result := spc.parseNVDCVE(cve)

	if result.CVEID != "CVE-2024-NVD01" {
		t.Errorf("CVEID = %s, want CVE-2024-NVD01", result.CVEID)
	}
	if result.Description != "Test NVD vulnerability" {
		t.Errorf("Description = %s, want English description", result.Description)
	}
	if result.CVSS != 9.8 {
		t.Errorf("CVSS = %.1f, want 9.8", result.CVSS)
	}
	if result.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("CVSSVector = %s", result.CVSSVector)
	}
	if len(result.AffectedCPEs) != 1 {
		t.Errorf("AffectedCPEs len = %d, want 1", len(result.AffectedCPEs))
	}
	if len(result.AttckTechniques) != 1 || result.AttckTechniques[0] != "T1190" {
		t.Errorf("AttckTechniques = %v, want [T1190]", result.AttckTechniques)
	}
	if result.DatePublished.IsZero() {
		t.Error("DatePublished should not be zero")
	}
}

func TestParseNVDCVEV2(t *testing.T) {
	spc := New()

	cve := nvdCVE{
		ID:        "CVE-2024-NVD02",
		Published: "2024-01-15T10:30:00.000",
		Metrics: nvdMetrics{
			CVSSMetricV2: []nvdCVSSMetricV2{
				{
					CVSSData: nvdCVSSDataV2{
						Version:      "2.0",
						VectorString: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
						BaseScore:    7.5,
					},
				},
			},
		},
	}

	result := spc.parseNVDCVE(cve)
	if result.CVSS != 7.5 {
		t.Errorf("CVSS = %.1f, want 7.5", result.CVSS)
	}
}

func TestParseMISPEvent(t *testing.T) {
	spc := New()

	event := mispEvent{
		ID:   "1234",
		Info: "Active exploitation of OpenSSL vulnerability",
		Date: "2024-01-15",
		Tags: []mispTag{
			{Name: "misp-galaxy:mitre-attck-pattern=\"Initial Access - T1190\""},
			{Name: "misp-galaxy:threat-actor=\"APT29\""},
		},
		Galaxy: []mispGalaxy{
			{
				Name: "Intrusion Set",
				Type: "threat-actor",
				Cluster: []mispGalaxyCluster{
					{Value: "APT29", TagName: "threat-actor=APT29"},
				},
			},
		},
		Attribute: []mispAttribute{
			{Type: "vulnerability", Value: "CVE-2024-MISP01", Category: "External analysis"},
			{Type: "vulnerability", Value: "CVE-2024-MISP02", Category: "External analysis"},
			{Type: "ip-dst", Value: "10.0.0.1", Category: "Network activity"},
		},
	}

	results := spc.parseMISPEvent(event)

	if len(results) != 2 {
		t.Fatalf("expected 2 CVEs, got %d", len(results))
	}

	if results[0].CVEID != "CVE-2024-MISP01" {
		t.Errorf("first CVE = %s, want CVE-2024-MISP01", results[0].CVEID)
	}
	if results[1].CVEID != "CVE-2024-MISP02" {
		t.Errorf("second CVE = %s, want CVE-2024-MISP02", results[1].CVEID)
	}

	if results[0].Description != "Active exploitation of OpenSSL vulnerability" {
		t.Errorf("Description = %s", results[0].Description)
	}

	if len(results[0].APTGroupAssoc) == 0 {
		t.Error("expected APT group association")
	}
}

func TestExtractATTCKTechnique(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"misp-galaxy:mitre-attck-pattern=\"Initial Access - T1190\"", "T1190"},
		{"misp-galaxy:mitre-attck-pattern=\"T1059 - Command Scripting\"", "T1059"},
		{"some-tag-without-technique", ""},
		{"T1078 Valid Accounts", "T1078"},
	}

	for _, tt := range tests {
		got := extractATTCKTechnique(tt.input)
		if got != tt.expected {
			t.Errorf("extractATTCKTechnique(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSPCConfigureMISPValidation(t *testing.T) {
	spc := New()

	err := spc.ConfigureMISP("", "key")
	if err == nil {
		t.Error("expected error for empty baseURL")
	}

	err = spc.ConfigureMISP("http://misp.example.com", "")
	if err == nil {
		t.Error("expected error for empty apiKey")
	}
}

func TestSPCDuplicateCVE(t *testing.T) {
	spc := New()
	spc.SetEnabled(true)

	cve := kernel.SPCCVEScore{
		CVEID:         "CVE-2024-DUP01",
		CVSS:          9.8,
		DatePublished: time.Now(),
	}
	spc.AddCVE(cve)
	spc.AddCVE(cve)

	if spc.GetCVECount() != 1 {
		t.Errorf("expected 1 CVE after duplicate add, got %d", spc.GetCVECount())
	}
}

func TestSPCClearCache(t *testing.T) {
	spc := New()
	spc.SetEnabled(true)

	spc.AddCVE(kernel.SPCCVEScore{CVEID: "CVE-TEST-01", CVSS: 5.0, DatePublished: time.Now()})
	spc.AddCVE(kernel.SPCCVEScore{CVEID: "CVE-TEST-02", CVSS: 7.0, DatePublished: time.Now()})

	if spc.GetCVECount() != 2 {
		t.Fatalf("expected 2 CVEs, got %d", spc.GetCVECount())
	}

	spc.ClearCache()
	if spc.GetCVECount() != 0 {
		t.Errorf("expected 0 CVEs after clear, got %d", spc.GetCVECount())
	}
}

func TestSPCUpsertAsset(t *testing.T) {
	spc := New()

	asset := kernel.LocalAsset{
		HostID:      "web-01",
		Hostname:    "web-01.example.com",
		Role:        "web-server",
		NetworkZone: "dmz",
	}
	spc.UpsertAsset(asset)

	got := spc.GetAsset("web-01")
	if got == nil {
		t.Fatal("expected asset, got nil")
	}
	if got.Hostname != "web-01.example.com" {
		t.Errorf("Hostname = %s, want web-01.example.com", got.Hostname)
	}
	if got.NetworkZone != "dmz" {
		t.Errorf("NetworkZone = %s, want dmz", got.NetworkZone)
	}

	asset.NetworkZone = "internal"
	spc.UpsertAsset(asset)

	got = spc.GetAsset("web-01")
	if got.NetworkZone != "internal" {
		t.Errorf("NetworkZone after upsert = %s, want internal", got.NetworkZone)
	}
}

func TestSPCClassifyAction(t *testing.T) {
	tests := []struct {
		pscore   float64
		expected string
	}{
		{0.96, "none"},
		{0.90, "notify_admin"},
		{0.80, "patch_recommended"},
		{0.70, "priority_fix"},
		{0.60, "isolate_host"},
		{0.50, "isolate_host"},
	}

	for _, tt := range tests {
		got := kernel.ClassifyAction(tt.pscore).String()
		if got != tt.expected {
			t.Errorf("ClassifyAction(%.2f) = %s, want %s", tt.pscore, got, tt.expected)
		}
	}
}

func TestSPCCleanupOldCVEs(t *testing.T) {
	spc := New()
	spc.SetEnabled(true)

	now := time.Now()
	spc.AddCVE(kernel.SPCCVEScore{
		CVEID:         "CVE-OLD-01",
		CVSS:          5.0,
		DateModified:  now.AddDate(0, 0, -400),
		DatePublished: now.AddDate(0, 0, -500),
	})
	spc.AddCVE(kernel.SPCCVEScore{
		CVEID:         "CVE-KEV-01",
		CVSS:          9.0,
		InKEV:         true,
		DateModified:  now.AddDate(0, 0, -400),
		DatePublished: now.AddDate(0, 0, -500),
	})
	spc.AddCVE(kernel.SPCCVEScore{
		CVEID:         "CVE-RECENT-01",
		CVSS:          7.0,
		DateModified:  now.AddDate(0, 0, -10),
		DatePublished: now.AddDate(0, 0, -30),
	})

	if spc.GetCVECount() != 3 {
		t.Fatalf("expected 3 CVEs, got %d", spc.GetCVECount())
	}

	spc.cleanupOldCVEs()

	count := spc.GetCVECount()
	if count != 2 {
		t.Errorf("expected 2 CVEs after cleanup (KEV + recent), got %d", count)
	}

	kevCount := spc.GetKEVCount()
	if kevCount != 1 {
		t.Errorf("expected 1 KEV CVE, got %d", kevCount)
	}
}

func TestParseOSCALYAMLWithComments(t *testing.T) {
	yamlData := []byte(`---
# This is a comment
findings:
  # Another comment
  vuln1:
    cve_id: CVE-2024-COMMENT
    description: Test with comments
    cvss_score: 6.5
    in_kev: false
    date_published: "2024-05-01"
`)

	records, err := parseOSCALYAML(yamlData)
	if err != nil {
		t.Fatalf("parseOSCALYAML with comments: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].CVEID != "CVE-2024-COMMENT" {
		t.Errorf("CVEID = %s, want CVE-2024-COMMENT", records[0].CVEID)
	}
}

func TestNVDAPICVEFallback(t *testing.T) {
	spc := New()
	spc.SetEnabled(true)

	cve := nvdCVE{
		ID:        "CVE-2024-NOFMT",
		Published: "2024-01-15T10:30:00Z",
		Descriptions: []nvdLangStr{
			{Lang: "en", Value: "RFC3339 date format test"},
		},
	}

	result := spc.parseNVDCVE(cve)
	if result.DatePublished.IsZero() {
		t.Error("DatePublished should parse from RFC3339 format")
	}
}

func TestSPCImportOSCALDuplicateHandling(t *testing.T) {
	spc := New()
	spc.SetEnabled(true)

	data1 := []byte(`[{"cve_id":"CVE-2024-DUP","description":"First import","cvss_score":7.5}]`)
	added1, _ := spc.ImportOSCAL(data1, "json")
	if added1 != 1 {
		t.Errorf("first import added = %d, want 1", added1)
	}

	data2 := []byte(`[{"cve_id":"CVE-2024-DUP","description":"Second import","cvss_score":9.0}]`)
	added2, _ := spc.ImportOSCAL(data2, "json")
	if added2 != 0 {
		t.Errorf("duplicate import added = %d, want 0", added2)
	}

	cves := spc.GetCVEs()
	if len(cves) != 1 {
		t.Fatalf("expected 1 CVE, got %d", len(cves))
	}
	if cves[0].CVSS != 9.0 {
		t.Errorf("duplicate CVE should merge higher CVSS score, CVSS = %.1f", cves[0].CVSS)
	}
}

func TestMISPEventNoCVEAttributes(t *testing.T) {
	spc := New()

	event := mispEvent{
		ID:   "5678",
		Info: "Suspicious activity without CVE",
		Date: "2024-02-01",
		Attribute: []mispAttribute{
			{Type: "ip-dst", Value: "10.0.0.1", Category: "Network activity"},
		},
	}

	results := spc.parseMISPEvent(event)
	if len(results) != 0 {
		t.Errorf("expected 0 CVEs from non-vulnerability event, got %d", len(results))
	}
}

func TestSPCExactVersionMatch(t *testing.T) {
	spc := New()
	spc.SetEnabled(true)

	cve := kernel.SPCCVEScore{
		CVEID:         "CVE-2024-TEST",
		CVSS:          9.8,
		EPSS:          0.72,
		InKEV:         true,
		DatePublished: time.Now().AddDate(0, 0, -14),
		AffectedCPEs:  []string{"cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"},
	}
	spc.AddCVE(cve)

	asset := kernel.LocalAsset{
		HostID:        "test-host",
		NetworkZone:   "internal",
		InstalledCPEs: []string{"cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"},
	}

	matchType, matched := spc.matchCPE(&cve, &asset, nil)
	if !matched {
		t.Fatal("expected exact CPE match")
	}
	if matchType != kernel.MatchExactVersion {
		t.Fatalf("expected MatchExactVersion, got %d", matchType)
	}
}

func TestSPCWeightShift(t *testing.T) {
	spc := New()
	spc.SetEnabled(true)

	cves := []kernel.SPCCVEScore{
		{
			CVEID: "CVE-A", CVSS: 9.0, EPSS: 0.5,
			AffectedCPEs: []string{"cpe:2.3:a:test:test:*:*:*:*:*:*:*:*"},
			Matched:      true, Exposure: kernel.ExposurePublic,
		},
		{
			CVEID: "CVE-B", CVSS: 8.0, EPSS: 0.3,
			AffectedCPEs: []string{"cpe:2.3:a:test:test:*:*:*:*:*:*:*:*"},
			Matched:      true, Exposure: kernel.ExposurePublic,
		},
		{
			CVEID: "CVE-C", CVSS: 7.0, EPSS: 0.2,
			AffectedCPEs: []string{"cpe:2.3:a:test:test:*:*:*:*:*:*:*:*"},
			Matched:      true, Exposure: kernel.ExposureDMZ,
		},
	}

	shift := spc.generateWeightShift([]string{"CVE-A", "CVE-B", "CVE-C"}, cves)

	if shift[model.DomainAttackSurface] != 5 {
		t.Errorf("expected attack_surface shift +5, got %.0f", shift[model.DomainAttackSurface])
	}
	if shift[model.DomainBusinessContinuity] != -3 {
		t.Errorf("expected business_continuity shift -3, got %.0f", shift[model.DomainBusinessContinuity])
	}
	if shift[model.DomainResilience] != -2 {
		t.Errorf("expected resilience shift -2, got %.0f", shift[model.DomainResilience])
	}

	var sum float64
	for _, v := range shift {
		sum += v
	}
	if sum != 0 {
		t.Errorf("weight shift sum should be 0, got %.0f", sum)
	}
}

func TestSPC_GetKEVCatalog(t *testing.T) {
	spc := New()
	spc.mu.Lock()
	spc.kevCatalog["CVE-2024-0001"] = true
	spc.kevCatalog["CVE-2024-0002"] = true
	spc.kevCatalog["CVE-2024-0003"] = true
	spc.mu.Unlock()

	catalog := spc.GetKEVCatalog()
	if len(catalog) != 3 {
		t.Errorf("expected 3 KEV entries, got %d", len(catalog))
	}

	found := make(map[string]bool)
	for _, cveID := range catalog {
		found[cveID] = true
	}
	for _, want := range []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"} {
		if !found[want] {
			t.Errorf("expected %s in KEV catalog", want)
		}
	}
}

func TestSPC_Summary(t *testing.T) {
	spc := New()
	spc.SetEnabled(true)
	spc.mu.Lock()
	spc.lastUpdate = time.Now()
	spc.minPScore = 0.65
	spc.kevCatalog["CVE-2024-0001"] = true
	spc.mu.Unlock()

	summary := spc.Summary()

	if v, ok := summary["enabled"].(bool); !ok || !v {
		t.Error("expected enabled=true in summary")
	}
	if v, ok := summary["kev_count"].(int); !ok || v != 1 {
		t.Errorf("kev_count = %v, want 1", summary["kev_count"])
	}
	if v, ok := summary["min_pscore"].(float64); !ok || v != 0.65 {
		t.Errorf("min_pscore = %v, want 0.65", summary["min_pscore"])
	}
}

func TestSPCInterface_Completeness(t *testing.T) {
	spc := New()
	var iface kernel.SPCInterface = spc
	_ = iface
}
