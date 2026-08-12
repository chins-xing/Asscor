package spc


import "testing"

func TestIsCVEID(t *testing.T) {
	if !isCVEID("CVE-2024-0001") {
		t.Error("expected valid CVE ID")
	}
	if !isCVEID("CVE-1999-0001") {
		t.Error("expected valid CVE ID")
	}
	if isCVEID("not-a-cve") {
		t.Error("expected invalid for non-CVE")
	}
	if isCVEID("") {
		t.Error("expected invalid for empty")
	}
	if isCVEID("cve-2024-0001") {
		t.Error("expected invalid for lowercase")
	}
}
