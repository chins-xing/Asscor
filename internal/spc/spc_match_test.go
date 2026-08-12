package spc

import (
	"testing"
)

func TestTruncateString(t *testing.T) {
	if got := truncateString("hello", 10); got != "hello" {
		t.Errorf("truncateString(hello, 10) = %s, want hello", got)
	}
	if got := truncateString("hello world", 5); got != "hello..." {
		t.Errorf("truncateString(hello world, 5) = %s, want hello...", got)
	}
	if got := truncateString("", 5); got != "" {
		t.Errorf("empty should be empty, got %s", got)
	}
}

func TestExtractPkgNames(t *testing.T) {
	names := extractPkgNames([]string{"openssl-1.1.1.x86_64", "nginx-1.20.1"})
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %d", len(names))
	}
	if names[0] != "openssl-1.1.1.x86_64" {
		t.Errorf("first = %s, want openssl-1.1.1.x86_64", names[0])
	}

	names = extractPkgNames([]string{"dup-1.0", "dup-1.0"})
	if len(names) != 1 {
		t.Fatalf("expected 1 unique name, got %d", len(names))
	}

	names = extractPkgNames(nil)
	if names != nil {
		t.Errorf("nil should return nil, got %v", names)
	}

	names = extractPkgNames([]string{})
	if names != nil {
		t.Errorf("empty should return nil, got %v", names)
	}
}

func TestInstalledCPEsCount(t *testing.T) {
	if count := installedCPEsCount(nil); count != 0 {
		t.Errorf("nil asset = %d, want 0", count)
	}

	asset := &LocalAsset{InstalledCPEs: []string{"cpe1", "cpe2", "cpe3"}}
	if count := installedCPEsCount(asset); count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}
