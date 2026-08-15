//go:build checks

package linux

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

// ---------------------------------------------------------------------------
// isPermDenied
// ---------------------------------------------------------------------------

func TestIsPermDenied(t *testing.T) {
	if !isPermDenied(fs.ErrPermission) {
		t.Error("fs.ErrPermission should be detected as permission denied")
	}
	if !isPermDenied(syscall.EACCES) {
		t.Error("syscall.EACCES should be detected as permission denied")
	}
	if !isPermDenied(syscall.EPERM) {
		t.Error("syscall.EPERM should be detected as permission denied")
	}
	if isPermDenied(nil) {
		t.Error("nil should not be permission denied")
	}
	if isPermDenied(errors.New("some other error")) {
		t.Error("unrelated error should not be permission denied")
	}
	if isPermDenied(os.ErrNotExist) {
		t.Error("ErrNotExist should not be permission denied")
	}
}

// ---------------------------------------------------------------------------
// readFileAllowPerm / statAllowPerm / readDirAllowPerm
// ---------------------------------------------------------------------------

func TestReadFileAllowPerm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	data, permDenied, err := readFileAllowPerm(path)
	if err != nil {
		t.Fatalf("readFileAllowPerm: %v", err)
	}
	if permDenied {
		t.Error("permDenied should be false for readable file")
	}
	if string(data) != "hello" {
		t.Errorf("data = %q, want hello", data)
	}
}

func TestReadFileAllowPermMissing(t *testing.T) {
	_, permDenied, err := readFileAllowPerm(filepath.Join(t.TempDir(), "nope.txt"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if permDenied {
		t.Error("missing file is not a permission denial")
	}
}

func TestStatAllowPerm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stat.txt")
	if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	info, permDenied, err := statAllowPerm(path)
	if err != nil {
		t.Fatalf("statAllowPerm: %v", err)
	}
	if permDenied {
		t.Error("permDenied should be false")
	}
	if !info.Mode().IsRegular() {
		t.Error("expected regular file")
	}
}

func TestReadDirAllowPerm(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("1"), 0644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b"), []byte("2"), 0644); err != nil {
		t.Fatalf("write b: %v", err)
	}

	entries, permDenied, err := readDirAllowPerm(dir)
	if err != nil {
		t.Fatalf("readDirAllowPerm: %v", err)
	}
	if permDenied {
		t.Error("permDenied should be false")
	}
	if len(entries) != 2 {
		t.Errorf("got %d entries, want 2", len(entries))
	}
}

// ---------------------------------------------------------------------------
// sortSlice / joinKeys / contains / unique
// ---------------------------------------------------------------------------

func TestSortSlice(t *testing.T) {
	s := []int{5, 1, 3, 2, 4}
	sortSlice(s)
	want := []int{1, 2, 3, 4, 5}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("sortSlice = %v, want %v", s, want)
	}
}

func TestJoinKeys(t *testing.T) {
	m := map[string]bool{"b": true, "a": true, "c": false}
	got := joinKeys(m)
	if got != "a, b, c" {
		t.Errorf("joinKeys = %q, want %q", got, "a, b, c")
	}
}

func TestContains(t *testing.T) {
	slice := []string{"sshd", "nginx", "httpd"}
	if !contains(slice, "nginx") {
		t.Error("contains should find nginx")
	}
	if contains(slice, "mysql") {
		t.Error("contains should not find mysql")
	}
	if contains(nil, "x") {
		t.Error("contains(nil) should be false")
	}
}

func TestUnique(t *testing.T) {
	in := []string{"a", "b", "a", "c", "b", "a"}
	got := unique(in)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unique = %v, want %v (order-preserving)", got, want)
	}
	if len(unique(nil)) != 0 {
		t.Error("unique(nil) should be empty")
	}
}

// ---------------------------------------------------------------------------
// matchSSHConfig
// ---------------------------------------------------------------------------

func TestMatchSSHConfig(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		key      string
		expected string
		want     bool
	}{
		{"simple match", "Port 22\n", "Port", "22", true},
		{"value mismatch", "Port 2222\n", "Port", "22", false},
		{"comment ignored", "#Port 22\n", "Port", "22", false},
		{"case insensitive key", "port 22\n", "Port", "22", true},
		{"case insensitive value", "PermitRootLogin YES\n", "PermitRootLogin", "yes", true},
		{"second line match", "Protocol 2\nPort 22\n", "Port", "22", true},
		{"key not present", "PermitRootLogin no\n", "Port", "22", false},
		{"empty content", "", "Port", "22", false},
		{"empty expected", "Port 22\n", "Port", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchSSHConfig(tt.content, tt.key, tt.expected); got != tt.want {
				t.Errorf("matchSSHConfig(%q, %q, %q) = %v, want %v",
					tt.content, tt.key, tt.expected, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseCrypttab
// ---------------------------------------------------------------------------

func TestParseCrypttab(t *testing.T) {
	content := `# encrypted volumes
cryptswap UUID=6a0d UUID=x /swapfile swap
cryptroot UUID=abc /dev/mapper/root ext4

# comment only line
`
	got := parseCrypttab(content)
	want := []string{"cryptswap", "cryptroot"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseCrypttab = %v, want %v", got, want)
	}
}

func TestParseCrypttabEmpty(t *testing.T) {
	if got := parseCrypttab(""); len(got) != 0 {
		t.Errorf("empty input should yield no volumes, got %v", got)
	}
	if got := parseCrypttab("# all comments\n\n"); len(got) != 0 {
		t.Errorf("comment-only input should yield no volumes, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// parseFail2banJails
// ---------------------------------------------------------------------------

func TestParseFail2banJails(t *testing.T) {
	output := "Status: Number of jail: 2\n Jail list: sshd, nginx\n"
	got := parseFail2banJails(output)
	want := []string{"sshd", "nginx"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseFail2banJails = %v, want %v", got, want)
	}
}

func TestParseFail2banJailsFiltersEmpty(t *testing.T) {
	output := "Jail list: sshd, , nginx, \n"
	got := parseFail2banJails(output)
	want := []string{"sshd", "nginx"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseFail2banJails = %v, want %v (empty entries filtered)", got, want)
	}
}

func TestParseFail2banJailsNoMatch(t *testing.T) {
	if got := parseFail2banJails("Status: running\n"); len(got) != 0 {
		t.Errorf("no Jail list line should yield empty, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// checkKernelCVEs — missing cache file returns 0
// ---------------------------------------------------------------------------

func TestCheckKernelCVEsMissingCache(t *testing.T) {
	// cveDBPath is the hardcoded /var/lib/ASSCOR/cve_cache.json; in test
	// environments it does not exist, so the function must return 0 without
	// erroring. This guards the "no data" path of KS-001.
	if got := checkKernelCVEs("6.1.0"); got != 0 {
		t.Errorf("checkKernelCVEs with missing cache = %d, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// All() — check-item metadata consistency (covers every constructor)
// ---------------------------------------------------------------------------

var validDomains = map[string]bool{
	"attack_surface":      true,
	"business_continuity": true,
	"operation_trust":     true,
	"resilience":          true,
	"kernel_security":     true,
}

func TestAllCheckItemsMetadata(t *testing.T) {
	items := All()
	if len(items) < 70 {
		t.Errorf("All() returned %d checks, want >= 70", len(items))
	}

	seenIDs := make(map[string]bool, len(items))
	for _, item := range items {
		if item.ID == "" {
			t.Error("check with empty ID found")
		}
		if seenIDs[item.ID] {
			t.Errorf("duplicate check ID: %s", item.ID)
		}
		seenIDs[item.ID] = true

		if !validDomains[item.Domain] {
			t.Errorf("check %s has invalid domain %q", item.ID, item.Domain)
		}
		if item.Delta < -20 || item.Delta > 10 {
			t.Errorf("check %s has out-of-range delta %v", item.ID, item.Delta)
		}
		if item.Name == "" {
			t.Errorf("check %s has empty name", item.ID)
		}
		if item.Description == "" {
			t.Errorf("check %s has empty description", item.ID)
		}
		if item.ComplianceRef == "" {
			t.Errorf("check %s has empty ComplianceRef (等保映射缺失)", item.ID)
		}
		if item.Platform != "linux" {
			t.Errorf("check %s platform = %q, want linux", item.ID, item.Platform)
		}
		if item.Check == nil {
			t.Errorf("check %s has nil Check function", item.ID)
		}
	}
}

func TestAllIncludesKernelSecurity(t *testing.T) {
	items := All()
	hasKS := false
	hasEF := false
	for _, item := range items {
		if len(item.ID) >= 3 && item.ID[:3] == "KS-" {
			hasKS = true
		}
		if len(item.ID) >= 3 && item.ID[:3] == "EF-" {
			hasEF = true
		}
	}
	if !hasKS {
		t.Error("All() should include KS-* kernel security checks (ksAll)")
	}
	if !hasEF {
		t.Error("All() should include EF-* edge factor checks")
	}
}

func TestAllDomainCounts(t *testing.T) {
	counts := map[string]int{}
	for _, item := range All() {
		counts[item.Domain]++
	}
	for domain := range validDomains {
		if counts[domain] == 0 {
			t.Errorf("no checks in domain %q", domain)
		}
	}
}
