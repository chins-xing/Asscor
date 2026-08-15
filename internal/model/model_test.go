package model

import "testing"

func TestIsPermissionDeniedDetail(t *testing.T) {
	tests := []struct {
		detail string
		want   bool
	}{
		{"open /etc/shadow: permission denied", true},
		{"无法读取/etc/shadow: permission denied", true},
		{"open /etc/audit/rules.d: permission denied", true},
		{"operation not permitted", true},
		{"access denied", true},
		{"eacces", true},
		{"eperm", true},
		{"无法验证rclone远程备份配置：需要 root 权限", true},
		{"部分备份配置无法检查（需要 root 权限）: /root/.config/rclone", true},
		{"文件权限不足", true},
		{"权限不足，无法读取", true},
		{"拒绝访问", true},
		{"SSH protocol 1 enabled", false},
		{"未发现远程备份配置", false},
		{"服务未运行", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsPermissionDeniedDetail(tt.detail); got != tt.want {
			t.Errorf("IsPermissionDeniedDetail(%q) = %v, want %v", tt.detail, got, tt.want)
		}
	}
}

func TestSkipResult_Neutral(t *testing.T) {
	c := CheckItem{
		ID:            "AS-012",
		Domain:        DomainAttackSurface,
		Name:          "幽灵账户检测",
		Delta:         -6,
		ComplianceRef: "L3-CE-09",
	}
	r := c.skipResult("skipped — requires root privileges")

	if !r.Passed {
		t.Error("skipped result should be Passed=true (not a failure)")
	}
	if r.Delta != 0 {
		t.Errorf("skipped result should have Delta=0, got %.1f", r.Delta)
	}
	if r.CheckID != "AS-012" || r.Domain != DomainAttackSurface || r.Name != "幽灵账户检测" {
		t.Error("skipResult should propagate identity fields")
	}
	if r.ComplianceRef != "L3-CE-09" {
		t.Error("skipResult should propagate ComplianceRef")
	}
}

// TestCheckItemRunPropagatesSource verifies the Source marker flows from
// CheckItem into CheckResult through both the normal and skip result paths.
func TestCheckItemRunPropagatesSource(t *testing.T) {
	// User-defined check: normal execution.
	userItem := CheckItem{
		ID:     "CU-001",
		Domain: DomainOperationTrust,
		Name:   "user check",
		Check:  func() (bool, string) { return true, "ok" },
		Source: CheckSourceUser,
	}
	if r := userItem.Run(); r.Source != CheckSourceUser {
		t.Errorf("Run() Source = %q, want %q", r.Source, CheckSourceUser)
	}

	// Builtin check: zero value must stay empty (builtin semantics).
	builtinItem := CheckItem{
		ID:    "AS-001",
		Check: func() (bool, string) { return true, "ok" },
	}
	if r := builtinItem.Run(); r.Source != "" {
		t.Errorf("builtin Run() Source = %q, want empty", r.Source)
	}

	// Skip path must also propagate Source.
	rootItem := CheckItem{
		ID:        "CU-ROOT",
		Check:     func() (bool, string) { return false, "permission denied" },
		Source:    CheckSourceUser,
		Privilege: PrivRoot,
	}
	if r := rootItem.skipResult("skipped"); r.Source != CheckSourceUser {
		t.Errorf("skipResult Source = %q, want %q", r.Source, CheckSourceUser)
	}
}
