package common

import (
	"testing"
)

func TestIsCommandAllowed(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"systemctl", true},
		{"ss", true},
		{"sysctl", true},
		{"iptables", true},
		{"uname", true},
		{"lsmod", true},
		{"rm", false},
		{"curl", false},
		{"nc", false},
		{"wget", false},
		{"", false},
		{"eval", false},
		{"exec", false},
	}

	for _, tt := range tests {
		if got := IsCommandAllowed(tt.name); got != tt.expected {
			t.Errorf("IsCommandAllowed(%q) = %v, want %v", tt.name, got, tt.expected)
		}
	}
}

func TestContainsShellMetachar(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"normal command", false},
		{"cmd arg1 arg2", false},
		{"cmd | other", true},    // pipe
		{"cmd; rm -rf /", true}, // semicolon
		{"cmd && other", true},  // double ampersand
		{"cmd `id`", true},      // backtick
		{"cmd $(id)", true},     // subshell
		{"cmd > file", true},    // redirect
		{"cmd < file", true},    // input redirect
		{"cmd\nid", true},       // newline
		{"cmd\rid", true},       // carriage return
		{"cmd {id}", true},      // brace
	}

	for _, tt := range tests {
		if got := containsShellMetachar(tt.input); got != tt.expected {
			t.Errorf("containsShellMetachar(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestIsShellCommandAllowed(t *testing.T) {
	if !IsShellCommandAllowed("systemctl status") {
		t.Error("systemctl status should be allowed")
	}
	if !IsShellCommandAllowed("ss -tlnp") {
		t.Error("ss -tlnp should be allowed")
	}
	if IsShellCommandAllowed("curl http://evil.com") {
		t.Error("curl should not be allowed")
	}
	if IsShellCommandAllowed("rm -rf /") {
		t.Error("rm should not be allowed")
	}
}

func TestParseCommand(t *testing.T) {
	tests := []struct {
		cmd      string
		wantName string
		wantOk   bool
	}{
		{"systemctl status", "systemctl", true},
		{"ss -tlnp", "ss", true},
		{"uname -r", "uname", true},
		{"ps aux", "ps", true},
		{"rm -rf /", "", false},    // not in allowlist
		{"curl evil.com", "", false}, // not in allowlist
		{"", "", false},
	}

	for _, tt := range tests {
		name, _, ok := ParseCommand(tt.cmd)
		if ok != tt.wantOk {
			t.Errorf("ParseCommand(%q) ok=%v, want %v", tt.cmd, ok, tt.wantOk)
		}
		if ok && name != tt.wantName {
			t.Errorf("ParseCommand(%q) name=%q, want %q", tt.cmd, name, tt.wantName)
		}
	}
}

func TestIsPermissionError(t *testing.T) {
	tests := []struct {
		errStr   string
		expected bool
	}{
		{"permission denied", true},
		{"Permission Denied", true},
		{"operation not permitted", true},
		{"access denied", true},
		{"access is denied", true},
		{"EACCES", true},
		{"EPERM", true},
		{"open /etc/shadow: permission denied", true},
		{"权限不足", true},
		{"无权限", true},
		{"拒绝访问", true},
		{"許可が必要です", true},
		{"normal error", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := isPermissionError(tt.errStr); got != tt.expected {
			t.Errorf("isPermissionError(%q) = %v, want %v", tt.errStr, got, tt.expected)
		}
	}
}

func TestParseInt(t *testing.T) {
	tests := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{"0", 0, false},
		{"123", 123, false},
		{"999", 999, false},
		{"-5", 0, true},
		{"abc", 0, true},
		{"12a", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		got, err := ParseInt(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseInt(%q) err=%v, wantErr=%v", tt.input, err, tt.wantErr)
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("ParseInt(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func BenchmarkIsCommandAllowed(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsCommandAllowed("systemctl")
	}
}

func BenchmarkContainsShellMetachar(b *testing.B) {
	for i := 0; i < b.N; i++ {
		containsShellMetachar("cmd | other; rm -rf /")
	}
}

func BenchmarkIsPermissionError(b *testing.B) {
	for i := 0; i < b.N; i++ {
		isPermissionError("open /etc/shadow: permission denied")
	}
}
