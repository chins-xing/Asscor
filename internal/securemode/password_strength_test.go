package securemode

import (
	"strings"
	"testing"
)

// TestValidatePasswordStrength covers audit RC-H1: operator-chosen run-mode
// secrets must be at least minPasswordLen characters and span at least
// minPasswordClasses character classes so a weak "1" or "password" cannot be
// used to protect configuration encryption.
func TestValidatePasswordStrength(t *testing.T) {
	cases := []struct {
		name     string
		pw       string
		wantWeak bool
	}{
		{"empty is weak", "", true},
		{"single char is weak", "1", true},
		{"short digit-only is weak", "12345678", true},
		{"long but one class is weak", "aaaaaaaaaaaa", true},
		{"11 chars refused", "abc12345XYZ", true}, // 11 < 12
		{"two classes refused", "abcdefgh123456", true},
		{"lower+upper+digit ok", "abcXYZ012345", false},
		{"with symbol ok", "Kernel-Run-Pw-2026!", false},
		{"12 char three-class boundary ok", "aB3cD5eF7gH1j", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tc.pw)
			if tc.wantWeak && err == nil {
				t.Errorf("password %q must be refused", tc.pw)
			}
			if !tc.wantWeak && err != nil {
				t.Errorf("password %q must be accepted, got: %v", tc.pw, err)
			}
		})
	}
}

// TestValidatePasswordStrengthMessage useful for operators: the refusal must
// explain why.
func TestValidatePasswordStrengthMessage(t *testing.T) {
	err := ValidatePasswordStrength("1")
	if err == nil {
		t.Fatal("weak password accepted")
	}
	msg := err.Error()
	if !strings.Contains(msg, "at least") && !strings.Contains(msg, "too") {
		t.Errorf("error should explain the requirement, got %q", msg)
	}
}
