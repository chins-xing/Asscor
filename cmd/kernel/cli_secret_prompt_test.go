package main

import (
	"reflect"
	"testing"
)

// TestNeedsSecretPrompt (deferred minor #9): mode enter/exit/unlock/
// set-password prompt when their secret options are absent or empty;
// config-set prompts only when --password was given but left empty (the
// client cannot know whether the kernel is in run mode, and default-mode
// config-set needs no password); any other command never prompts.
func TestNeedsSecretPrompt(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		{"mode unlock", []string{"password"}},
		{"mode unlock --password", []string{"password"}},
		{"mode unlock --password=", []string{"password"}},
		{"mode unlock --password secret", nil},
		{"mode unlock --password=secret", nil},
		{"mode enter", []string{"password"}},
		{"mode exit", []string{"password"}},
		{"mode exit --password old", nil},
		{"mode set-password", []string{"old", "new"}},
		{"mode set-password --old=a", []string{"new"}},
		{"mode set-password --old a --new b", nil},
		{"mode set-password --new=b", []string{"old"}},
		{"mode status", nil},
		{"mode agent web01 exit", nil},
		{"mode", nil},
		{"config-set addr 80", nil},
		{"config-set addr 80 --password", []string{"password"}},
		{"config-set addr 80 --password=", []string{"password"}},
		{"config-set addr 80 --password secret", nil},
		{"status --password=secret", nil},
		{"", nil},
	}
	for _, tc := range cases {
		if got := needsSecretPrompt(tc.cmd); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("needsSecretPrompt(%q) = %v, want %v", tc.cmd, got, tc.want)
		}
	}
}

// TestSpliceSecret: the prompted value is spliced back into the command line
// as --flag=<value> without disturbing the rest of the line (quoting, spacing
// of unrelated arguments preserved byte-for-byte).
func TestSpliceSecret(t *testing.T) {
	cases := []struct {
		cmd, flag, value, want string
	}{
		{"mode unlock", "password", "pw123", "mode unlock --password=pw123"},
		{"mode unlock --password", "password", "pw123", "mode unlock --password=pw123"},
		{"mode unlock --password=", "password", "pw123", "mode unlock --password=pw123"},
		{"mode unlock --password --verbose", "password", "pw123", "mode unlock --password=pw123 --verbose"},
		{"mode unlock --verbose --password", "password", "pw123", "mode unlock --verbose --password=pw123"},
		{"mode set-password --old", "old", "oldpw", "mode set-password --old=oldpw"},
		{"mode set-password --old= --new", "old", "oldpw", "mode set-password --old=oldpw --new"},
		{"config-set addr 80", "password", "pw123", "config-set addr 80 --password=pw123"},
	}
	for _, tc := range cases {
		if got := spliceSecret(tc.cmd, tc.flag, tc.value); got != tc.want {
			t.Errorf("spliceSecret(%q, %q, %q) = %q, want %q", tc.cmd, tc.flag, tc.value, got, tc.want)
		}
	}
}
