//go:build expr

package main

import "testing"

// TestShellSafe (audit RC-M5): values interpolated into docker-exec bash -c
// templates must reject shell metacharacters so an externalized IP/port/path
// can never inject a mutated command into a container.
func TestShellSafe(t *testing.T) {
	allowed := []string{
		"10.10.13.10",
		"asc-asscor-host1",
		"/tmp/decoyd-1.log",
		"22221",
		"10.0.0.1",
	}
	for _, v := range allowed {
		if err := shellSafe(v); err != nil {
			t.Errorf("shellSafe(%q) = %v, want nil", v, err)
		}
	}

	rejected := []string{
		"10.10.13.10; rm -rf /",
		"host$(id)",
		"x`id`y",
		"/tmp/a & id",
		"22221|cat /etc/passwd",
		"a b c", // space breaks single-token values
		"",
	}
	for _, v := range rejected {
		if err := shellSafe(v); err == nil {
			t.Errorf("shellSafe(%q) must reject shell metacharacters", v)
		}
	}
}
