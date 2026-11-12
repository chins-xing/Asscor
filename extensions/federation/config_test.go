package federation

import (
	"strings"
	"testing"
)

func cfgGetter(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// Audit D-01: a master must never run without authentication on a
// network-reachable address. These tests pin the fail-closed rule.
func TestParseConfigMasterRequiresTokenOutsideLoopback(t *testing.T) {
	for _, listen := range []string{"", ":5099", "0.0.0.0:5099", "[::]:5099"} {
		t.Run(listen, func(t *testing.T) {
			_, err := ParseConfig(cfgGetter(map[string]string{
				"federation.role":        "master",
				"federation.listen_addr": listen,
			}))
			if err == nil {
				t.Fatalf("role=master listen=%q token empty must fail", listen)
			}
			if !strings.Contains(err.Error(), "token") {
				t.Errorf("error %q should mention token", err)
			}
		})
	}
}

func TestParseConfigMasterLoopbackWithoutTokenAllowed(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:5099", "[::1]:5099", "localhost:5099"} {
		t.Run(listen, func(t *testing.T) {
			cfg, err := ParseConfig(cfgGetter(map[string]string{
				"federation.role":        "master",
				"federation.listen_addr": listen,
			}))
			if err != nil {
				t.Fatalf("loopback listen %q should be allowed without token: %v", listen, err)
			}
			if cfg.Role != RoleMaster {
				t.Errorf("role = %q, want master", cfg.Role)
			}
		})
	}
}

func TestParseConfigMasterTokenOutsideLoopbackAllowed(t *testing.T) {
	cfg, err := ParseConfig(cfgGetter(map[string]string{
		"federation.role":        "master",
		"federation.listen_addr": ":5099",
		"federation.token":       "secret",
	}))
	if err != nil {
		t.Fatalf("token-protected master must parse: %v", err)
	}
	if cfg.Token != "secret" {
		t.Errorf("token = %q", cfg.Token)
	}
}

func TestIsLoopbackListen(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:5099":     true,
		"[::1]:5099":         true,
		"localhost:5099":     true,
		":5099":              false,
		"0.0.0.0:5099":       false,
		"[::]:5099":          false,
		"192.168.30.50:5099": false,
		"not-an-addr":        false,
	}
	for addr, want := range cases {
		if got := isLoopbackListen(addr); got != want {
			t.Errorf("isLoopbackListen(%q) = %v, want %v", addr, got, want)
		}
	}
}
