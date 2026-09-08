package agent

import "testing"

// TestTLSServerNameResolution covers audit H-4: the TLS ServerName must be
// configurable explicitly and otherwise derived from KernelAddr's host —
// never a hard-coded "localhost" that breaks remote verification.
func TestTLSServerNameResolution(t *testing.T) {
	cases := []struct {
		name     string
		cfg      AgentConfig
		expected string
	}{
		{"explicit override wins", AgentConfig{KernelAddr: "127.0.0.1:50051", TLSServerName: "kernel.internal"}, "kernel.internal"},
		{"host derived from kernel addr", AgentConfig{KernelAddr: "kernel.internal:50051"}, "kernel.internal"},
		{"ip from kernel addr", AgentConfig{KernelAddr: "10.0.0.7:50051"}, "10.0.0.7"},
		{"default localhost fallback", AgentConfig{KernelAddr: "localhost:50051"}, "localhost"},
		{"missing port falls back", AgentConfig{KernelAddr: "somehost"}, "localhost"},
		{"empty kernel addr falls back", AgentConfig{}, "localhost"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Agent{cfg: tc.cfg}
			if got := a.tlsServerName(); got != tc.expected {
				t.Errorf("tlsServerName() = %q, want %q", got, tc.expected)
			}
		})
	}
}
