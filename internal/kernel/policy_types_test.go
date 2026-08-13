package kernel

import "testing"

func TestHostStatusString(t *testing.T) {
	tests := []struct {
		status HostStatus
		want   string
	}{
		{HostOK, "OK"},
		{HostWarning, "Warning"},
		{HostCritical, "Critical"},
		{HostIsolated, "Isolated"},
		{HostStatus(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Errorf("HostStatus(%d).String() = %q, want %q", tt.status, got, tt.want)
		}
	}
}
