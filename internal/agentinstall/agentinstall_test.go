//go:build linux

package agentinstall

import (
	"strings"
	"testing"
)

// TestAgentUnitContent (RC-L5: agentinstall had zero coverage): the main
// agent unit must run as the non-root asscor account, point at the real
// binary/config/log paths, and keep the privileged socket wired.
func TestAgentUnitContent(t *testing.T) {
	u := agentUnitContent("/opt/asscor/agent", "/etc/asscor/agent.ini", "/var/log/asscor")
	for _, want := range []string{
		"User=asscor",
		"Group=asscor",
		"WorkingDirectory=/opt/asscor",
		"ExecStart=/opt/asscor/agent/ASSCOR-agent --config=/etc/asscor/agent.ini",
		"--priv-socket=/run/asscor/agent-priv.sock",
		"--log-output=/var/log/asscor/agent.log",
		"Restart=always",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("agent unit missing %q:\n%s", want, u)
		}
	}
}

// TestAgentPrivSocketUnitContent: the privileged socket must be root-owned,
// asscor-group readable with mode 0660 (C-2 audit: not world-accessible).
func TestAgentPrivSocketUnitContent(t *testing.T) {
	u := agentPrivSocketUnitContent()
	for _, want := range []string{
		"ListenStream=/run/asscor/agent-priv.sock",
		"SocketUser=root",
		"SocketGroup=asscor",
		"SocketMode=0660",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("priv socket unit missing %q:\n%s", want, u)
		}
	}
}

// TestAgentPrivUnitContent: the privileged worker runs as root, is
// Restart=no, and has NO [Install] section — so it can never self-start or
// be enabled on boot (only socket activation starts it).
func TestAgentPrivUnitContent(t *testing.T) {
	u := agentPrivUnitContent("/opt/asscor/agent")
	for _, want := range []string{
		"Requires=asscor-agent-priv.socket",
		"User=root",
		"ExecStart=/opt/asscor/agent/ASSCOR-agent --privileged",
		"Restart=no",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("priv unit missing %q:\n%s", want, u)
		}
	}
	if strings.Contains(u, "[Install]") {
		t.Error("priv unit must NOT have an [Install] section (cannot be enabled/self-start)")
	}
}
