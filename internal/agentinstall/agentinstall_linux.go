//go:build linux

// Package agentinstall provides single-binary agent installation as a Linux
// systemd service. It is deliberately a leaf package with NO dependency on
// internal/kernel or internal/cli, so the agent binary (cmd/agent) can use it
// without dragging the whole kernel contract surface into a thin managed host
// (coupling audit 2026-09-03, finding C1).
package agentinstall

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	agentServiceName     = "asscor-agent"
	agentServiceFile     = "/etc/systemd/system/asscor-agent.service"
	agentPrivServiceName = "asscor-agent-priv"
	agentPrivServiceFile = "/etc/systemd/system/asscor-agent-priv.service"
	agentPrivSocketName  = "asscor-agent-priv"
	agentPrivSocketFile  = "/etc/systemd/system/asscor-agent-priv.socket"
	agentBinDir          = "/opt/asscor/agent"
	agentConfigPath      = "/etc/asscor/agent.ini"
	agentPrivSocketPath  = "/run/asscor/agent-priv.sock"
)

// agentUnitContent returns the main agent systemd unit. The main agent runs
// under the non-root "asscor" account and delegates all root-required business
// to the privileged agent process.
func agentUnitContent(binDir, configPath, logsDir string) string {
	return fmt.Sprintf(`[Unit]
Description=ASSCOR Agent
After=network-online.target

[Service]
Type=simple
User=asscor
Group=asscor
WorkingDirectory=/opt/asscor
ExecStart=%s/ASSCOR-agent --config=%s --kernel=127.0.0.1:50051 --priv-socket=%s --log-output=%s/agent.log
Restart=always
RestartSec=15
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, binDir, configPath, agentPrivSocketPath, logsDir)
}

// agentPrivSocketUnitContent returns the systemd socket unit for the
// privileged agent. The socket is what activates the privileged process: the
// main agent connects here (never execs the binary), and systemd then starts
// asscor-agent-priv on demand.
func agentPrivSocketUnitContent() string {
	return fmt.Sprintf(`[Unit]
Description=ASSCOR Privileged Agent Socket

[Socket]
ListenStream=%s
SocketUser=root
SocketGroup=asscor
SocketMode=0660

[Install]
WantedBy=sockets.target
`, agentPrivSocketPath)
}

// agentPrivUnitContent returns the privileged agent systemd unit. It runs under
// a dedicated privileged account (root), is Restart=no, and has NO [Install]
// section — so it cannot be enabled or self-start on boot. It is started ONLY
// by systemd socket activation when the (kernel-authorized) main agent
// connects to the socket.
func agentPrivUnitContent(binDir string) string {
	return fmt.Sprintf(`[Unit]
Description=ASSCOR Privileged Agent (root-required business only)
Requires=asscor-agent-priv.socket
After=asscor-agent-priv.socket

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/asscor
ExecStart=%s/ASSCOR-agent --privileged --priv-socket=%s --priv-peer-user=asscor --log-output=/var/log/asscor/agent-priv.log
Restart=no
LimitNOFILE=65536
`, binDir, agentPrivSocketPath)
}

func writeAgentUnit() {
	logsDir := "/var/log/asscor"
	os.WriteFile(agentServiceFile, []byte(agentUnitContent(agentBinDir, agentConfigPath, logsDir)), 0644)
}

func writeAgentPrivUnits() {
	os.WriteFile(agentPrivSocketFile, []byte(agentPrivSocketUnitContent()), 0644)
	os.WriteFile(agentPrivServiceFile, []byte(agentPrivUnitContent(agentBinDir)), 0644)
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this operation requires root privileges")
	}
	return nil
}

func copySelfTo(targetPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return fmt.Errorf("read self: %w", err)
	}
	if err := os.WriteFile(targetPath, data, 0755); err != nil {
		return fmt.Errorf("write binary to %s: %w", targetPath, err)
	}
	return nil
}

func systemctlReload() {
	exec.Command("systemctl", "daemon-reload").Run()
}

func systemctlStopDisable(serviceName string) {
	exec.Command("systemctl", "stop", serviceName).Run()
	exec.Command("systemctl", "disable", serviceName).Run()
}

func chownAsscor(paths ...string) {
	for _, p := range paths {
		exec.Command("chown", "-R", "asscor:asscor", p).Run()
	}
}

func waitForServiceHealthy(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("systemctl", "is-active", name).Output()
		status := string(out)
		if status == "active\n" {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service %s did not become active within %v", name, timeout)
}

// Install installs the agent as systemd services (main + socket-activated
// privileged worker). Requires root.
func Install() error {
	if err := requireRoot(); err != nil {
		return err
	}
	logsDir := "/var/log/asscor"
	os.MkdirAll(agentBinDir, 0755)
	os.MkdirAll("/etc/asscor", 0755)
	os.MkdirAll(logsDir, 0755)
	os.MkdirAll("/run/asscor", 0755)

	if err := copySelfTo(agentBinDir + "/ASSCOR-agent"); err != nil {
		return err
	}

	if _, err := os.Stat(agentConfigPath); os.IsNotExist(err) {
		os.WriteFile(agentConfigPath, []byte("[agent]\nheartbeat_sec = 30\ncheck_interval_sec = 300\nlog_format = text\n"), 0640)
	}

	// Security: the agent config is the primary source of agent behavior
	// (HMAC key, user checks, delta overrides). The main agent runs as the
	// `asscor` user, so the file must be root-owned and group-readable only:
	//   - agent.ini: 0640 root:asscor — root can modify, asscor group can
	//     read (the agent needs to read it), nobody else can read or write.
	//   - /etc/asscor: 0750 root:asscor — the agent can read but never write
	//     its own configuration directory, preventing a compromised agent
	//     from tampering with its config (e.g. injecting user_check commands
	//     or replacing the HMAC key).
	chownAsscor(agentBinDir) // binary + logs stay asscor-owned
	exec.Command("chown", "-R", "root:asscor", "/etc/asscor").Run()
	exec.Command("chmod", "0750", "/etc/asscor").Run()
	exec.Command("chmod", "0640", agentConfigPath).Run()
	// /run/asscor must be owned by root with group access for the agent so the
	// privileged socket (SocketUser=root SocketGroup=asscor) is connectable.
	exec.Command("chown", "root:asscor", "/run/asscor").Run()
	exec.Command("chmod", "0755", "/run/asscor").Run()

	writeAgentUnit()
	writeAgentPrivUnits()
	systemctlReload()
	return nil
}

// Uninstall stops and removes the agent systemd units. Requires root.
func Uninstall() error {
	if err := requireRoot(); err != nil {
		return err
	}
	systemctlStopDisable(agentServiceName)
	systemctlStopDisable(agentPrivServiceName)
	systemctlStopDisable(agentPrivSocketName)
	os.Remove(agentServiceFile)
	os.Remove(agentPrivServiceFile)
	os.Remove(agentPrivSocketFile)
	systemctlReload()
	return nil
}

// Upgrade replaces the installed agent binary in place and restarts the
// service, rolling back on failure. Requires root.
func Upgrade() error {
	if err := requireRoot(); err != nil {
		return err
	}
	binPath := agentBinDir + "/ASSCOR-agent"
	backupPath := binPath + ".bak"

	exec.Command("systemctl", "stop", agentServiceName).Run()
	exec.Command("systemctl", "stop", agentPrivServiceName).Run()
	os.Remove(backupPath)
	os.Rename(binPath, backupPath)

	if err := copySelfTo(binPath); err != nil {
		os.Rename(backupPath, binPath)
		return fmt.Errorf("upgrade failed, rolled back: %w", err)
	}

	writeAgentUnit()
	writeAgentPrivUnits()
	systemctlReload()

	exec.Command("systemctl", "start", agentServiceName).Run()
	if err := waitForServiceHealthy(agentServiceName, 10*time.Second); err != nil {
		return fmt.Errorf("upgrade applied but service failed to start: %w", err)
	}
	return nil
}
