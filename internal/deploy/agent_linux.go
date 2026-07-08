//go:build linux

package deploy

import (
	"fmt"
	"os"
	"os/exec"
)

const (
	agentServiceName = "asscor-agent"
	agentServiceFile = "/etc/systemd/system/asscor-agent.service"
	agentBinDir      = "/opt/asscor/agent"
	agentConfigPath  = "/etc/asscor/agent.ini"
)

func InstallAgent() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("install requires root privileges")
	}
	logsDir := "/var/log/asscor"
	os.MkdirAll(agentBinDir, 0755)
	os.MkdirAll("/etc/asscor", 0755)
	os.MkdirAll(logsDir, 0755)

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return fmt.Errorf("read self: %w", err)
	}
	os.WriteFile(agentBinDir+"/ASSCOR-agent", data, 0755)

	if _, err := os.Stat(agentConfigPath); os.IsNotExist(err) {
		os.WriteFile(agentConfigPath, []byte("[agent]\nheartbeat_sec = 30\ncheck_interval_sec = 300\nlog_format = text\n"), 0644)
	}

	exec.Command("chown", "-R", "asscor:asscor", agentBinDir, "/etc/asscor").Run()

	svcContent := fmt.Sprintf(`[Unit]
Description=ASSCOR Agent
After=network-online.target

[Service]
Type=simple
User=root
ExecStart=%s/ASSCOR-agent --config=%s --kernel=127.0.0.1:50051 --log-output=%s/agent.log
Restart=always
RestartSec=15
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, agentBinDir, agentConfigPath, logsDir)

	os.WriteFile(agentServiceFile, []byte(svcContent), 0644)
	exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

func UninstallAgent() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall requires root privileges")
	}
	exec.Command("systemctl", "stop", agentServiceName).Run()
	exec.Command("systemctl", "disable", agentServiceName).Run()
	os.Remove(agentServiceFile)
	exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

func UpgradeAgent() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("upgrade requires root privileges")
	}
	binPath := agentBinDir + "/ASSCOR-agent"
	backupPath := binPath + ".bak"
	exec.Command("systemctl", "stop", agentServiceName).Run()
	os.Rename(binPath, backupPath)
	exe, _ := os.Executable()
	data, _ := os.ReadFile(exe)
	os.WriteFile(binPath, data, 0755)
	exec.Command("systemctl", "start", agentServiceName).Run()
	return nil
}
