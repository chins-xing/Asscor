//go:build linux

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	agentServiceName = "asscor-agent"
	agentServiceFile = "/etc/systemd/system/asscor-agent.service"
	agentBinDir      = "/opt/asscor/agent"
	agentConfigPath  = "/etc/asscor/agent.ini"
)

func agentUnitContent(binDir, configPath, logsDir string) string {
	return fmt.Sprintf(`[Unit]
Description=ASSCOR Agent
After=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/asscor
ExecStart=%s/ASSCOR-agent --config=%s --kernel=127.0.0.1:50051 --log-output=%s/agent.log
Restart=always
RestartSec=15
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, binDir, configPath, logsDir)
}

func writeAgentUnit() {
	logsDir := "/var/log/asscor"
	os.WriteFile(agentServiceFile, []byte(agentUnitContent(agentBinDir, agentConfigPath, logsDir)), 0644)
}

func InstallAgent() error {
	if err := requireRoot(); err != nil {
		return err
	}
	logsDir := "/var/log/asscor"
	os.MkdirAll(agentBinDir, 0755)
	os.MkdirAll("/etc/asscor", 0755)
	os.MkdirAll(logsDir, 0755)

	if err := copySelfTo(agentBinDir + "/ASSCOR-agent"); err != nil {
		return err
	}

	if _, err := os.Stat(agentConfigPath); os.IsNotExist(err) {
		os.WriteFile(agentConfigPath, []byte("[agent]\nheartbeat_sec = 30\ncheck_interval_sec = 300\nlog_format = text\n"), 0644)
	}

	chownAsscor(agentBinDir, "/etc/asscor")

	writeAgentUnit()
	systemctlReload()
	return nil
}

func UninstallAgent() error {
	if err := requireRoot(); err != nil {
		return err
	}
	systemctlStopDisable(agentServiceName)
	os.Remove(agentServiceFile)
	systemctlReload()
	return nil
}

func UpgradeAgent() error {
	if err := requireRoot(); err != nil {
		return err
	}
	binPath := agentBinDir + "/ASSCOR-agent"
	backupPath := binPath + ".bak"

	exec.Command("systemctl", "stop", agentServiceName).Run()
	os.Remove(backupPath)
	os.Rename(binPath, backupPath)

	if err := copySelfTo(binPath); err != nil {
		os.Rename(backupPath, binPath)
		return fmt.Errorf("upgrade failed, rolled back: %w", err)
	}

	writeAgentUnit()
	systemctlReload()

	exec.Command("systemctl", "start", agentServiceName).Run()
	if err := waitForServiceHealthy(agentServiceName, 10*time.Second); err != nil {
		return fmt.Errorf("upgrade applied but service failed to start: %w", err)
	}
	return nil
}
