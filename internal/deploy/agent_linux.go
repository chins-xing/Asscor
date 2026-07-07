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
		return fmt.Errorf("install requires root privileges (use sudo)")
	}

	logsDir := "/var/log/asscor"

	dirs := []string{agentBinDir, "/etc/asscor", logsDir}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("create directory %s: %w", d, err)
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	if err := copyFile(exe, agentBinDir+"/ASSCOR-agent"); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}
	if err := os.Chmod(agentBinDir+"/ASSCOR-agent", 0755); err != nil {
		return fmt.Errorf("chmod binary: %w", err)
	}

	if _, err := os.Stat(agentConfigPath); os.IsNotExist(err) {
		copyFile("agent.ini", agentConfigPath)
	}

	exec.Command("chown", "-R", "asscor:asscor", agentBinDir, "/etc/asscor").Run()

	svcContent := fmt.Sprintf(`[Unit]
Description=ASSCOR Agent - Host Security Assessment Probe
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=%s/ASSCOR-agent --config=%s --kernel=127.0.0.1:50051 --log-format=text --log-level=info --log-output=%s/agent.log
Restart=always
RestartSec=15
KillMode=mixed
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, agentBinDir, agentConfigPath, logsDir)

	if err := os.WriteFile(agentServiceFile, []byte(svcContent), 0644); err != nil {
		return fmt.Errorf("write service file: %w", err)
	}

	exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

func UninstallAgent() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall requires root privileges (use sudo)")
	}
	_ = exec.Command("systemctl", "stop", agentServiceName).Run()
	_ = exec.Command("systemctl", "disable", agentServiceName).Run()
	os.Remove(agentServiceFile)
	exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

func UpgradeAgent() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("upgrade requires root privileges (use sudo)")
	}

	binPath := agentBinDir + "/ASSCOR-agent"
	backupPath := binPath + ".bak"

	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		return fmt.Errorf("no existing agent installation â€?use --install first")
	}

	_ = exec.Command("systemctl", "stop", agentServiceName).Run()

	if err := os.Rename(binPath, backupPath); err != nil {
		_ = exec.Command("systemctl", "start", agentServiceName).Run()
		return fmt.Errorf("backup existing agent: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	if err := copyFile(exe, binPath); err != nil {
		os.Rename(backupPath, binPath)
		_ = exec.Command("systemctl", "start", agentServiceName).Run()
		return fmt.Errorf("copy new agent: %w (old restored)", err)
	}
	os.Chmod(binPath, 0755)

	if err := exec.Command("systemctl", "start", agentServiceName).Run(); err != nil {
		return fmt.Errorf("start agent after upgrade: %w (old at %s)", err, backupPath)
	}

	fmt.Fprintf(os.Stderr, "Agent upgrade complete. Old: %s\n", backupPath)
	return nil
}
