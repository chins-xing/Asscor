//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
)

const agentServiceName = "asscor-agent"
const agentServiceFile = "/etc/systemd/system/asscor-agent.service"

func installAgent() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("install requires root privileges (use sudo)")
	}

	const installPath = "/opt/asscor/agent"
	const binPath = installPath + "/ASSCOR-agent"
	const configPath = installPath + "/agent.ini"
	const logsDir = "/opt/asscor/logs"

	dirs := []string{installPath, logsDir}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("create directory %s: %w", d, err)
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	if err := copyFile(exe, binPath); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}
	if err := os.Chmod(binPath, 0755); err != nil {
		return fmt.Errorf("chmod binary: %w", err)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		copyFile("agent.ini", configPath)
	}

	svcContent := fmt.Sprintf(`[Unit]
Description=ASSCOR Agent - Host Security Assessment Probe
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s --config=%s --kernel=127.0.0.1:50051 --log-format=text --log-level=info --log-output=%s/agent.log
Restart=always
RestartSec=15
KillMode=mixed
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, binPath, configPath, logsDir)

	if err := os.WriteFile(agentServiceFile, []byte(svcContent), 0644); err != nil {
		return fmt.Errorf("write service file: %w", err)
	}

	exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

func uninstallAgent() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall requires root privileges (use sudo)")
	}

	_ = exec.Command("systemctl", "stop", agentServiceName).Run()
	_ = exec.Command("systemctl", "disable", agentServiceName).Run()
	os.Remove(agentServiceFile)
	exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0755)
}
