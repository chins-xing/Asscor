//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
)

const serviceName = "asscor-kernel"
const serviceFile = "/etc/systemd/system/asscor-kernel.service"

func installService(installPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("install requires root privileges (use sudo)")
	}

	binPath := installPath + "/ASSCOR-kernel"
	configPath := installPath + "/config.ini"
	agentConfigPath := installPath + "/agent.ini"
	dataDir := installPath + "/data"
	logsDir := installPath + "/logs"
	configDir := installPath + "/config"

	dirs := []string{installPath, dataDir, logsDir, configDir}
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
		if err := copyFile("config.ini", configPath); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: could not copy config.ini: %v (binary may not be in source repo)\n", err)
		}
	}

	if _, err := os.Stat(agentConfigPath); os.IsNotExist(err) {
		copyFile("agent.ini", agentConfigPath)
	}

	_ = os.Chmod(configPath, 0644)

	exec.Command("chown", "-R", "asscor:asscor", installPath).Run()

	svcContent := fmt.Sprintf(`[Unit]
Description=ASSCOR Microkernel - Security Acceptability Assessment Engine
Documentation=https://github.com/asscor/asscor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s --config=%s --listen=:50051 --webui-port=8087 --pid-file=%s/ASSCOR-kernel.pid --log-format=json --log-level=info --log-output=%s/kernel.log
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill -SIGTERM $MAINPID
Restart=on-failure
RestartSec=10
PIDFile=%s/ASSCOR-kernel.pid
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
`, binPath, configPath, installPath, logsDir, installPath)

	if err := os.WriteFile(serviceFile, []byte(svcContent), 0644); err != nil {
		return fmt.Errorf("write service file: %w", err)
	}

	if err := createUser(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: could not create asscor user: %v\n", err)
	}

	exec.Command("systemctl", "daemon-reload").Run()
	fmt.Fprintf(os.Stderr, "Service file: %s\n", serviceFile)
	fmt.Fprintf(os.Stderr, "Binary:       %s\n", binPath)
	fmt.Fprintf(os.Stderr, "Config:       %s\n", configPath)
	fmt.Fprintf(os.Stderr, "Logs:         %s\n", logsDir)
	return nil
}

func uninstallService(installPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall requires root privileges (use sudo)")
	}

	_ = exec.Command("systemctl", "stop", serviceName).Run()
	_ = exec.Command("systemctl", "disable", serviceName).Run()

	if err := os.Remove(serviceFile); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "WARN: could not remove service file: %v\n", err)
	}

	exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

func checkInstallation(installPath string) error {
	binPath := installPath + "/ASSCOR-kernel"
	configPath := installPath + "/config.ini"

	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		return fmt.Errorf("binary not found at %s", binPath)
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config not found at %s", configPath)
	}
	if _, err := os.Stat(installPath + "/data"); os.IsNotExist(err) {
		return fmt.Errorf("data directory not found")
	}
	if _, err := os.Stat(serviceFile); os.IsNotExist(err) {
		return fmt.Errorf("systemd service not installed at %s", serviceFile)
	}
	return nil
}

func createUser() error {
	if err := exec.Command("id", "asscor").Run(); err == nil {
		return nil
	}
	return exec.Command("useradd", "-r", "-s", "/sbin/nologin", "-d", "/opt/asscor", "asscor").Run()
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
