//go:build linux

package deploy

import (
	"fmt"
	"os"
	"os/exec"
)

const (
	serviceName       = "asscor-kernel"
	serviceFile       = "/etc/systemd/system/asscor-kernel.service"
	defaultInstallDir = "/opt/asscor"
	defaultConfigDir  = "/etc/asscor"
	defaultDataDir    = "/var/lib/asscor"
	defaultLogsDir    = "/var/log/asscor"
)

func InstallKernel(installPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("install requires root privileges")
	}
	binPath := installPath + "/ASSCOR-kernel"
	configPath := defaultConfigDir + "/config.ini"
	configTemplates := defaultConfigDir + "/config"
	dataDir := defaultDataDir
	logsDir := defaultLogsDir

	for _, d := range []string{installPath, defaultConfigDir, dataDir, logsDir, configTemplates} {
		os.MkdirAll(d, 0755)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return fmt.Errorf("read self: %w", err)
	}
	os.WriteFile(binPath, data, 0755)

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		os.WriteFile(configPath, []byte("data_dir = "+dataDir+"\n[weights]\nattack_surface = 35\nbusiness_continuity = 25\noperation_trust = 25\nresilience = 15\n"), 0644)
	}

	exec.Command("useradd", "-r", "-s", "/sbin/nologin", "-d", "/opt/asscor", "-M", "asscor").Run()
	exec.Command("chown", "-R", "asscor:asscor", installPath, defaultConfigDir, dataDir, logsDir).Run()

	svcContent := fmt.Sprintf(`[Unit]
Description=ASSCOR Microkernel
After=network-online.target

[Service]
Type=simple
User=asscor
ExecStart=%s --config=%s --listen=:50051 --webui-port=8087 --log-output=%s/kernel.log
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
KillMode=mixed
TimeoutStopSec=30
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, binPath, configPath, logsDir)

	os.WriteFile(serviceFile, []byte(svcContent), 0644)

	os.Remove("/usr/bin/asscor")
	os.Remove("/usr/bin/asscor-cli")
	os.Symlink(binPath, "/usr/bin/asscor")
	cliWrapper := fmt.Sprintf("#!/bin/sh\nexec %s --cli %s/asscor-cli.sock \"$@\"\n", binPath, installPath)
	os.WriteFile("/usr/bin/asscor-cli", []byte(cliWrapper), 0755)

	exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

func UninstallKernel(_ string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall requires root privileges")
	}
	exec.Command("systemctl", "stop", serviceName).Run()
	exec.Command("systemctl", "disable", serviceName).Run()
	os.Remove(serviceFile)
	os.Remove("/usr/bin/asscor")
	os.Remove("/usr/bin/asscor-cli")
	exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

func CheckKernelInstall(_ string) error {
	if _, err := os.Stat(defaultInstallDir + "/ASSCOR-kernel"); os.IsNotExist(err) {
		return fmt.Errorf("binary not found at %s/ASSCOR-kernel", defaultInstallDir)
	}
	if _, err := os.Stat(serviceFile); os.IsNotExist(err) {
		return fmt.Errorf("service not installed")
	}
	return nil
}

func UpgradeKernel(_ string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("upgrade requires root privileges")
	}
	binPath := defaultInstallDir + "/ASSCOR-kernel"
	backupPath := binPath + ".bak"
	exec.Command("systemctl", "stop", serviceName).Run()
	os.Rename(binPath, backupPath)
	exe, _ := os.Executable()
	data, _ := os.ReadFile(exe)
	os.WriteFile(binPath, data, 0755)
	exec.Command("chown", "asscor:asscor", binPath).Run()
	exec.Command("systemctl", "start", serviceName).Run()
	return nil
}
