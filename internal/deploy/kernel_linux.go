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
	if err := requireRoot(); err != nil {
		return err
	}
	binPath := installPath + "/ASSCOR-kernel"
	configPath := defaultConfigDir + "/config.ini"
	configTemplates := defaultConfigDir + "/config"
	dataDir := defaultDataDir
	logsDir := defaultLogsDir

	for _, d := range []string{installPath, defaultConfigDir, dataDir, logsDir, configTemplates} {
		os.MkdirAll(d, 0755)
	}

	if err := copySelfTo(binPath); err != nil {
		return err
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		os.WriteFile(configPath, []byte("data_dir = "+dataDir+"\n[weights]\nattack_surface = 35\nbusiness_continuity = 25\noperation_trust = 25\nresilience = 15\n"), 0644)
	}

	exec.Command("useradd", "-r", "-s", "/sbin/nologin", "-d", "/opt/asscor", "-M", "asscor").Run()
	chownAsscor(installPath, defaultConfigDir, dataDir, logsDir)

	svcContent := fmt.Sprintf(`[Unit]
Description=ASSCOR Microkernel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=asscor
Group=asscor
ExecStart=%s --config=%s --listen=:50051 --webui-port=8087 --pid-file=%s/ASSCOR-kernel.pid --log-format=json --log-output=%s/kernel.log
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
ReadWritePaths=%s /var/lib/asscor /var/log/asscor

[Install]
WantedBy=multi-user.target
`, binPath, configPath, installPath, logsDir, installPath, installPath)

	os.WriteFile(serviceFile, []byte(svcContent), 0644)

	os.Remove("/usr/bin/asscor")
	os.Remove("/usr/bin/asscor-cli")
	os.Symlink(binPath, "/usr/bin/asscor")
	cliWrapper := fmt.Sprintf("#!/bin/sh\nSOCK=\"${ASSCOR_CLI_SOCKET:-%s/asscor-cli.sock}\"\nexec %s --cli \"$SOCK\" \"$@\"\n", installPath, binPath)
	os.WriteFile("/usr/bin/asscor-cli", []byte(cliWrapper), 0755)

	systemctlReload()
	return nil
}

func UninstallKernel(_ string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	systemctlStopDisable(serviceName)
	os.Remove(serviceFile)
	os.Remove("/usr/bin/asscor")
	os.Remove("/usr/bin/asscor-cli")
	systemctlReload()
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
	if err := requireRoot(); err != nil {
		return err
	}
	binPath := defaultInstallDir + "/ASSCOR-kernel"
	backupPath := binPath + ".bak"
	exec.Command("systemctl", "stop", serviceName).Run()
	os.Rename(binPath, backupPath)
	if err := copySelfTo(binPath); err != nil {
		return err
	}
	chownAsscor(binPath)
	exec.Command("systemctl", "start", serviceName).Run()
	return nil
}
