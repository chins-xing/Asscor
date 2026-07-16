//go:build linux

package deploy

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	serviceName       = "asscor-kernel"
	serviceFile       = "/etc/systemd/system/asscor-kernel.service"
	defaultInstallDir = "/opt/asscor"
	defaultConfigDir  = "/etc/asscor"
	defaultDataDir    = "/var/lib/asscor"
	defaultLogsDir    = "/var/log/asscor"
)

func kernelUnitContent(binPath, configPath, installPath, logsDir string) string {
	return fmt.Sprintf(`[Unit]
Description=ASSCOR Microkernel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=asscor
Group=asscor
WorkingDirectory=%s
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
`, installPath, binPath, configPath, installPath, logsDir, installPath, installPath)
}

func writeSystemdUnit(installPath string) {
	binPath := installPath + "/ASSCOR-kernel"
	configPath := defaultConfigDir + "/config.ini"
	logsDir := defaultLogsDir
	os.WriteFile(serviceFile, []byte(kernelUnitContent(binPath, configPath, installPath, logsDir)), 0644)
}

func writeCLISymlinks(binPath, installPath string) {
	os.Remove("/usr/bin/asscor")
	os.Remove("/usr/bin/asscor-cli")
	os.Symlink(binPath, "/usr/bin/asscor")
	cliWrapper := fmt.Sprintf("#!/bin/sh\nSOCK=\"${ASSCOR_CLI_SOCKET:-%s/asscor-cli.sock}\"\nexec %s --cli \"$SOCK\" \"$@\"\n", installPath, binPath)
	os.WriteFile("/usr/bin/asscor-cli", []byte(cliWrapper), 0755)
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

	writeSystemdUnit(installPath)
	writeCLISymlinks(binPath, installPath)
	systemctlReload()
	return nil
}

func UninstallKernel(installPath string) error {
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

func CheckKernelInstall(installPath string) error {
	binPath := installPath + "/ASSCOR-kernel"
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		return fmt.Errorf("binary not found at %s", binPath)
	}
	if _, err := os.Stat(serviceFile); os.IsNotExist(err) {
		return fmt.Errorf("service not installed")
	}
	return nil
}

func UpgradeKernel(installPath string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	binPath := installPath + "/ASSCOR-kernel"
	backupPath := binPath + ".bak"

	exec.Command("systemctl", "stop", serviceName).Run()
	os.Remove(backupPath)
	os.Rename(binPath, backupPath)

	if err := copySelfTo(binPath); err != nil {
		os.Rename(backupPath, binPath)
		return fmt.Errorf("upgrade failed, rolled back: %w", err)
	}
	chownAsscor(binPath)

	writeSystemdUnit(installPath)
	writeCLISymlinks(binPath, installPath)
	systemctlReload()

	exec.Command("systemctl", "start", serviceName).Run()
	if err := waitForServiceHealthy(serviceName, 10*time.Second); err != nil {
		return fmt.Errorf("upgrade applied but service failed to start: %w", err)
	}
	return nil
}
