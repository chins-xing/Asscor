//go:build linux

package main

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

func installService(installPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("install requires root privileges (use sudo)")
	}

	binPath := installPath + "/ASSCOR-kernel"
	configPath := defaultConfigDir + "/config.ini"
	configTemplates := defaultConfigDir + "/config"
	dataDir := defaultDataDir
	logsDir := defaultLogsDir

	dirs := []string{installPath, defaultConfigDir, dataDir, logsDir, configTemplates}
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
			fmt.Fprintf(os.Stderr, "WARN: could not copy config.ini: %v\n", err)
		}
	}
	if _, err := os.Stat(configTemplates); os.IsNotExist(err) {
		copyDir("config", configTemplates)
	}

	// fix config data_dir to use FHS path
	updateConfigDataDir(configPath)

	if err := createUser(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: could not create asscor user: %v\n", err)
	}
	exec.Command("chown", "-R", "asscor:asscor", installPath, defaultConfigDir, dataDir, logsDir).Run()

	svcContent := fmt.Sprintf(`[Unit]
Description=ASSCOR Microkernel - Security Acceptability Assessment Engine
Documentation=https://github.com/asscor/asscor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=asscor
Group=asscor
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
ReadWritePaths=%s %s %s /opt/asscor

[Install]
WantedBy=multi-user.target
`, binPath, configPath, installPath, logsDir, installPath, dataDir, logsDir, installPath)

	if err := os.WriteFile(serviceFile, []byte(svcContent), 0644); err != nil {
		return fmt.Errorf("write service file: %w", err)
	}

	exec.Command("systemctl", "daemon-reload").Run()
	fmt.Fprintf(os.Stderr, "ASSCOR installed successfully\n")
	fmt.Fprintf(os.Stderr, "  Binary:  %s\n", binPath)
	fmt.Fprintf(os.Stderr, "  Config:  %s\n", configPath)
	fmt.Fprintf(os.Stderr, "  Data:    %s\n", dataDir)
	fmt.Fprintf(os.Stderr, "  Logs:    %s\n", logsDir)
	fmt.Fprintf(os.Stderr, "  CLI:     %s --cli %s/asscor-cli.sock\n", binPath, installPath)
	fmt.Fprintf(os.Stderr, "  Start:   sudo systemctl start asscor-kernel\n")
	return nil
}

func updateConfigDataDir(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)
	if containsStr(content, "data_dir") {
		content = replaceLine(content, "data_dir", "data_dir = "+defaultDataDir)
	} else {
		content = "data_dir = " + defaultDataDir + "\n" + content
	}
	os.WriteFile(path, []byte(content), 0644)
}

func containsStr(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && findInStr(s, substr)
}

func findInStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func replaceLine(content, key, replacement string) string {
	result := ""
	i := 0
	lines := splitLines(content)
	for _, line := range lines {
		if findInStr(line, key+" ") || findInStr(line, key+"=") {
			result += replacement + "\n"
		} else {
			result += line + "\n"
		}
		i++
	}
	_ = i
	return result
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func uninstallService(installPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall requires root privileges (use sudo)")
	}

	_ = exec.Command("systemctl", "stop", serviceName).Run()
	_ = exec.Command("systemctl", "disable", serviceName).Run()
	os.Remove(serviceFile)
	exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

func checkInstallation(installPath string) error {
	configPath := defaultConfigDir + "/config.ini"

	if _, err := os.Stat(installPath + "/ASSCOR-kernel"); os.IsNotExist(err) {
		return fmt.Errorf("binary not found at %s/ASSCOR-kernel", installPath)
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config not found at %s", configPath)
	}
	if _, err := os.Stat(defaultDataDir); os.IsNotExist(err) {
		return fmt.Errorf("data directory not found at %s", defaultDataDir)
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
	return exec.Command("useradd", "-r", "-s", "/sbin/nologin", "-d", "/opt/asscor", "-M", "asscor").Run()
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		srcPath := src + "/" + e.Name()
		dstPath := dst + "/" + e.Name()
		if e.IsDir() {
			os.MkdirAll(dstPath, 0755)
			copyDir(srcPath, dstPath)
		} else {
			copyFile(srcPath, dstPath)
		}
	}
	return nil
}
