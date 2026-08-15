package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/asscor/asscor/internal/agent"
	"github.com/asscor/asscor/internal/cli"
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/version"
)

func main() {
	configPath := flag.String("config", "agent.ini", "path to agent config file")
	kernelAddr := flag.String("kernel", "127.0.0.1:50051", "kernel address host:port")
	hostID := flag.String("host-id", "", "agent host identifier (default: hostname)")
	tlsEnabled := flag.Bool("tls", false, "enable mTLS connection")
	tlsSkipVerify := flag.Bool("tls-skip-verify", false, "skip TLS certificate verification (DEVELOPMENT ONLY)")
	certDir := flag.String("cert-dir", "certs", "TLS certificate directory")
	logFormat := flag.String("log-format", "", "log format: json, text")
	logLevel := flag.String("log-level", "", "log level: debug, info, warn, error")
	logOutput := flag.String("log-output", "", "log output: stderr, stdout, or file path")
	install := flag.Bool("install", false, "install agent as systemd service (requires root)")
	uninstall := flag.Bool("uninstall", false, "remove agent systemd service")
	showVersion := flag.Bool("version", false, "display version and exit")
	upgrade := flag.Bool("upgrade", false, "upgrade existing agent installation in-place (requires root)")
	privileged := flag.Bool("privileged", false, "run as the privileged agent worker process (systemd socket-activated, root-required business only)")
	privSocket := flag.String("priv-socket", "/run/asscor/agent-priv.sock", "privileged agent unix socket path")
	privPeerUser := flag.String("priv-peer-user", "asscor", "unix account allowed to connect to the privileged agent (peer credential check)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ASSCOR Agent %s (SSAM %s)\n", version.ASSCORVersion, version.SSAMVersion)
		os.Exit(0)
	}
	if *privileged {
		if err := runPrivileged(*privSocket, *privPeerUser); err != nil {
			fmt.Fprintf(os.Stderr, "agent-priv: fatal: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *install {
		if err := cli.InstallAgent(); err != nil {
			fmt.Fprintf(os.Stderr, "agent: install failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "ASSCOR agent installed successfully\n")
		os.Exit(0)
	}
	if *uninstall {
		if err := cli.UninstallAgent(); err != nil {
			fmt.Fprintf(os.Stderr, "agent: uninstall failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "ASSCOR agent uninstalled successfully\n")
		os.Exit(0)
	}
	if *upgrade {
		if err := cli.UpgradeAgent(); err != nil {
			fmt.Fprintf(os.Stderr, "agent: upgrade failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Agent upgraded to %s\n", version.ASSCORVersion)
		os.Exit(0)
	}

	cfg := agent.DefaultConfig()

	if err := loadConfigFile(*configPath, &cfg); err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "agent: warning: cannot load config %s: %v\n", *configPath, err)
		}
	}

	cfg.KernelAddr = *kernelAddr

	if *hostID != "" {
		cfg.HostID = *hostID
	}

	if *tlsEnabled {
		cfg.TLSEnabled = true
	}

	if *tlsSkipVerify {
		cfg.TLSSkipVerify = true
	}

	if *certDir != "" {
		cfg.CertDir = *certDir
	}

	if *privSocket != "" {
		cfg.PrivilegedSocket = *privSocket
	}

	if *logFormat != "" {
		cfg.LogFormat = *logFormat
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}
	if *logOutput != "" {
		cfg.LogOutput = *logOutput
	}

	logger.Init(logger.Config{
		Format: cfg.LogFormat,
		Level:  cfg.LogLevel,
		Output: cfg.LogOutput,
	})
	log := logger.WithComponent("agent")

	if cfg.HostID == "" {
		hostname, _ := os.Hostname()
		cfg.HostID = hostname
		cfg.Hostname = hostname
	}

	log.Info("starting agent", "version", version.ASSCORVersion, "ssam_version", version.SSAMVersion, "host_id", cfg.HostID, "kernel_addr", cfg.KernelAddr)

	agt := agent.NewAgent(cfg)
	if err := agt.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "agent: fatal: %v\n", err)
		os.Exit(1)
	}

	log.Info("agent stopped")
}

// runPrivileged launches the privileged agent worker process. It only runs
// when started by systemd socket activation (the kernel side); it never
// self-starts and cannot be started by the main agent.
func runPrivileged(socketPath, peerUser string) error {
	priv, err := agent.NewPrivilegedAgent(agent.PrivilegedConfig{
		AllowedPeerUID: agent.LookupUID(peerUser),
		SocketPath:     socketPath,
	})
	if err != nil {
		return err
	}
	return priv.Run()
}

func loadConfigFile(path string, cfg *agent.AgentConfig) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := splitLines(string(data))
	section := ""

	for _, line := range lines {
		line = trimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		if line[0] == '[' && line[len(line)-1] == ']' {
			section = line[1 : len(line)-1]
			continue
		}

		eqIdx := indexByte(line, '=')
		if eqIdx < 0 {
			continue
		}

		key := trimSpace(line[:eqIdx])
		val := trimSpace(line[eqIdx+1:])

		switch section {
		case "agent":
			switch key {
			case "kernel_addr":
				cfg.KernelAddr = val
			case "host_id":
				cfg.HostID = val
			case "hostname":
				cfg.Hostname = val
			case "version":
				cfg.Version = val
			case "heartbeat_sec":
				cfg.HeartbeatSec = atoi(val, cfg.HeartbeatSec)
			case "check_interval_sec":
				cfg.CheckIntervalSec = atoi(val, cfg.CheckIntervalSec)
			case "check_timeout_sec":
				cfg.CheckTimeoutSec = atoi(val, cfg.CheckTimeoutSec)
			case "max_retries":
				cfg.MaxRetries = atoi(val, cfg.MaxRetries)
			case "reconnect_sec":
				cfg.ReconnectSec = atoi(val, cfg.ReconnectSec)
			case "tls_enabled":
				cfg.TLSEnabled = val == "true" || val == "yes" || val == "1"
			case "tls_skip_verify":
				cfg.TLSSkipVerify = val == "true" || val == "yes" || val == "1"
			case "cert_dir":
				cfg.CertDir = val
			case "hmac_key":
				cfg.HMACKey = val
			case "priv_socket":
				cfg.PrivilegedSocket = val
			case "log_format":
				cfg.LogFormat = val
			case "log_level":
				cfg.LogLevel = val
			case "log_output":
				cfg.LogOutput = val
			}
		case "check_deltas":
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				if cfg.CheckDeltas == nil {
					cfg.CheckDeltas = make(map[string]float64)
				}
				cfg.CheckDeltas[key] = f
			}
		}
	}

	// Load configuration-defined user checks ([user_check.<name>] sections).
	// The full config parser understands these sections; it also re-parses the
	// [agent] section which is ignored here (already applied above).
	if fullCfg, err := config.Parse(string(data)); err == nil {
		cfg.UserCheckItems = config.ParseUserChecks(fullCfg.AdapterConfig)
	}

	return nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		} else if s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 2
			i++
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func atoi(s string, def int) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
