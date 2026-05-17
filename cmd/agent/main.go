package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/argus-security/argus/internal/agent"
	"github.com/argus-security/argus/internal/version"
)

func main() {
	configPath := flag.String("config", "agent.ini", "path to agent config file")
	kernelAddr := flag.String("kernel", "localhost:50051", "kernel address host:port")
	hostID := flag.String("host-id", "", "agent host identifier (default: hostname)")
	tlsEnabled := flag.Bool("tls", false, "enable mTLS connection")
	certDir := flag.String("cert-dir", "certs", "TLS certificate directory")
	flag.Parse()

	cfg := agent.DefaultConfig()
	cfg.KernelAddr = *kernelAddr

	if *hostID != "" {
		cfg.HostID = *hostID
	}

	if *tlsEnabled {
		cfg.TLSEnabled = true
	}

	if *certDir != "" {
		cfg.CertDir = *certDir
	}

	if *configPath != "" {
		if err := loadConfigFile(*configPath, &cfg); err != nil {
			log.Printf("agent: warning: cannot load config %s: %v, using defaults", *configPath, err)
		}
	}

	if cfg.HostID == "" {
		hostname, _ := os.Hostname()
		cfg.HostID = hostname
		cfg.Hostname = hostname
	}

	log.Printf("agent: starting (ARGUS %s, SSAM %s) — %s @ %s", version.ARGUSVersion, version.SSAMVersion, cfg.HostID, cfg.KernelAddr)

	agt := agent.NewAgent(cfg)
	if err := agt.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "agent: fatal: %v\n", err)
		os.Exit(1)
	}

	log.Println("agent: stopped")
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
			}
		}
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