package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/argus-security/argus/internal/logger"
	"github.com/argus-security/argus/internal/version"
	"syscall"
	"time"

	apiv1 "github.com/argus-security/argus/api/v1"
	"github.com/argus-security/argus/internal/checks"
	"github.com/argus-security/argus/internal/common"
	"github.com/argus-security/argus/internal/model"
)

type AgentConfig struct {
	KernelAddr       string
	HostID           string
	Hostname         string
	Version          string
	HeartbeatSec     int
	CheckIntervalSec int
	CheckTimeoutSec  int
	MaxRetries       int
	ReconnectSec     int
	TLSEnabled       bool
	TLSSkipVerify    bool
	CertDir          string
	HMACKey          string
}

func DefaultConfig() AgentConfig {
	hostname, _ := os.Hostname()
	return AgentConfig{
		KernelAddr:       "localhost:50051",
		HostID:           hostname,
		Hostname:         hostname,
		Version:          version.ARGUSVersion,
		HeartbeatSec:     2,
		CheckIntervalSec: 3600,
		CheckTimeoutSec:  10,
		MaxRetries:       3,
		ReconnectSec:     5,
		TLSEnabled:       true,
		TLSSkipVerify:    false,
	}
}

type Agent struct {
	cfg              AgentConfig
	client           *Client
	sessionID        string
	running          atomic.Bool
	checkers         []model.CheckItem
	checkCount       int
	pendingCmd       []*apiv1.Command
	lastCheckTime    time.Time
	hmacKeyConfigured bool
	hmacKeyWarned    atomic.Bool
	cachedPackages   []string
}

func NewAgent(cfg AgentConfig) *Agent {
	common.DefaultTimeout = time.Duration(cfg.CheckTimeoutSec) * time.Second

	allChecks := checks.GetAll()
	logger.WithComponent("agent").Info("loaded platform checks", "count", len(allChecks), "os", runtime.GOOS, "arch", runtime.GOARCH)

	hmacKeyConfigured := cfg.HMACKey != "" || os.Getenv("ARGUS_HMAC_KEY") != ""
	if !hmacKeyConfigured {
		logger.WithComponent("agent").Warn("HMAC key not configured, remote commands will be rejected")
	}

	return &Agent{
		cfg:              cfg,
		checkers:         allChecks,
		checkCount:       len(allChecks),
		hmacKeyConfigured: hmacKeyConfigured,
	}
}

func (a *Agent) Run() error {
	a.running.Store(true)
	defer a.running.Store(false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		logger.WithComponent("agent").Info("received shutdown signal")
		cancel()
	}()

	for a.running.Load() {
		if err := a.runOnce(ctx); err != nil {
			logger.WithComponent("agent").Error("session error", "error", err)
			a.sessionID = ""
			if a.client != nil {
				a.client.Close()
				a.client = nil
			}

			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Duration(a.cfg.ReconnectSec) * time.Second):
				continue
			}
		}
	}

	return nil
}

func (a *Agent) runOnce(ctx context.Context) error {
	if a.client == nil || !a.client.Connected() {
		if err := a.connect(); err != nil {
			return fmt.Errorf("connect: %w", err)
		}
	}

	if a.sessionID == "" {
		if err := a.register(); err != nil {
			return fmt.Errorf("register: %w", err)
		}
	}

	a.lastCheckTime = time.Time{}

	consecutiveErrors := 0
	timer := time.NewTimer(time.Duration(a.cfg.HeartbeatSec) * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			if err := a.heartbeatCycle(); err != nil {
				consecutiveErrors++
				logger.WithComponent("agent").Error("cycle error", "consecutive", consecutiveErrors, "max_retries", a.cfg.MaxRetries, "error", err)
				if consecutiveErrors >= a.cfg.MaxRetries {
					return fmt.Errorf("max retries exceeded: %w", err)
				}
				timer.Reset(time.Duration(a.cfg.HeartbeatSec) * time.Second)
				continue
			}
			consecutiveErrors = 0
			timer.Reset(time.Duration(a.cfg.HeartbeatSec) * time.Second)
		}
	}
}

func (a *Agent) connect() error {
	var tlsConfig *tls.Config
	if a.cfg.TLSEnabled {
		certDir := a.cfg.CertDir
		if certDir == "" {
			certDir = "certs"
		}

		caCertPath := filepath.Join(certDir, "ca.crt")
		agentCertPath := filepath.Join(certDir, "agent.crt")
		agentKeyPath := filepath.Join(certDir, "agent.key")

		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return fmt.Errorf("read CA certificate from %s: %w", caCertPath, err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse CA certificate from %s", caCertPath)
		}

		caFingerprint := sha256.Sum256(caCert)
		caFPShort := hex.EncodeToString(caFingerprint[:])[:16]

		agentCert, err := tls.LoadX509KeyPair(agentCertPath, agentKeyPath)
		if err != nil {
			return fmt.Errorf("load agent certificate from %s: %w", agentCertPath, err)
		}

		var agentFPShort string
		if len(agentCert.Certificate) > 0 {
			agentFP := sha256.Sum256(agentCert.Certificate[0])
			agentFPShort = hex.EncodeToString(agentFP[:])[:16]
		}

		logger.WithComponent("agent").Info("TLS configured",
			"cert_dir", certDir,
			"ca_sha256", caFPShort,
			"agent_sha256", agentFPShort)

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{agentCert},
			RootCAs:      caPool,
			ServerName:   "localhost",
			MinVersion:   tls.VersionTLS12,
		}

		if a.cfg.TLSSkipVerify {
			tlsConfig.InsecureSkipVerify = true
			logger.WithComponent("agent").Warn("TLS certificate verification is DISABLED — not for production use")
		}
	}

	a.client = NewClient(a.cfg.KernelAddr, tlsConfig)
	if err := a.client.Connect(); err != nil {
		a.client = nil
		a.diagnoseTLS()

		if a.cfg.TLSEnabled {
			logger.WithComponent("agent").Info("re-reading certificates from disk and retrying connection")
			time.Sleep(1 * time.Second)

			certDir := a.cfg.CertDir
			if certDir == "" {
				certDir = "certs"
			}
			caCertPath := filepath.Join(certDir, "ca.crt")
			agentCertPath := filepath.Join(certDir, "agent.crt")
			agentKeyPath := filepath.Join(certDir, "agent.key")

			caCert, caErr := os.ReadFile(caCertPath)
			if caErr != nil {
				return fmt.Errorf("TLS connect failed, re-read CA cert error: %w (original: %v)", caErr, err)
			}
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("TLS connect failed, re-read CA cert parse error (original: %v)", err)
			}

			caFP := sha256.Sum256(caCert)
			logger.WithComponent("agent").Info("re-read CA cert", "sha256", hex.EncodeToString(caFP[:])[:16])

			agentCert, agentErr := tls.LoadX509KeyPair(agentCertPath, agentKeyPath)
			if agentErr != nil {
				return fmt.Errorf("TLS connect failed, re-read agent cert error: %w (original: %v)", agentErr, err)
			}

			retryTLSConfig := &tls.Config{
				Certificates: []tls.Certificate{agentCert},
				RootCAs:      caPool,
				ServerName:   "localhost",
				MinVersion:   tls.VersionTLS12,
			}
			if a.cfg.TLSSkipVerify {
				retryTLSConfig.InsecureSkipVerify = true
			}

			a.client = NewClient(a.cfg.KernelAddr, retryTLSConfig)
			if retryErr := a.client.Connect(); retryErr != nil {
				a.client = nil
				return fmt.Errorf("TLS connect failed after cert re-read (original: %v, retry: %v). HINT: delete certs/ directory on BOTH kernel and agent, then restart kernel to regenerate", err, retryErr)
			}
			logger.WithComponent("agent").Info("connected to kernel on retry with fresh certs", "addr", a.cfg.KernelAddr)
			return nil
		}

		return err
	}
	logger.WithComponent("agent").Info("connected to kernel", "addr", a.cfg.KernelAddr, "mtls", a.cfg.TLSEnabled)
	return nil
}

func (a *Agent) diagnoseTLS() {
	if !a.cfg.TLSEnabled {
		return
	}

	certDir := a.cfg.CertDir
	if certDir == "" {
		certDir = "certs"
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	diagConn, err := tls.DialWithDialer(dialer, "tcp", a.cfg.KernelAddr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		logger.WithComponent("agent").Error("TLS diagnose: cannot connect even with skip-verify", "error", err)
		return
	}
	defer diagConn.Close()

	certs := diagConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		logger.WithComponent("agent").Error("TLS diagnose: server sent no certificates")
		return
	}

	serverCert := certs[0]
	serverFP := sha256.Sum256(serverCert.Raw)
	logger.WithComponent("agent").Error("TLS diagnose: server certificate info",
		"subject", serverCert.Subject.CommonName,
		"issuer", serverCert.Issuer.CommonName,
		"sha256", hex.EncodeToString(serverFP[:])[:16],
		"not_before", serverCert.NotBefore.Format(time.RFC3339),
		"not_after", serverCert.NotAfter.Format(time.RFC3339),
		"dns_names", fmt.Sprintf("%v", serverCert.DNSNames),
	)

	caCertPEM, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		logger.WithComponent("agent").Error("TLS diagnose: cannot read local CA", "error", err)
		return
	}

	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		logger.WithComponent("agent").Error("TLS diagnose: cannot decode local CA PEM")
		return
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		logger.WithComponent("agent").Error("TLS diagnose: cannot parse local CA", "error", err)
		return
	}

	sigErr := serverCert.CheckSignatureFrom(caCert)
	if sigErr != nil {
		logger.WithComponent("agent").Error("TLS diagnose: server cert NOT signed by local CA",
			"error", sigErr,
			"ca_issuer", caCert.Issuer.CommonName,
			"ca_subject", caCert.Subject.CommonName,
		)
		logger.WithComponent("agent").Error("HINT: delete certs/ directory on BOTH kernel and agent, then restart kernel to regenerate")
	} else {
		logger.WithComponent("agent").Info("TLS diagnose: server cert IS signed by local CA — issue may be SAN/name mismatch")
	}
}

func (a *Agent) register() error {
	req := &apiv1.RegisterRequest{
		HostId:   a.cfg.HostID,
		Hostname: a.cfg.Hostname,
		Version:  a.cfg.Version,
	}

	resp, err := a.client.Register(req)
	if err != nil {
		return err
	}

	if !resp.Accepted {
		return fmt.Errorf("registration rejected by kernel")
	}

	a.sessionID = resp.SessionId
	logger.WithComponent("agent").Info("registered", "session_id", a.sessionID)
	return nil
}

func (a *Agent) heartbeatCycle() error {
	a.executePendingCommands()

	interval := time.Duration(a.cfg.CheckIntervalSec) * time.Second
	elapsed := time.Since(a.lastCheckTime)
	shouldCheck := a.lastCheckTime.IsZero() || elapsed >= interval

	var checkResults []*apiv1.CheckResult

	if shouldCheck {
		results := a.runChecks()

		checkResults = make([]*apiv1.CheckResult, 0, len(results))
		for _, r := range results {
			checkResults = append(checkResults, &apiv1.CheckResult{
				CheckId:       r.CheckID,
				Domain:        r.Domain,
				Name:          r.Name,
				Passed:        r.Passed,
				Delta:         r.Delta,
				Detail:        r.Detail,
				ComplianceRef: r.ComplianceRef,
			})
		}

		a.lastCheckTime = time.Now()
	} else {
		remaining := interval - elapsed
		if remaining.Seconds() <= 60 || int(remaining.Seconds())%60 == 0 {
			logger.WithComponent("agent").Info("next assessment", "in", remaining.Round(time.Second))
		}
	}

	var snapshot *apiv1.AssessmentResult
	if len(checkResults) > 0 {
		snapshot = &apiv1.AssessmentResult{
			Checks: checkResults,
		}
	}

	heartbeatReq := &apiv1.HeartbeatRequest{
		HostId:    a.cfg.HostID,
		SessionId: a.sessionID,
		Result:    snapshot,
		Packages:  a.collectPackages(),
	}

	heartbeatResp, err := a.client.Heartbeat(heartbeatReq)
	if err != nil {
		return err
	}

	if !heartbeatResp.Ok {
		logger.WithComponent("agent").Warn("heartbeat not ok, re-registering")
		a.sessionID = ""
		return fmt.Errorf("heartbeat rejected by kernel")
	}

	a.pendingCmd = heartbeatResp.PendingCommands

	if heartbeatResp.AssessmentResult != nil && len(checkResults) > 0 {
		a.printAssessmentReport(heartbeatResp.AssessmentResult)
	}

	return nil
}

func (a *Agent) printAssessmentReport(result *apiv1.AssessmentResult) {
	bar := func(score float64, width int) string {
		filled := int(score / 100 * float64(width))
		if filled > width {
			filled = width
		}
		b := make([]byte, width)
		for i := 0; i < width; i++ {
			if i < filled {
				b[i] = '='
			} else {
				b[i] = ' '
			}
		}
		return string(b)
	}

	domainLabels := map[string]string{
		"attack_surface":      "Attack Surface",
		"business_continuity": "Business Continuity",
		"operation_trust":     "Operation Trust",
		"resilience":          "Resilience",
		"kernel_security":     "Kernel Security",
	}

	coreOrder := []string{"resilience", "attack_surface", "business_continuity", "operation_trust"}
	extOrder := []string{"kernel_security"}
	detailOrder := []string{"operation_trust", "attack_surface", "kernel_security", "resilience", "business_continuity"}

	checksByDomain := make(map[string][]*apiv1.CheckResult)
	for _, c := range result.Checks {
		checksByDomain[c.Domain] = append(checksByDomain[c.Domain], c)
	}

	fmt.Println()
	fmt.Println("[ Core Domain Scores ]")
	fmt.Println("---------------------------------------------------------------")
	for _, domain := range coreOrder {
		label := domainLabels[domain]
		if label == "" {
			label = domain
		}
		score := 0.0
		if result.DomainScores != nil {
			score = result.DomainScores[domain]
		}
		fmt.Printf("  %-20s : [%-20s] %.0f/100\n", label, bar(score, 20), score)
	}

	fmt.Println()
	fmt.Println("[ Extension Domain Scores ]")
	fmt.Println("---------------------------------------------------------------")
	extFound := false
	for _, domain := range extOrder {
		checks, ok := checksByDomain[domain]
		if !ok {
			continue
		}
		extFound = true
		passed := 0
		for _, c := range checks {
			if c.Passed {
				passed++
			}
		}
		label := domainLabels[domain]
		if label == "" {
			label = domain
		}
		score := 0.0
		if result.DomainScores != nil {
			score = result.DomainScores[domain]
		}
		fmt.Printf("  %-20s : [%-20s] %.0f/100  (%d of %d checks passed)\n",
			label, bar(score, 20), score, passed, len(checks))
	}
	if !extFound {
		fmt.Println("  (none)")
	}

	fmt.Println()
	fmt.Println("[ Edge Factor Report ]")
	fmt.Println("---------------------------------------------------------------")
	edgeFound := false
	for id, factor := range result.EdgeFactors {
		if factor < 1.0 {
			name := ""
			switch id {
			case "two_factor_failure":
				name = "2FA Missing"
			default:
				name = id
			}
			fmt.Printf("  %-12s : %-30s factor=%.2f (ACTIVE)\n", id, name, factor)
			edgeFound = true
		}
	}
	if !edgeFound {
		fmt.Println("  (none)")
	}

	for _, domain := range detailOrder {
		checks, ok := checksByDomain[domain]
		if !ok {
			continue
		}
		label := domainLabels[domain]
		if label == "" {
			label = domain
		}
		fmt.Println()
		fmt.Printf("[ %s Details ]\n", label)
		fmt.Println("---------------------------------------------------------------")
		for _, c := range checks {
			status := "PASS"
			if !c.Passed {
				status = "FAIL"
			}
			if c.Detail != "" {
				fmt.Printf("  [%s] %s : %s (%s)\n", status, c.CheckId, c.Name, c.Detail)
			} else {
				fmt.Printf("  [%s] %s : %s\n", status, c.CheckId, c.Name)
			}
		}
	}

	fmt.Println()
	fmt.Println("---------------------------------------------------------------")
	status := "ACCEPTABLE"
	if !result.Acceptable {
		status = "NOT ACCEPTABLE"
	}
	threatCoeff := result.ThreatCoeff
	if threatCoeff == 0 {
		threatCoeff = 1.0
	}
	spcScore := result.SpcScore
	if spcScore == 0 {
		spcScore = 1.0
	}
	fmt.Printf("  Final Score: %.2f/100    Status: %s\n", result.FinalScore, status)
	if spcScore >= 1.0 {
		fmt.Printf("  Threat Coeff: %.2f    SPC Score: %.2f (pending data sync)\n", threatCoeff, spcScore)
	} else {
		fmt.Printf("  Threat Coeff: %.2f    SPC Score: %.2f\n", threatCoeff, spcScore)
	}

	if len(result.SpcCVEs) > 0 {
		fmt.Println("---------------------------------------------------------------")
		fmt.Printf("[ SPC: Matched CVEs (%d) ]\n", len(result.SpcCVEs))
		fmt.Println("---------------------------------------------------------------")
		sort.Slice(result.SpcCVEs, func(i, j int) bool {
			return result.SpcCVEs[i].CVSS > result.SpcCVEs[j].CVSS
		})
		maxShow := len(result.SpcCVEs)
		if maxShow > 15 {
			maxShow = 15
		}
		for i := 0; i < maxShow; i++ {
			cve := result.SpcCVEs[i]
			tags := ""
			if cve.InKEV {
				tags += " [KEV]"
			}
			if cve.HasPoC {
				tags += " [PoC]"
			}
			product := ""
			if cve.Product != "" {
				product = fmt.Sprintf("  (%s)", cve.Product)
			}
			fmt.Printf("  %s  CVSS:%.1f  EPSS:%.2f  Penalty:%.4f%s%s\n",
				cve.CVEID, cve.CVSS, cve.EPSS, cve.Penalty, tags, product)
		}
		if len(result.SpcCVEs) > maxShow {
			fmt.Printf("  ... and %d more\n", len(result.SpcCVEs)-maxShow)
		}
	}
	fmt.Println("---------------------------------------------------------------")
	fmt.Println()

	passed := 0
	total := len(result.Checks)
	for _, c := range result.Checks {
		if c.Passed {
			passed++
		}
	}
	passRate := 0.0
	if total > 0 {
		passRate = float64(passed) / float64(total) * 100.0
	}
	logger.WithComponent("agent").Info("assessment complete",
		"passed", passed, "total", total, "pass_rate", passRate,
		"status", map[bool]string{true: "ACCEPTABLE", false: "FAILED"}[result.Acceptable],
		"next_check", time.Duration(a.cfg.CheckIntervalSec)*time.Second)
}

func (a *Agent) executePendingCommands() {
	if len(a.pendingCmd) == 0 {
		return
	}

	logger.WithComponent("agent").Info("executing pending commands", "count", len(a.pendingCmd))
	for _, cmd := range a.pendingCmd {
		if !a.verifyCommandSignature(cmd) {
			logger.WithComponent("agent").Warn("command rejected: HMAC verification failed", "command_id", cmd.CommandId)
			continue
		}
		logger.WithComponent("agent").Info("executing command", "command_id", cmd.CommandId, "command", cmd.Command)
		a.runCommand(cmd)
	}
	a.pendingCmd = nil
}

func (a *Agent) verifyCommandSignature(cmd *apiv1.Command) bool {
	if len(cmd.Signature) == 0 {
		logger.WithComponent("agent").Warn("command has no signature, rejecting", "command_id", cmd.CommandId)
		return false
	}

	hmacKey := a.cfg.HMACKey
	if hmacKey == "" {
		hmacKey = os.Getenv("ARGUS_HMAC_KEY")
	}
	if hmacKey == "" {
		if !a.hmacKeyWarned.Load() {
			a.hmacKeyWarned.Store(true)
			logger.WithComponent("agent").Error("SECURITY ALERT: HMAC key not configured, all remote commands rejected")
		}
		return false
	}

	mac := hmac.New(sha256.New, []byte(hmacKey))
	mac.Write([]byte(cmd.CommandId + ":" + cmd.Command))
	keys := sortedParamKeys(cmd.Params)
	for _, k := range keys {
		mac.Write([]byte(":" + k + "=" + cmd.Params[k]))
	}
	expected := mac.Sum(nil)

	return hmac.Equal(cmd.Signature, expected)
}

func sortedParamKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (a *Agent) collectPackages() []string {
	if a.cachedPackages != nil {
		return a.cachedPackages
	}

	var packages []string

	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/usr/bin/rpm"); err == nil {
			packages = a.parseRPMPackages()
			if len(packages) == 0 {
				logger.WithComponent("agent").Warn("rpm command found but no packages returned, trying alternative rpm query")
				packages = a.parseRPMPackagesAlt()
			}
		} else if _, err := os.Stat("/usr/bin/dpkg-query"); err == nil {
			packages = a.parseDPKGPackages()
		} else if _, err := os.Stat("/usr/bin/pacman"); err == nil {
			packages = a.parsePacmanPackages()
		} else {
			logger.WithComponent("agent").Warn("no supported package manager found (rpm/dpkg/pacman)")
		}
	}

	if len(packages) == 0 {
		packages = a.extractPackagesFromChecks()
	}

	a.cachedPackages = packages
	logger.WithComponent("agent").Info("collected packages", "count", len(packages))
	return packages
}

func (a *Agent) parseRPMPackages() []string {
	out, err := a.safeExec("rpm", []string{"-qa", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE}\n"})
	if err != nil {
		logger.WithComponent("agent").Warn("rpm -qa failed", "error", err.Error())
		return nil
	}
	return a.parsePackageList(out)
}

func (a *Agent) parseRPMPackagesAlt() []string {
	out, err := a.safeExec("rpm", []string{"-qa"})
	if err != nil {
		logger.WithComponent("agent").Warn("rpm -qa (alt) failed", "error", err.Error())
		return nil
	}
	return a.parsePackageList(out)
}

func (a *Agent) parseDPKGPackages() []string {
	out, err := a.safeExec("dpkg-query", []string{"-W", "-f", "${Package} ${Version}\n"})
	if err != nil {
		logger.WithComponent("agent").Warn("dpkg-query failed", "error", err.Error())
		return nil
	}
	return a.parsePackageList(out)
}

func (a *Agent) parsePacmanPackages() []string {
	out, err := a.safeExec("pacman", []string{"-Q"})
	if err != nil {
		logger.WithComponent("agent").Warn("pacman -Q failed", "error", err.Error())
		return nil
	}
	return a.parsePackageList(out)
}

func (a *Agent) parsePackageList(output string) []string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	pkgs := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			pkgs = append(pkgs, line)
		}
	}
	return pkgs
}

func (a *Agent) extractPackagesFromChecks() []string {
	keywordMap := map[string][]string{
		"ssh":       {"openssh", "ssh"},
		"openssl":   {"openssl"},
		"nginx":     {"nginx"},
		"apache":    {"apache", "httpd"},
		"php":       {"php"},
		"mysql":     {"mysql", "mariadb"},
		"postgres":  {"postgresql", "postgres"},
		"redis":     {"redis"},
		"docker":    {"docker"},
		"kernel":    {"linux-kernel"},
		"selinux":   {"selinux", "libselinux"},
		"firewall":  {"iptables", "firewalld", "nftables"},
		"fail2ban":  {"fail2ban"},
		"audit":     {"auditd", "audit"},
		"cron":      {"cronie", "crontabs"},
		"rsyslog":   {"rsyslog"},
		"suricata":  {"suricata"},
		"chrony":    {"chrony"},
		"clamav":    {"clamav"},
		"cryptsetup": {"cryptsetup"},
	}

	pkgSet := make(map[string]bool)
	for _, check := range a.checkers {
		desc := strings.ToLower(check.Description)
		name := strings.ToLower(check.Name)
		id := strings.ToLower(check.ID)
		combined := desc + " " + name + " " + id
		for keyword, pkgs := range keywordMap {
			if strings.Contains(combined, keyword) {
				for _, pkg := range pkgs {
					pkgSet[pkg] = true
				}
			}
		}
	}

	pkgs := make([]string, 0, len(pkgSet))
	for p := range pkgSet {
		pkgs = append(pkgs, p)
	}
	if len(pkgs) > 0 {
		logger.WithComponent("agent").Info("extracted packages from check results", "count", len(pkgs), "packages", strings.Join(pkgs, ","))
	}
	return pkgs
}

func (a *Agent) safeExec(name string, args []string) (string, error) {
	if !common.IsCommandAllowed(name) {
		return "", fmt.Errorf("command %s not in allowlist", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	return string(out), err
}

func (a *Agent) runChecks() []model.CheckResult {
	results := make([]model.CheckResult, len(a.checkers))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for i, check := range a.checkers {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, c model.CheckItem) {
			defer wg.Done()
			defer func() { <-sem }()

			done := make(chan model.CheckResult, 1)
			go func() {
				done <- c.Run()
			}()

			select {
			case r := <-done:
				results[idx] = r
			case <-time.After(60 * time.Second):
				results[idx] = model.CheckResult{
					CheckID: c.ID,
					Passed:  false,
					Detail:  "check timed out after 60s",
				}
			}
		}(i, check)
	}
	wg.Wait()
	return results
}

func (a *Agent) runCommand(cmd *apiv1.Command) {
	timeout := 30 * time.Second

	if !common.IsShellCommandAllowed(cmd.Command) {
		name, args, ok := common.ParseCommand(cmd.Command)
		if !ok {
			logger.WithComponent("agent").Warn("command rejected: not in allowlist", "command_id", cmd.CommandId, "command", cmd.Command)
			return
		}
		output, err := common.RunCmdTimeout(timeout, name, args...)
		if err != nil && output == "" {
			logger.WithComponent("agent").Error("command failed", "command_id", cmd.CommandId, "error", err)
		} else if output != "" {
			logger.WithComponent("agent").Info("command output", "command_id", cmd.CommandId, "output", output)
		}
		return
	}

	name, args, ok := common.ParseCommand(cmd.Command)
	if !ok {
		logger.WithComponent("agent").Warn("command rejected: failed to parse", "command_id", cmd.CommandId, "command", cmd.Command)
		return
	}
	output, err := common.RunCmdTimeout(timeout, name, args...)
	if err != nil && output == "" {
		logger.WithComponent("agent").Error("command failed", "command_id", cmd.CommandId, "error", err)
	} else if output != "" {
		logger.WithComponent("agent").Info("command output", "command_id", cmd.CommandId, "output", output)
	}
}

func (a *Agent) Stop() {
	a.running.Store(false)
	if a.client != nil {
		a.client.Close()
	}
}

func (a *Agent) IsRunning() bool {
	return a.running.Load()
}