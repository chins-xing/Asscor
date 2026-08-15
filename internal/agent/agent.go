package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/version"
	"syscall"
	"time"

	apiv1 "github.com/asscor/asscor/api/v1"
	"github.com/asscor/asscor/internal/checks"
	"github.com/asscor/asscor/internal/common"
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/model"
)

// ErrKernelUnreachable is returned when the agent fails to contact the kernel
// after max_retries heartbeat attempts. The Run loop should exit on this error.
var ErrKernelUnreachable = errors.New("kernel unreachable: max heartbeat retries exceeded")

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
	LogFormat        string
	LogLevel         string
	LogOutput        string
	// PrivilegedSocket is the Unix socket path of the privileged agent
	// process. When empty, root checks/commands are reported as skipped.
	PrivilegedSocket string
	// UserCheckItems are configuration-defined checks loaded from the agent
	// config file ([user_check.*] sections). They are appended to the
	// compiled-in checks at agent construction, letting administrators add or
	// adjust checks without recompiling.
	UserCheckItems []model.CheckItem
	// CheckDeltas overrides per-check Delta values by check ID, loaded from
	// the [check_deltas] section of the agent config file. Applied to both
	// builtin and user checkers at construction (kernel-side equivalent:
	// config.ini [check_deltas]).
	CheckDeltas map[string]float64
}

func DefaultConfig() AgentConfig {
	hostname, _ := os.Hostname()
	return AgentConfig{
		KernelAddr:       "localhost:50051",
		HostID:           hostname,
		Hostname:         hostname,
		Version:          version.ASSCORVersion,
		HeartbeatSec:     30,
		CheckIntervalSec: 300,
		CheckTimeoutSec:  10,
		MaxRetries:       3,
		ReconnectSec:     5,
		TLSEnabled:       true,
		TLSSkipVerify:    false,
		LogFormat:        "json",
		LogLevel:         "info",
		LogOutput:        "stderr",
		PrivilegedSocket: "/run/asscor/agent-priv.sock",
	}
}

type Agent struct {
	cfg               AgentConfig
	client            *Client
	sessionID         string
	running           atomic.Bool
	checkers          []model.CheckItem
	checkCount        int
	pendingCmd        []*apiv1.Command
	lastCheckTime     time.Time
	hmacKeyConfigured bool
	hmacKeyWarned     atomic.Bool
	cachedPackages    []string
	pkgHash           [32]byte
	cpeHash           [32]byte
	pkgSent           bool // true after first full packages send
	cpeSent           bool // true after first full CPE send
	privClient        *PrivilegedClient
	// syncedChecks holds checks pushed from the kernel via heartbeat
	// (config.ini [user_check.*]). syncedCfgVersion fingerprints the last
	// applied sync so unchanged config is skipped. cfgMu guards checkers
	// replacement when a synced config arrives mid-cycle.
	syncedChecks     []model.CheckItem
	syncedCfgVersion string
	cfgMu            sync.Mutex
}

// buildAgentCheckers assembles the agent's check set: compiled-in normal
// checks + local user checks ([user_check.*] in agent.ini) + synced checks
// (pushed from the kernel), then applies local [check_deltas] overrides.
func buildAgentCheckers(cfg AgentConfig, synced []model.CheckItem) []model.CheckItem {
	all := checks.GetNormal()
	all = append(all, cfg.UserCheckItems...)
	all = append(all, synced...)

	if len(cfg.CheckDeltas) > 0 {
		for i := range all {
			if d, ok := cfg.CheckDeltas[all[i].ID]; ok {
				all[i].Delta = d
			}
		}
	}
	return all
}

// applySyncedCheckConfig applies check-item configuration synced from the
// kernel (config.ini [user_check.*] + [check_deltas]) to the live checkers.
// It is a no-op for nil config, empty version, or an unchanged version.
func (a *Agent) applySyncedCheckConfig(cc *apiv1.AgentCheckConfig) {
	if cc == nil || cc.Version == "" {
		return
	}
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	if cc.Version == a.syncedCfgVersion {
		return
	}

	var synced []model.CheckItem
	if len(cc.UserChecks) > 0 {
		synced = config.ParseUserChecks(cc.UserChecks)
	}

	// Extend the execution allowlist with kernel-synced commands (idempotent).
	// The built-in 25-command baseline is never removed; the kernel only
	// augments it centrally so agents cannot locally alter it.
	if len(cc.AllowedCommands) > 0 {
		common.AddAllowedCommands(cc.AllowedCommands...)
	}

	a.syncedChecks = synced
	a.checkers = buildAgentCheckers(a.cfg, synced)
	if len(cc.CheckDeltas) > 0 {
		for i := range a.checkers {
			if d, ok := cc.CheckDeltas[a.checkers[i].ID]; ok {
				a.checkers[i].Delta = d
			}
		}
	}
	a.syncedCfgVersion = cc.Version

	logger.WithComponent("agent").Info("applied synced check config from kernel",
		"version", cc.Version, "user_checks", len(synced), "delta_overrides", len(cc.CheckDeltas), "allowed_commands", len(cc.AllowedCommands), "total_checks", len(a.checkers))
}

func NewAgent(cfg AgentConfig) *Agent {
	common.DefaultTimeout = time.Duration(cfg.CheckTimeoutSec) * time.Second

	allChecks := buildAgentCheckers(cfg, nil)
	logger.WithComponent("agent").Info("loaded non-root platform checks", "count", len(allChecks), "os", runtime.GOOS, "arch", runtime.GOARCH, "user_checks", len(cfg.UserCheckItems), "delta_overrides", len(cfg.CheckDeltas))

	hmacKeyConfigured := cfg.HMACKey != "" || os.Getenv("ASSCOR_HMAC_KEY") != ""
	if !hmacKeyConfigured {
		logger.WithComponent("agent").Warn("HMAC key not configured, remote commands will be rejected")
	}

	return &Agent{
		cfg:               cfg,
		checkers:          allChecks,
		checkCount:        len(allChecks),
		hmacKeyConfigured: hmacKeyConfigured,
		privClient:        NewPrivilegedClient(cfg.PrivilegedSocket),
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
		defer func() {
			if r := recover(); r != nil {
				logger.WithComponent("agent").Error("signal handler panic", "panic", r)
			}
		}()
		<-sigCh
		logger.WithComponent("agent").Info("received shutdown signal")
		cancel()
	}()

	for a.running.Load() {
		if err := a.runOnce(ctx); err != nil {
			if errors.Is(err, ErrKernelUnreachable) {
				logger.WithComponent("agent").Info("kernel unreachable after max retries, shutting down")
				return nil
			}
			logger.WithComponent("agent").Error("session error", "error", err)
			a.sessionID = ""
			// Reset incremental-send state so a reconnection (e.g. after kernel
			// restart cleared in-memory SPC assets) re-sends the full package/CPE
			// list rather than incorrectly skipping it as "unchanged".
			a.pkgSent = false
			a.cpeSent = false
			a.pkgHash = [32]byte{}
			a.cpeHash = [32]byte{}
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
					return ErrKernelUnreachable
				}
				backoff := time.Duration(a.cfg.HeartbeatSec) * time.Second * time.Duration(1<<uint(consecutiveErrors-1))
				if backoff > 60*time.Second {
					backoff = 60 * time.Second
				}
				logger.WithComponent("agent").Info("retrying with backoff", "backoff", backoff)
				timer.Reset(backoff)
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
				Source:        string(r.Source),
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
	}
	heartbeatReq.NetworkInfo = a.collectNetworkInfo()
	if pkgs := a.collectPackages(); pkgs != nil {
		h := sha256.Sum256([]byte(strings.Join(pkgs, ",")))
		if !a.pkgSent || h != a.pkgHash {
			heartbeatReq.Packages = pkgs
			a.pkgHash = h
			a.pkgSent = true
		}
	}
	if cpes := a.collectCPEs(); cpes != nil {
		h2 := sha256.Sum256([]byte(strings.Join(cpes, ",")))
		if !a.cpeSent || h2 != a.cpeHash {
			heartbeatReq.InstalledCPEs = cpes
			a.cpeHash = h2
			a.cpeSent = true
		}
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

	// Apply check-item configuration synced from the kernel (config.ini
	// [user_check.*] + [check_deltas]). The kernel config file is the primary
	// source of truth for check definitions; unchanged versions are skipped.
	if heartbeatResp.CheckConfig != nil {
		a.applySyncedCheckConfig(heartbeatResp.CheckConfig)
	}

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
			// Mark configuration-defined checks so operators can tell them
			// apart from the builtin platform checks at a glance.
			tag := ""
			if c.Source == "user" {
				tag = " [user]"
			}
			if c.Detail != "" {
				fmt.Printf("  [%s]%s %s : %s (%s)\n", status, tag, c.CheckId, c.Name, c.Detail)
			} else {
				fmt.Printf("  [%s]%s %s : %s\n", status, tag, c.CheckId, c.Name)
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

	if len(result.ATTACKCoverage) > 0 || result.ATTACKKillChain != nil || len(result.ATTACKAPTMatches) > 0 {
		fmt.Println()
		fmt.Println("===============================================================")
		fmt.Println("[ ATT&CK Analysis ]")
		fmt.Println("===============================================================")

		if len(result.ATTACKCoverage) > 0 {
			fmt.Println()
			fmt.Println("--- ATT&CK Coverage ---")
			for _, cov := range result.ATTACKCoverage {
				bar := ""
				filled := int(cov.CoverageDet / 10)
				for i := 0; i < 10; i++ {
					if i < filled {
						bar += "="
					} else {
						bar += " "
					}
				}
				fmt.Printf("  %-20s [%s] %d/%d (%.0f%%)\n",
					cov.TacticName, bar, cov.CoveredDet, cov.TotalTechniques, cov.CoverageDet)
			}
		}

		if result.ATTACKKillChain != nil {
			fmt.Println()
			fmt.Println("--- Kill Chain Assessment ---")
			fmt.Printf("  Overall Score: %.0f/100\n", result.ATTACKKillChain.OverallScore)
			fmt.Printf("  Weakest Stage: %s\n", result.ATTACKKillChain.WeakestStage)
			for _, stage := range result.ATTACKKillChain.Stages {
				bar := ""
				filled := int(stage.Score / 10)
				for i := 0; i < 10; i++ {
					if i < filled {
						bar += "="
					} else {
						bar += " "
					}
				}
				marker := "  "
				if stage.Name == result.ATTACKKillChain.WeakestStage {
					marker = " *"
				}
				fmt.Printf("%s %-20s [%s] %.0f (%s)\n",
					marker, stage.Name, bar, stage.Score, stage.Status)
			}
		}

		if len(result.ATTACKAPTMatches) > 0 {
			fmt.Println()
			fmt.Println("--- APT Group Matches ---")
			for _, apt := range result.ATTACKAPTMatches {
				fmt.Printf("  %s (%s): %.0f%% [%s]\n",
					apt.GroupName, apt.GroupID, apt.Similarity*100, apt.Confidence)
				if len(apt.OverlapTech) > 0 {
					fmt.Printf("    Overlap: %v\n", apt.OverlapTech)
				}
			}
		}

		if result.ATTACKPredictedRisk != nil {
			fmt.Println()
			fmt.Println("--- Predicted Risk ---")
			fmt.Printf("  Max Risk Score: %.2f\n", result.ATTACKPredictedRisk.MaxRiskScore)
			fmt.Printf("  Enhanced Threat Coeff: %.2f\n", result.ATTACKPredictedRisk.EnhancedThreat)
			fmt.Printf("  Predicted Paths: %d\n", result.ATTACKPredictedRisk.PredictedPaths)
			if len(result.ATTACKPredictedRisk.Recommendations) > 0 {
				fmt.Println("  Recommendations:")
				for _, rec := range result.ATTACKPredictedRisk.Recommendations {
					fmt.Printf("    - %s\n", rec)
				}
			}
		}

		if len(result.ATTACKFailedTechs) > 0 {
			fmt.Println()
			fmt.Println("--- Failed Techniques ---")
			for _, tech := range result.ATTACKFailedTechs {
				fmt.Printf("  - %s\n", tech)
			}
		}
		fmt.Println("---------------------------------------------------------------")
	}

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
		hmacKey = os.Getenv("ASSCOR_HMAC_KEY")
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

	if !hmac.Equal(cmd.Signature, expected) {
		return false
	}

	if ts, ok := cmd.Params["_timestamp"]; ok {
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil || time.Since(t) > 5*time.Minute {
			logger.WithComponent("agent").Warn("command rejected: expired or invalid timestamp", "command_id", cmd.CommandId, "age", time.Since(t))
			return false
		}
	} else if len(cmd.Signature) > 0 {
		return false
	}

	return true
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
		"ssh":        {"openssh", "ssh"},
		"openssl":    {"openssl"},
		"nginx":      {"nginx"},
		"apache":     {"apache", "httpd"},
		"php":        {"php"},
		"mysql":      {"mysql", "mariadb"},
		"postgres":   {"postgresql", "postgres"},
		"redis":      {"redis"},
		"docker":     {"docker"},
		"kernel":     {"linux-kernel"},
		"selinux":    {"selinux", "libselinux"},
		"firewall":   {"iptables", "firewalld", "nftables"},
		"fail2ban":   {"fail2ban"},
		"audit":      {"auditd", "audit"},
		"cron":       {"cronie", "crontabs"},
		"rsyslog":    {"rsyslog"},
		"suricata":   {"suricata"},
		"chrony":     {"chrony"},
		"clamav":     {"clamav"},
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
	return common.RunCmdTimeout(30*time.Second, name, args...)
}

func (a *Agent) collectCPEs() []string {
	if a.cachedPackages == nil {
		return nil
	}
	cpes := generateCPEsFromPackages(a.cachedPackages)
	logger.WithComponent("agent").Info("generated CPEs from packages", "cpes", len(cpes), "packages", len(a.cachedPackages))
	return cpes
}

// collectNetworkInfo gathers the agent's network topology data using the
// standard library (no external commands). This enables real-edge risk
// diffusion in SRD instead of a synthetic complete graph.
func (a *Agent) collectNetworkInfo() *apiv1.NetworkInfo {
	info := &apiv1.NetworkInfo{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return info
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			var ipNet *net.IPNet
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				ipNet = v
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.To4() == nil {
				continue
			}
			info.LocalIPs = append(info.LocalIPs, ip.String())
			if ipNet != nil {
				info.Subnets = append(info.Subnets, ipNet.String())
			}
		}
	}
	info.NetworkZone = a.inferZone(info.LocalIPs)
	return info
}

// inferZone classifies the agent's network zone based on IP address ranges.
func (a *Agent) inferZone(ips []string) string {
	hasPrivate := false
	hasPublic := false
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.IsPrivate() || ip.IsLoopback() {
			hasPrivate = true
		} else {
			hasPublic = true
		}
	}
	switch {
	case hasPublic && hasPrivate:
		return "dmz"
	case hasPublic:
		return "public"
	default:
		return "internal"
	}
}

func generateCPEsFromPackages(packages []string) []string {
	cpes := make([]string, 0, len(packages))
	seen := make(map[string]bool, len(packages))

	for _, pkg := range packages {
		name, version := splitPkgNameVersion(pkg)
		if name == "" {
			continue
		}

		vendorProduct := lookupVendorProduct(name)
		if vendorProduct == nil {
			continue
		}

		cpeStr := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendorProduct.vendor, vendorProduct.product, version)
		if !seen[cpeStr] {
			seen[cpeStr] = true
			cpes = append(cpes, cpeStr)
		}
	}

	return cpes
}

type vendorProductEntry struct {
	vendor  string
	product string
}

func splitPkgNameVersion(pkg string) (string, string) {
	pkg = strings.TrimSpace(pkg)
	if pkg == "" {
		return "", ""
	}

	spaceIdx := strings.IndexByte(pkg, ' ')
	if spaceIdx > 0 {
		name := pkg[:spaceIdx]
		version := pkg[spaceIdx+1:]
		version = strings.TrimSpace(version)
		if dashIdx := strings.IndexByte(version, '-'); dashIdx > 0 {
			version = version[:dashIdx]
		}
		return name, version
	}

	dashIdx := strings.IndexByte(pkg, '-')
	if dashIdx < 0 {
		return pkg, "*"
	}

	hasDigit := false
	for i := dashIdx + 1; i < len(pkg); i++ {
		if pkg[i] >= '0' && pkg[i] <= '9' {
			hasDigit = true
			break
		}
	}

	if !hasDigit {
		return pkg, "*"
	}

	name := pkg[:dashIdx]
	verPart := pkg[dashIdx+1:]
	if relIdx := strings.IndexByte(verPart, '-'); relIdx > 0 {
		verPart = verPart[:relIdx]
	}
	if dotIdx := strings.LastIndex(verPart, "."); dotIdx > 0 {
		arch := verPart[dotIdx+1:]
		if arch == "x86_64" || arch == "amd64" || arch == "aarch64" || arch == "arm64" || arch == "i686" || arch == "i386" || arch == "noarch" || arch == "all" {
			verPart = verPart[:dotIdx]
		}
	}
	return name, verPart
}

func lookupVendorProduct(pkgName string) *vendorProductEntry {
	coreName := pkgName
	suffixes := []string{
		"-libs", "-devel", "-static", "-doc", "-debuginfo", "-debugsource",
		"-common", "-utils", "-tools", "-plugins", "-module", "-modules",
		"-daemon", "-server", "-client", "-cli", "-bin", "-data", "-lang",
		"-help", "-license", "-logrotate", "-sysconfig", "-config", "-conf",
		"-headers", "-dev", "-perl", "-python", "-python3", "-ruby",
		"-java", "-jni", "-bash", "-zsh", "-fish", "-tcsh",
		"-compat", "-legacy", "-minimal", "-full", "-core", "-base",
	}
	for _, s := range suffixes {
		if strings.HasSuffix(coreName, s) {
			coreName = coreName[:len(coreName)-len(s)]
			break
		}
	}

	if entry, ok := cpeVendorMap[coreName]; ok {
		return entry
	}
	if entry, ok := cpeVendorMap[pkgName]; ok {
		return entry
	}
	return nil
}

var cpeVendorMap = map[string]*vendorProductEntry{
	"openssl":         {vendor: "openssl", product: "openssl"},
	"openssh":         {vendor: "openbsd", product: "openssh"},
	"ssh":             {vendor: "openbsd", product: "openssh"},
	"nginx":           {vendor: "nginx", product: "nginx"},
	"httpd":           {vendor: "apache", product: "http_server"},
	"apache2":         {vendor: "apache", product: "http_server"},
	"php":             {vendor: "php", product: "php"},
	"mysql":           {vendor: "oracle", product: "mysql"},
	"mariadb":         {vendor: "mariadb", product: "mariadb"},
	"postgresql":      {vendor: "postgresql", product: "postgresql"},
	"postgres":        {vendor: "postgresql", product: "postgresql"},
	"redis":           {vendor: "redis", product: "redis"},
	"docker":          {vendor: "docker", product: "docker"},
	"docker-ce":       {vendor: "docker", product: "docker"},
	"containerd":      {vendor: "containerd", product: "containerd"},
	"runc":            {vendor: "opencontainers", product: "runc"},
	"kernel":          {vendor: "linux", product: "linux_kernel"},
	"kernel-core":     {vendor: "linux", product: "linux_kernel"},
	"glibc":           {vendor: "gnu", product: "glibc"},
	"glibc-minimal":   {vendor: "gnu", product: "glibc"},
	"systemd":         {vendor: "systemd", product: "systemd"},
	"sudo":            {vendor: "sudo", product: "sudo"},
	"curl":            {vendor: "haxx", product: "curl"},
	"wget":            {vendor: "gnu", product: "wget"},
	"bind":            {vendor: "isc", product: "bind"},
	"bind-utils":      {vendor: "isc", product: "bind"},
	"vsftpd":          {vendor: "vsftpd", product: "vsftpd"},
	"proftpd":         {vendor: "proftpd", product: "proftpd"},
	"postfix":         {vendor: "postfix", product: "postfix"},
	"dovecot":         {vendor: "dovecot", product: "dovecot"},
	"samba":           {vendor: "samba", product: "samba"},
	"libcurl":         {vendor: "haxx", product: "curl"},
	"libxml2":         {vendor: "xmlsoft", product: "libxml2"},
	"libpng":          {vendor: "libpng", product: "libpng"},
	"libjpeg":         {vendor: "ijg", product: "libjpeg"},
	"libtiff":         {vendor: "libtiff", product: "libtiff"},
	"zlib":            {vendor: "zlib", product: "zlib"},
	"openssl-libs":    {vendor: "openssl", product: "openssl"},
	"openssh-server":  {vendor: "openbsd", product: "openssh"},
	"openssh-clients": {vendor: "openbsd", product: "openssh"},
	"java":            {vendor: "oracle", product: "jdk"},
	"java-11":         {vendor: "oracle", product: "jdk"},
	"java-17":         {vendor: "oracle", product: "jdk"},
	"java-21":         {vendor: "oracle", product: "jdk"},
	"tomcat":          {vendor: "apache", product: "tomcat"},
	"nodejs":          {vendor: "nodejs", product: "node.js"},
	"python3":         {vendor: "python", product: "python"},
	"python":          {vendor: "python", product: "python"},
	"perl":            {vendor: "perl", product: "perl"},
	"ruby":            {vendor: "ruby", product: "ruby"},
	"go":              {vendor: "golang", product: "go"},
	"git":             {vendor: "git-scm", product: "git"},
	"xz":              {vendor: "tukaani", product: "xz"},
	"xz-libs":         {vendor: "tukaani", product: "xz"},
	"zstd":            {vendor: "facebook", product: "zstd"},
	"libssh2":         {vendor: "libssh2", product: "libssh2"},
	"libssh":          {vendor: "libssh", product: "libssh"},
	"krb5-libs":       {vendor: "mit", product: "kerberos"},
	"krb5":            {vendor: "mit", product: "kerberos"},
	"pam":             {vendor: "linux-pam", product: "linux-pam"},
	"shadow-utils":    {vendor: "shadow", product: "shadow"},
	"cryptsetup":      {vendor: "cryptsetup", product: "cryptsetup"},
	"grub2":           {vendor: "gnu", product: "grub"},
	"firewalld":       {vendor: "firewalld", product: "firewalld"},
	"iptables":        {vendor: "netfilter", product: "iptables"},
	"nftables":        {vendor: "netfilter", product: "nftables"},
	"fail2ban":        {vendor: "fail2ban", product: "fail2ban"},
	"audit":           {vendor: "linux-audit", product: "audit"},
	"auditd":          {vendor: "linux-audit", product: "audit"},
	"rsyslog":         {vendor: "rsyslog", product: "rsyslog"},
	"chrony":          {vendor: "chrony", product: "chrony"},
	"clamav":          {vendor: "clamav", product: "clamav"},
	"suricata":        {vendor: "oisf", product: "suricata"},
	"libselinux":      {vendor: "selinuxproject", product: "libselinux"},
	"selinux-policy":  {vendor: "selinuxproject", product: "selinux_policy"},
	"expat":           {vendor: "libexpat", product: "expat"},
	"sqlite":          {vendor: "sqlite", product: "sqlite"},
	"openldap":        {vendor: "openldap", product: "openldap"},
	"net-snmp":        {vendor: "net-snmp", product: "net-snmp"},
	"haproxy":         {vendor: "haproxy", product: "haproxy"},
	"memcached":       {vendor: "memcached", product: "memcached"},
	"varnish":         {vendor: "varnish-cache", product: "varnish"},
	"grafana":         {vendor: "grafana", product: "grafana"},
	"prometheus":      {vendor: "prometheus", product: "prometheus"},
	"elasticsearch":   {vendor: "elastic", product: "elasticsearch"},
	"logstash":        {vendor: "elastic", product: "logstash"},
	"kibana":          {vendor: "elastic", product: "kibana"},
	"mongodb":         {vendor: "mongodb", product: "mongodb"},
	"rabbitmq":        {vendor: "rabbitmq", product: "rabbitmq"},
	"kafka":           {vendor: "apache", product: "kafka"},
	"zookeeper":       {vendor: "apache", product: "zookeeper"},
	"nginx-mod":       {vendor: "nginx", product: "nginx"},
	"nginx-core":      {vendor: "nginx", product: "nginx"},
	"coreutils":       {vendor: "gnu", product: "coreutils"},
	"bash":            {vendor: "gnu", product: "bash"},
	"tar":             {vendor: "gnu", product: "tar"},
	"grep":            {vendor: "gnu", product: "grep"},
	"sed":             {vendor: "gnu", product: "sed"},
	"findutils":       {vendor: "gnu", product: "findutils"},
	"binutils":        {vendor: "gnu", product: "binutils"},
	"cpio":            {vendor: "gnu", product: "cpio"},
	"patch":           {vendor: "gnu", product: "patch"},
	"crontabs":        {vendor: "cronie", product: "cronie"},
	"cronie":          {vendor: "cronie", product: "cronie"},
	"polkit":          {vendor: "freedesktop", product: "polkit"},
	"dbus":            {vendor: "freedesktop", product: "dbus"},
	"networkmanager":  {vendor: "freedesktop", product: "networkmanager"},
}

// checkConcurrency bounds the number of concurrently executing normal checks.
const checkConcurrency = 10

// runChecks executes all normal-privilege checks concurrently (bounded by
// checkConcurrency workers), each under a hard per-check timeout derived from
// cfg.CheckTimeoutSec, then appends root-privilege check results delegated to
// the privileged agent. Results are returned in checker order.
func (a *Agent) runChecks() []model.CheckResult {
	results := make([]model.CheckResult, len(a.checkers))
	if len(a.checkers) == 0 {
		return append(results, a.runRootChecks()...)
	}

	timeout := a.checkTimeout()

	var wg sync.WaitGroup
	sem := make(chan struct{}, checkConcurrency)
	for i, check := range a.checkers {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, c model.CheckItem) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = a.runCheckWithTimeout(c, timeout)
		}(i, check)
	}
	wg.Wait()

	// Root-privilege checks are delegated to the privileged agent process.
	// If it is unavailable (e.g. not yet socket-activated by the kernel),
	// report those checks as skipped instead of silently dropping them.
	results = append(results, a.runRootChecks()...)

	return results
}

// checkTimeout returns the per-check hard timeout, defaulting to 60s when the
// configured CheckTimeoutSec is unset (zero).
func (a *Agent) checkTimeout() time.Duration {
	if a.cfg.CheckTimeoutSec > 0 {
		return time.Duration(a.cfg.CheckTimeoutSec) * time.Second
	}
	return 60 * time.Second
}

// runCheckWithTimeout executes one check under a hard timeout and returns a
// fully-populated result. On timeout the result retains the check's
// Domain/Delta/Name/ComplianceRef so the kernel still receives complete
// scoring metadata instead of a bare failure with no domain attribution.
func (a *Agent) runCheckWithTimeout(c model.CheckItem, timeout time.Duration) model.CheckResult {
	done := make(chan model.CheckResult, 1)
	go func() {
		done <- c.Run()
	}()
	select {
	case r := <-done:
		return r
	case <-time.After(timeout):
		logger.WithComponent("agent").Warn("check timed out", "check_id", c.ID, "timeout", timeout.String())
		return model.CheckResult{
			CheckID:       c.ID,
			Domain:        c.Domain,
			Name:          c.Name,
			Passed:        false,
			Delta:         c.Delta,
			Detail:        fmt.Sprintf("check timed out after %s", timeout),
			ComplianceRef: c.ComplianceRef,
		}
	}
}

// runRootChecks delegates root-privilege checks to the privileged agent
// process. On failure it returns "skipped" results so the kernel still sees
// full check coverage without penalizing the host.
func (a *Agent) runRootChecks() []model.CheckResult {
	rootChecks := checks.GetRoot()
	if len(rootChecks) == 0 {
		return nil
	}

	if a.privClient != nil {
		if res := a.privClient.RunRootChecks(); res != nil {
			logger.WithComponent("agent").Info("received root check results from privileged agent", "count", len(res))
			return res
		}
	}

	results := make([]model.CheckResult, 0, len(rootChecks))
	for _, c := range rootChecks {
		results = append(results, model.CheckResult{
			CheckID:       c.ID,
			Domain:        c.Domain,
			Name:          c.Name,
			Passed:        true,
			Delta:         0,
			Detail:        "skipped — privileged agent unavailable",
			ComplianceRef: c.ComplianceRef,
		})
	}
	return results
}

func (a *Agent) runCommand(cmd *apiv1.Command) {
	// Root-required logical actions (isolate_host/deisolate_host) are delegated
	// to the privileged agent process — the non-root main agent cannot modify
	// firewall rules itself.
	switch cmd.Command {
	case "isolate_host", "deisolate_host":
		a.delegateRootCommand(cmd)
		return
	}

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
			logger.WithComponent("agent").Info("command output", "command_id", cmd.CommandId, "output", truncateCommandOutput(output))
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
		logger.WithComponent("agent").Info("command output", "command_id", cmd.CommandId, "output", truncateCommandOutput(output))
	}
}

// delegateRootCommand forwards a root-required command (isolate_host /
// deisolate_host) to the privileged agent process over the Unix socket.
// The main agent never executes these itself.
func (a *Agent) delegateRootCommand(cmd *apiv1.Command) {
	if a.privClient == nil {
		logger.WithComponent("agent").Error("privileged agent unavailable",
			"command_id", cmd.CommandId, "command", cmd.Command)
		return
	}
	output, err := a.privClient.RunRootCommand(cmd.Command, cmd.Params)
	if err != nil {
		logger.WithComponent("agent").Error("privileged command failed",
			"command_id", cmd.CommandId, "command", cmd.Command, "error", err)
		return
	}
	logger.WithComponent("agent").Info("privileged command executed",
		"command_id", cmd.CommandId, "command", cmd.Command, "output", truncateCommandOutput(output))
}

// truncateCommandOutput truncates command output to a bounded length for safe
// logging. Command output (e.g. "ps aux", "ss -tlnp") may contain sensitive
// system information; truncation prevents unbounded/sensitive data persisting
// to logs while retaining enough context for diagnostics.
func truncateCommandOutput(output string) string {
	const maxLogOutput = 512
	if len(output) <= maxLogOutput {
		return output
	}
	return output[:maxLogOutput] + "... (truncated)"
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
