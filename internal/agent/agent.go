package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync/atomic"
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
}

func DefaultConfig() AgentConfig {
	hostname, _ := os.Hostname()
	return AgentConfig{
		KernelAddr:       "localhost:50051",
		HostID:           hostname,
		Hostname:         hostname,
		Version:          "1.2.0",
		HeartbeatSec:     2,
		CheckIntervalSec: 3600,
		CheckTimeoutSec:  10,
		MaxRetries:       3,
		ReconnectSec:     5,
		TLSEnabled:       false,
		TLSSkipVerify:    false,
	}
}

type Agent struct {
	cfg           AgentConfig
	client        *Client
	sessionID     string
	running       atomic.Bool
	checkers      []model.CheckItem
	checkCount    int
	pendingCmd    []*apiv1.Command
	lastCheckTime time.Time
}

func NewAgent(cfg AgentConfig) *Agent {
	common.DefaultTimeout = time.Duration(cfg.CheckTimeoutSec) * time.Second

	allChecks := checks.GetAll()
	log.Printf("agent: loaded %d platform checks for %s/%s", len(allChecks), runtime.GOOS, runtime.GOARCH)

	return &Agent{
		cfg:        cfg,
		checkers:   allChecks,
		checkCount: len(allChecks),
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
		log.Println("agent: received shutdown signal")
		cancel()
	}()

	for a.running.Load() {
		if err := a.runOnce(ctx); err != nil {
			log.Printf("agent: session error: %v", err)
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
				log.Printf("agent: cycle error (%d/%d): %v",
					consecutiveErrors, a.cfg.MaxRetries, err)
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

		caCert, err := os.ReadFile(certDir + "/ca.crt")
		if err != nil {
			return fmt.Errorf("读取CA证书: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("解析CA证书失败")
		}

		agentCert, err := tls.LoadX509KeyPair(certDir+"/agent.crt", certDir+"/agent.key")
		if err != nil {
			return fmt.Errorf("加载Agent证书: %w", err)
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{agentCert},
			RootCAs:      caPool,
			ServerName:   "localhost",
			MinVersion:   tls.VersionTLS12,
		}
	}

	a.client = NewClient(a.cfg.KernelAddr, tlsConfig)
	if err := a.client.Connect(); err != nil {
		a.client = nil
		return err
	}
	log.Printf("agent: connected to kernel at %s (mTLS: %v)", a.cfg.KernelAddr, a.cfg.TLSEnabled)
	return nil
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
	log.Printf("agent: registered — session=%s", a.sessionID)
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
			log.Printf("agent: next assessment in %s", remaining.Round(time.Second))
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

	heartbeatResp, err := a.client.Heartbeat(heartbeatReq)
	if err != nil {
		return err
	}

	if !heartbeatResp.Ok {
		log.Printf("agent: heartbeat not ok, re-registering")
		a.sessionID = ""
		return nil
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
	fmt.Printf("  Final Score: %.2f/100    Threshold: 80.00    Status: %s\n", result.FinalScore, status)
	fmt.Printf("  Threat Coeff: %.2f    SPC Score: %.2f\n", threatCoeff, spcScore)
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
	log.Printf("agent: assessment complete — %d/%d (%.1f%%) %s, next check in %s",
		passed, total, passRate,
		map[bool]string{true: "ACCEPTABLE", false: "FAILED"}[result.Acceptable],
		time.Duration(a.cfg.CheckIntervalSec)*time.Second)
}

func (a *Agent) executePendingCommands() {
	if len(a.pendingCmd) == 0 {
		return
	}

	log.Printf("agent: executing %d pending commands", len(a.pendingCmd))
	for _, cmd := range a.pendingCmd {
		log.Printf("agent: exec [%s]: %s", cmd.CommandId, cmd.Command)
		a.runCommand(cmd)
	}
	a.pendingCmd = nil
}

func (a *Agent) runChecks() []model.CheckResult {
	results := make([]model.CheckResult, 0, len(a.checkers))
	for _, check := range a.checkers {
		result := check.Run()
		results = append(results, result)
	}
	return results
}

func (a *Agent) runCommand(cmd *apiv1.Command) {
	timeout := 30 * time.Second

	shell := "sh"
	shellFlag := "-c"
	if runtime.GOOS == "windows" {
		shell = "cmd"
		shellFlag = "/c"
	}

	output, err := common.RunCmdTimeout(timeout, shell, shellFlag, cmd.Command)
	if err != nil && output == "" {
		log.Printf("agent: command [%s] failed: %v", cmd.CommandId, err)
	} else if output != "" {
		log.Printf("agent: command [%s] output: %s", cmd.CommandId, output)
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