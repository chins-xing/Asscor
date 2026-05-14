package agent

import (
	"context"
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
}

func DefaultConfig() AgentConfig {
	hostname, _ := os.Hostname()
	return AgentConfig{
		KernelAddr:       "localhost:8443",
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

	ticker := time.NewTicker(time.Duration(a.cfg.HeartbeatSec) * time.Second)
	defer ticker.Stop()

	consecutiveErrors := 0

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := a.heartbeatCycle(); err != nil {
				consecutiveErrors++
				log.Printf("agent: cycle error (%d/%d): %v",
					consecutiveErrors, a.cfg.MaxRetries, err)
				if consecutiveErrors >= a.cfg.MaxRetries {
					return fmt.Errorf("max retries exceeded: %w", err)
				}
				continue
			}
			consecutiveErrors = 0
		}
	}
}

func (a *Agent) connect() error {
	a.client = NewClient(a.cfg.KernelAddr, nil)
	if err := a.client.Connect(); err != nil {
		a.client = nil
		return err
	}
	log.Printf("agent: connected to kernel at %s", a.cfg.KernelAddr)
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

	var snapshot *apiv1.AssessmentResult

	if shouldCheck {
		results := a.runChecks()

		passed := 0
		failed := 0
		checkResults := make([]*apiv1.CheckResult, 0, len(results))
		for _, r := range results {
			cr := &apiv1.CheckResult{
				CheckId: r.CheckID,
				Domain:  r.Domain,
				Passed:  r.Passed,
				Delta:   r.Delta,
				Detail:  r.Detail,
			}
			checkResults = append(checkResults, cr)
			if r.Passed {
				passed++
			} else {
				failed++
			}
		}

		score := 0.0
		if a.checkCount > 0 {
			score = float64(passed) / float64(a.checkCount) * 100.0
		}

		snapshot = &apiv1.AssessmentResult{
			FinalScore: score,
			Acceptable: score >= 80.0,
			DomainScores: map[string]float64{
				"total_passed": float64(passed),
				"total_failed": float64(failed),
			},
			Checks: checkResults,
		}

		a.lastCheckTime = time.Now()

		log.Printf("agent: assessment complete — %d/%d (%.1f%%) %s, next check in %s",
			passed, a.checkCount, score,
			map[bool]string{true: "ACCEPTABLE", false: "FAILED"}[score >= 80.0],
			time.Duration(a.cfg.CheckIntervalSec)*time.Second)
	} else {
		remaining := interval - elapsed
		if remaining.Seconds() <= 60 || int(remaining.Seconds())%60 == 0 {
			log.Printf("agent: next assessment in %s", remaining.Round(time.Second))
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

	return nil
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