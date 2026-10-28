package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ReporterConfig configures the node→master reporter. Zero values fall back to
// the package defaults, except MasterURL (required).
type ReporterConfig struct {
	MasterURL   string
	NodeID      string
	Token       string
	Interval    time.Duration
	Timeout     time.Duration
	MaxAttempts int
	Backoff     time.Duration
	HTTPClient  *http.Client // optional (tests / custom TLS); Timeout is set per attempt
	MaxBackoff  time.Duration
	// OnReport is called after every cycle with the final outcome (nil error =
	// sent). The plugin uses it for component-scoped logging; nil is allowed.
	OnReport func(err error, attempts int)
}

// Reporter periodically POSTs a NodeReport to the master's /federation/report.
//
// Each cycle is retried up to MaxAttempts with exponential backoff bounded by
// the cycle's timeout; a failed cycle never stops the loop (the next tick
// tries again). Stop cancels in-flight work and waits for the loop to exit.
type Reporter struct {
	cfg ReporterConfig
	// httpClient must not carry a global Timeout: each attempt derives its own
	// bounded context so retries stay independent.
	httpClient *http.Client

	stopOnce sync.Once
	stopCh   chan struct{}
	wg       sync.WaitGroup

	mu           sync.Mutex
	lastReportAt time.Time
	lastErr      error
	lastAttempts int
}

// NewReporter validates the configuration and builds a reporter.
func NewReporter(cfg ReporterConfig) (*Reporter, error) {
	if strings.TrimSpace(cfg.MasterURL) == "" {
		return nil, fmt.Errorf("federation: reporter requires master_url")
	}
	u, err := url.Parse(cfg.MasterURL)
	if err != nil {
		return nil, fmt.Errorf("federation: invalid master_url %q: %w", cfg.MasterURL, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("federation: invalid master_url %q: must be http(s)://host[:port]", cfg.MasterURL)
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Duration(DefaultReportIntervalSec) * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultRequestTimeout
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultMaxAttempts
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = DefaultRetryBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = maxRetryBackoff
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{}
	}

	return &Reporter{
		cfg:        cfg,
		httpClient: client,
		stopCh:     make(chan struct{}),
	}, nil
}

// reportURL joins the master URL with the report path (master_url may already
// carry a path prefix, e.g. http://10.0.0.1:5099/fed).
func (r *Reporter) reportURL() string {
	base := strings.TrimRight(r.cfg.MasterURL, "/")
	return base + ReportPath
}

// Report performs one report cycle: POST with up to MaxAttempts attempts,
// each bounded by Timeout, with exponential backoff in between.
func (r *Reporter) Report(ctx context.Context, report NodeReport) error {
	if report.NodeID == "" {
		report.NodeID = r.cfg.NodeID
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("federation: marshal report: %w", err)
	}

	var lastErr error
	attempts := 0
	for attempt := 1; attempt <= r.cfg.MaxAttempts; attempt++ {
		attempts = attempt
		lastErr = r.postOnce(ctx, payload)
		if lastErr == nil {
			r.record(time.Now().UTC(), nil, attempts)
			r.notify(nil, attempts)
			return nil
		}
		// A cancelled/expired parent context wins over further retries.
		if ctx.Err() != nil {
			break
		}
		if attempt < r.cfg.MaxAttempts {
			if werr := sleepBackoff(ctx, r.backoff(attempt)); werr != nil {
				break
			}
		}
	}

	r.record(time.Time{}, lastErr, attempts)
	r.notify(lastErr, attempts)
	return fmt.Errorf("federation: report to %s failed after %d attempt(s): %w",
		r.reportURL(), attempts, lastErr)
}

func (r *Reporter) notify(err error, attempts int) {
	if r.cfg.OnReport != nil {
		r.cfg.OnReport(err, attempts)
	}
}

func (r *Reporter) postOnce(ctx context.Context, payload []byte) error {
	attemptCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, r.reportURL(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if r.cfg.Token != "" {
		req.Header.Set(TokenHeader, r.cfg.Token)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return classifyHTTPError(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("master returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// classifyHTTPError keeps the timeout signal readable in logs/tests.
func classifyHTTPError(err error) error {
	if err == nil {
		return nil
	}
	if isTimeout(err) {
		return fmt.Errorf("request timeout: %w", err)
	}
	return err
}

func isTimeout(err error) bool {
	type timeoutErr interface{ Timeout() bool }
	if te, ok := err.(timeoutErr); ok && te.Timeout() {
		return true
	}
	return false
}

// backoff returns the exponential delay before the next attempt:
// Backoff, 2×Backoff, 4×Backoff … capped at MaxBackoff.
func (r *Reporter) backoff(attempt int) time.Duration {
	d := r.cfg.Backoff
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= r.cfg.MaxBackoff {
			return r.cfg.MaxBackoff
		}
	}
	if d > r.cfg.MaxBackoff {
		return r.cfg.MaxBackoff
	}
	return d
}

func sleepBackoff(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Run starts the reporting loop in the background and returns immediately
// (kernel bootstrap must not block on the network). The first report is sent
// immediately; snapshot is called once per cycle so the summary always
// reflects the current topology/scores. The loop exits on ctx cancellation or
// Stop.
func (r *Reporter) Run(ctx context.Context, snapshot func() NodeReport) {
	if snapshot == nil {
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.run(ctx, snapshot)
	}()
}

func (r *Reporter) run(ctx context.Context, snapshot func() NodeReport) {
	r.reportCycle(ctx, snapshot)

	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.reportCycle(ctx, snapshot)
		}
	}
}

// reportCycle is a single guarded cycle: a panic in snapshot must not kill the
// kernel.
func (r *Reporter) reportCycle(ctx context.Context, snapshot func() NodeReport) {
	defer func() {
		_ = recover()
	}()
	if err := r.Report(ctx, snapshot()); err != nil {
		// Report already recorded lastErr; logging is the plugin's job (it has
		// a component-scoped logger and the operator-facing state).
		_ = err
	}
}

// Stop stops the loop after the in-flight cycle and waits for it to exit.
func (r *Reporter) Stop() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() { close(r.stopCh) })
	r.wg.Wait()
}

// LastReport returns the master-clock time of the last successful report and
// the most recent error (nil after a success).
func (r *Reporter) LastReport() (time.Time, error, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastReportAt, r.lastErr, r.lastAttempts
}

func (r *Reporter) record(at time.Time, err error, attempts int) {
	r.mu.Lock()
	if err == nil {
		r.lastReportAt = at
	}
	r.lastErr = err
	r.lastAttempts = attempts
	r.mu.Unlock()
}
