package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReporterRetriesUntilSuccess(t *testing.T) {
	var attempts int32
	var lastToken atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		lastToken.Store(r.Header.Get(TokenHeader))
		if n < 3 {
			http.Error(w, "master warming up", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	reporter, err := NewReporter(ReporterConfig{
		MasterURL:   srv.URL,
		NodeID:      "nk1",
		Token:       "demo-token",
		Timeout:     time.Second,
		MaxAttempts: 3,
		Backoff:     time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	if err := reporter.Report(context.Background(), NodeReport{NodeID: "nk1", Hosts: 2}); err != nil {
		t.Fatalf("Report should succeed on the 3rd attempt: %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
	if lastToken.Load().(string) != "demo-token" {
		t.Errorf("token header = %q, want demo-token", lastToken.Load())
	}
	last, err, attemptsSeen := reporter.LastReport()
	if err != nil {
		t.Errorf("LastReport error = %v, want nil after success", err)
	}
	if last.IsZero() {
		t.Error("LastReport time is zero after success")
	}
	if attemptsSeen != 3 {
		t.Errorf("LastReport attempts = %d, want 3", attemptsSeen)
	}
}

func TestReporterGivesUpAfterMaxAttempts(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		http.Error(w, "always down", http.StatusBadGateway)
	}))
	defer srv.Close()

	reporter, err := NewReporter(ReporterConfig{
		MasterURL:   srv.URL,
		NodeID:      "nk1",
		MaxAttempts: 3,
		Timeout:     time.Second,
		Backoff:     time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	err = reporter.Report(context.Background(), NodeReport{NodeID: "nk1"})
	if err == nil {
		t.Fatal("Report should fail when the master never accepts")
	}
	if !strings.Contains(err.Error(), "3 attempt") {
		t.Errorf("error = %v, want it to mention the attempt budget", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
	_, lastErr, _ := reporter.LastReport()
	if lastErr == nil {
		t.Error("LastReport should record the failure")
	}
}

func TestReporterTimesOut(t *testing.T) {
	var attempts int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		select {
		case <-release:
		case <-time.After(3 * time.Second):
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(release)

	reporter, err := NewReporter(ReporterConfig{
		MasterURL:   srv.URL,
		NodeID:      "nk1",
		MaxAttempts: 2,
		Timeout:     20 * time.Millisecond,
		Backoff:     time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	start := time.Now()
	err = reporter.Report(context.Background(), NodeReport{NodeID: "nk1"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Report should time out against a stalled master")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Report took %s, want it bounded by the per-attempt timeout", elapsed)
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Errorf("attempts = %d, want 2 (retries respect the timeout)", got)
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("error = %v, want it classified as a timeout", err)
	}
}

func TestReporterRunPostsImmediatelyAndStops(t *testing.T) {
	var attempts int32
	reportCh := make(chan NodeReport, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		var rep NodeReport
		_ = json.NewDecoder(r.Body).Decode(&rep)
		select {
		case reportCh <- rep:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	reporter, err := NewReporter(ReporterConfig{
		MasterURL: srv.URL,
		NodeID:    "nk1",
		Interval:  10 * time.Millisecond,
		Timeout:   time.Second,
		Backoff:   time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reporter.Run(ctx, func() NodeReport {
		return NodeReport{NodeID: "nk1", Hosts: 7, ConfigHash: "hash"}
	})

	select {
	case rep := <-reportCh:
		if rep.NodeID != "nk1" || rep.Hosts != 7 {
			t.Errorf("first report = %+v", rep)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not post the first report immediately")
	}

	reporter.Stop()
	stopped := atomic.LoadInt32(&attempts)
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&attempts); got != stopped {
		t.Errorf("reporter kept posting after Stop: %d -> %d", stopped, got)
	}
	last, lastErr, _ := reporter.LastReport()
	if last.IsZero() || lastErr != nil {
		t.Errorf("LastReport = %v, %v after a successful cycle", last, lastErr)
	}
}

func TestNewReporterValidatesMasterURL(t *testing.T) {
	cases := []string{"", "not-a-url", "ftp://master:5099", "http://"}
	for _, raw := range cases {
		if _, err := NewReporter(ReporterConfig{MasterURL: raw}); err == nil {
			t.Errorf("NewReporter(%q) expected an error", raw)
		}
	}
	if _, err := NewReporter(ReporterConfig{MasterURL: "https://192.168.30.50:5099"}); err != nil {
		t.Errorf("NewReporter(https) unexpected error: %v", err)
	}
	if _, err := NewReporter(ReporterConfig{MasterURL: "http://192.168.30.50:5099"}); err != nil {
		t.Errorf("NewReporter(http) unexpected error: %v", err)
	}
}

func TestReporterBackoffIsCapped(t *testing.T) {
	reporter, err := NewReporter(ReporterConfig{
		MasterURL:  "http://127.0.0.1:5099",
		Backoff:    time.Second,
		MaxBackoff: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	if got := reporter.backoff(1); got != time.Second {
		t.Errorf("backoff(1) = %s, want 1s", got)
	}
	if got := reporter.backoff(2); got != 2*time.Second {
		t.Errorf("backoff(2) = %s, want 2s", got)
	}
	if got := reporter.backoff(10); got != 3*time.Second {
		t.Errorf("backoff(10) = %s, want the 3s cap", got)
	}
}
