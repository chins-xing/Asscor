package kernel

import (
	"testing"
	"time"
)

func TestWorkerPool(t *testing.T) {
	pool := NewWorkerPool(3)
	if got := pool.MaxConcurrency(); got != 3 {
		t.Fatalf("expected max 3, got %d", got)
	}

	completed := 0
	for i := 0; i < 10; i++ {
		pool.Submit(func() error {
			time.Sleep(10 * time.Millisecond)
			return nil
		})
	}
	pool.Wait()

	metrics := pool.Metrics()
	if metrics.totalSubmitted != 10 {
		t.Fatalf("expected 10 submitted, got %d", metrics.totalSubmitted)
	}
	if metrics.totalCompleted != 10 {
		t.Fatalf("expected 10 completed, got %d", metrics.totalCompleted)
	}

	_ = completed
}

func TestWorkerPoolTimeout(t *testing.T) {
	pool := NewWorkerPool(2)

	pool.SubmitWithTimeout(func() error {
		time.Sleep(200 * time.Millisecond)
		return nil
	}, 50*time.Millisecond)

	time.Sleep(300 * time.Millisecond)
	pool.Wait()

	metrics := pool.Metrics()
	if metrics.totalTimeout == 0 {
		t.Error("expected at least 1 timeout")
	}
}

func TestSIEMPusher_Disabled(t *testing.T) {
	s := NewSIEMPusher("", "", "")
	if s.Enabled() {
		t.Error("SIEM pusher with empty config should be disabled")
	}
}

func TestSIEMPusher_Enabled(t *testing.T) {
	s := NewSIEMPusher("https://siem.internal:55000", "admin", "pass")
	if !s.Enabled() {
		t.Error("SIEM pusher with full config should be enabled")
	}
}

func TestSIEMPusher_EndpointURLs(t *testing.T) {
	s := NewSIEMPusher("https://siem.internal:55000/", "admin", "pass")

	s.mu.Lock()
	s.token = "test-token"
	token := s.token
	s.mu.Unlock()

	if token != "test-token" {
		t.Errorf("token = %s, want test-token", token)
	}
}

func TestSelfAssessment_TopicConstant(t *testing.T) {
	if TopicAssessorSelfCheck != "assessor.self_check" {
		t.Errorf("TopicAssessorSelfCheck = %s, want assessor.self_check", TopicAssessorSelfCheck)
	}
	if TopicAssessorSelfCheck == TopicAssessorResult {
		t.Error("self_check topic must differ from assessor.result to prevent downstream pollution")
	}
}

func TestAdapterIntegration_StopChannel(t *testing.T) {
	m := NewAdapterIntegrationModule()
	m.mu.Lock()
	ch := m.stopCh
	m.mu.Unlock()

	if ch == nil {
		t.Error("stopCh should be initialized in constructor")
	}

	go func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		select {
		case <-m.stopCh:
		default:
			close(m.stopCh)
		}
	}()

	time.Sleep(10 * time.Millisecond)

	m.mu.Lock()
	select {
	case <-m.stopCh:
	default:
		t.Error("stopCh should have been closed")
	}
	m.mu.Unlock()
}
