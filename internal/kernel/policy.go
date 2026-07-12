package kernel

import (
	"context"
	"fmt"
	"sync"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
)

type HostStatus int

const (
	HostOK HostStatus = iota
	HostWarning
	HostCritical
	HostIsolated
)

func (s HostStatus) String() string {
	switch s {
	case HostOK:
		return "OK"
	case HostWarning:
		return "Warning"
	case HostCritical:
		return "Critical"
	case HostIsolated:
		return "Isolated"
	default:
		return "Unknown"
	}
}

type PolicyAction struct {
	Action  string
	Params  map[string]string
	Message string
}

type PolicyModule struct {
	kernel KernelContext
	cfg    *config.Config

	mu          sync.RWMutex
	hostStatus  map[string]HostStatus
	actionQueue []PolicyAction

	state PluginState
}

func (m *PolicyModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "policy",
		Version:     "1.2.0",
		Description: "Policy manager — evaluates scores against thresholds and triggers automated actions",
		Author:      "ASSCOR Core Team",
	}
}

func (m *PolicyModule) Dependencies() []PluginDependency {
	return nil
}

func (m *PolicyModule) Priority() int {
	return 50
}

func (m *PolicyModule) Init(ctx context.Context, kc KernelContext) error {
	m.kernel = kc
	m.hostStatus = make(map[string]HostStatus)
	m.actionQueue = make([]PolicyAction, 0)
	m.state = PluginInitialized

	if impl, ok := kc.Container().ResolveNamed("config"); ok {
		if c, ok := impl.(*config.Config); ok {
			m.cfg = c
		}
	}
	if m.cfg == nil {
		m.cfg = config.Default()
	}

	kc.Container().Bind((*PolicyInterface)(nil), m)

	return nil
}

func (m *PolicyModule) Start(ctx context.Context) error {
	m.state = PluginStarted
	m.kernel.Bus().Subscribe(TopicAssessorResult, "policy", m.onAssessmentResult)
	logger.WithComponent("policy").Info("started")
	return nil
}

func (m *PolicyModule) Stop(ctx context.Context) error {
	m.state = PluginStopping
	m.kernel.Bus().UnsubscribeAll("policy")
	m.state = PluginStopped
	logger.WithComponent("policy").Info("stopped")
	return nil
}

func (m *PolicyModule) State() PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *PolicyModule) EvaluateHost(hostID string, score float64) (HostStatus, []PolicyAction) {
	threshold := m.cfg.Threshold

	var status HostStatus
	var actions []PolicyAction

	switch {
	case score >= threshold:
		status = HostOK
	case score >= threshold-10:
		status = HostWarning
		actions = append(actions, PolicyAction{
			Action:  "notify_admin",
			Message: fmt.Sprintf("host %s score %.2f below threshold %.2f", hostID, score, threshold),
		})
	case score >= threshold-30:
		status = HostCritical
		actions = append(actions, PolicyAction{
			Action:  "notify_admin",
			Message: fmt.Sprintf("CRITICAL: host %s score %.2f", hostID, score),
		}, PolicyAction{
			Action: "increase_assessment",
			Params: map[string]string{"host_id": hostID},
		})
	default:
		status = HostIsolated
		actions = append(actions, PolicyAction{
			Action:  "isolate_host",
			Params:  map[string]string{"host_id": hostID},
			Message: fmt.Sprintf("ISOLATING host %s: score %.2f", hostID, score),
		}, PolicyAction{
			Action:  "notify_admin",
			Message: fmt.Sprintf("ISOLATED: host %s", hostID),
		})
	}

	m.mu.Lock()
	prevStatus := m.hostStatus[hostID]
	m.hostStatus[hostID] = status
	m.mu.Unlock()

	if prevStatus != status && m.kernel != nil && m.kernel.Extensions() != nil {
		m.kernel.Extensions().Execute(m.kernel.Context(), "policy.status_changed", map[string]interface{}{
			"host_id":      hostID,
			"score":        score,
			"prev_status":  prevStatus.String(),
			"new_status":   status.String(),
			"actions":      actions,
		})
	}

	for _, action := range actions {
		if m.kernel != nil && m.kernel.Extensions() != nil {
			m.kernel.Extensions().Execute(m.kernel.Context(), "policy.action_decided", map[string]interface{}{
				"host_id": hostID,
				"score":   score,
				"status":  status.String(),
				"action":  action,
			})

			if action.Action == "notify_admin" {
				m.kernel.Extensions().Execute(m.kernel.Context(), "policy.notify", map[string]interface{}{
					"host_id": hostID,
					"score":   score,
					"status":  status.String(),
					"message": action.Message,
				})
			}
		}

		if errs := m.kernel.Bus().PublishSync(m.kernel.Context(), Message{
			Topic:   TopicPolicyAction,
			Payload: action,
			Source:  "policy",
		}); len(errs) > 0 {
			logger.WithComponent("policy").Warn("sync publish errors", "count", len(errs))
		}
	}

	return status, actions
}

func (m *PolicyModule) GetHostStatus(hostID string) HostStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s, ok := m.hostStatus[hostID]; ok {
		return s
	}
	return HostOK
}

func (m *PolicyModule) onAssessmentResult(ctx context.Context, msg Message) error {
	result, ok := msg.Payload.(*model.AssessmentResult)
	if !ok {
		return nil
	}

	status, actions := m.EvaluateHost(result.HostID, result.FinalScore)

	if result.PrismInferenceTrend == "collapsing" && result.PrismInferenceCollapseRisk > 0.7 {
		actions = append(actions, PolicyAction{
			Action:  "isolate_host",
			Message: fmt.Sprintf("PREEMPTIVE ISOLATION: host %s Prism collapse risk %.2f (trend: %s, SSAM score: %.2f)",
				result.HostID, result.PrismInferenceCollapseRisk, result.PrismInferenceTrend, result.FinalScore),
		})
		actions = append(actions, PolicyAction{
			Action:  "notify_admin",
			Message: fmt.Sprintf("Prism preemptive: host %s collapse risk %.2f",
				result.HostID, result.PrismInferenceCollapseRisk),
		})
		logger.WithComponent("policy").Warn("Prism preemptive isolation triggered",
			"host_id", result.HostID,
			"prism_collapse_risk", result.PrismInferenceCollapseRisk,
			"prism_trend", result.PrismInferenceTrend,
			"policy_status", status)
	}

	return nil
}

type PolicyInterface interface {
	EvaluateHost(hostID string, score float64) (HostStatus, []PolicyAction)
	GetHostStatus(hostID string) HostStatus
}