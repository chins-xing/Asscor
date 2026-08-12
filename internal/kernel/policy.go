package kernel

import (
	"context"
	"fmt"
	"sync"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
)

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
		Description: "Policy manager 鈥?evaluates scores against thresholds and triggers automated actions",
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
			HostID:  hostID,
			Action:  "notify_admin",
			Message: fmt.Sprintf("host %s score %.2f below threshold %.2f", hostID, score, threshold),
		})
	case score >= threshold-30:
		status = HostCritical
		actions = append(actions, PolicyAction{
			HostID:  hostID,
			Action:  "notify_admin",
			Message: fmt.Sprintf("CRITICAL: host %s score %.2f", hostID, score),
		}, PolicyAction{
			HostID: hostID,
			Action: "increase_assessment",
			Params: map[string]string{"host_id": hostID},
		})
	default:
		status = HostIsolated
		actions = append(actions, PolicyAction{
			HostID:  hostID,
			Action:  "isolate_host",
			Params:  map[string]string{"host_id": hostID},
			Message: fmt.Sprintf("ISOLATING host %s: score %.2f", hostID, score),
		}, PolicyAction{
			HostID:  hostID,
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

			m.kernel.Extensions().Execute(m.kernel.Context(), "policy.notify", map[string]interface{}{
				"host_id": hostID,
				"score":   score,
				"status":  status.String(),
				"action":  action.Action,
				"message": action.Message,
			})
		}

		if m.kernel != nil {
			if errs := m.kernel.Bus().PublishSync(m.kernel.Context(), Message{
				Topic:   TopicPolicyAction,
				Payload: action,
				Source:  "policy",
			}); len(errs) > 0 {
				logger.WithComponent("policy").Warn("sync publish errors", "count", len(errs))
			}
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

	status, _ := m.EvaluateHost(result.HostID, result.FinalScore)

	if result.PrismInferenceTrend == "collapsing" && result.PrismInferenceCollapseRisk > 0.7 {
		// Update host status so IsBlocked/HasActiveThreat reflect the preemptive
		// isolation (fixes the feedback loop where isolation wasn't recorded).
		m.mu.Lock()
		m.hostStatus[result.HostID] = HostIsolated
		m.mu.Unlock()

		preemptive := []PolicyAction{
			{
				HostID:  result.HostID,
				Action:  "isolate_host",
				Params:  map[string]string{"host_id": result.HostID},
				Message: fmt.Sprintf("PREEMPTIVE ISOLATION: host %s Prism collapse risk %.2f (trend: %s, SSAM score: %.2f)",
					result.HostID, result.PrismInferenceCollapseRisk, result.PrismInferenceTrend, result.FinalScore),
			},
			{
				HostID:  result.HostID,
				Action:  "notify_admin",
				Message: fmt.Sprintf("Prism preemptive: host %s collapse risk %.2f",
					result.HostID, result.PrismInferenceCollapseRisk),
			},
		}
		for _, action := range preemptive {
			if m.kernel != nil {
				if errs := m.kernel.Bus().PublishSync(m.kernel.Context(), Message{
					Topic:   TopicPolicyAction,
					Payload: action,
					Source:  "policy",
				}); len(errs) > 0 {
					logger.WithComponent("policy").Warn("preemptive publish errors", "count", len(errs))
				}
			}
		}
		logger.WithComponent("policy").Warn("Prism preemptive isolation triggered",
			"host_id", result.HostID,
			"prism_collapse_risk", result.PrismInferenceCollapseRisk,
			"prism_trend", result.PrismInferenceTrend,
			"policy_status", status)
	}

	return nil
}