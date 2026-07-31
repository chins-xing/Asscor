package kernel

import (
	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/model"
)

type AssessorInterface interface {
	Evaluate(hostID string) *model.AssessmentResult
	EvaluateFromResults(hostID string, hostname string, checkResults []model.CheckResult) *model.AssessmentResult
	GetResult(hostID string) *model.AssessmentResult
	ReloadConfig(cfg *config.Config)
}
