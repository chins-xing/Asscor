package kernel

import (
	"context"

	"github.com/asscor/asscor/internal/adapter"
	"github.com/asscor/asscor/internal/model"
)

type AdapterIntegrationInterface interface {
	RunAdapters(ctx context.Context) []adapter.PipelineResult
	CollectFindings() []model.CheckResult
}
