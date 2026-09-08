package kernel

import (
	"context"

	"github.com/chins-xing/asscor/internal/adapter"
	"github.com/chins-xing/asscor/internal/model"
)

type AdapterIntegrationInterface interface {
	RunAdapters(ctx context.Context) []adapter.PipelineResult
	CollectFindings() []model.CheckResult
}
