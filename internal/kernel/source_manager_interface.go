package kernel

import "context"

type SourceManagerInterface interface {
	DeploySource(ctx context.Context, spec SourceSpec, cfg SourceConfig) error
	UninstallSource(ctx context.Context, id string, force bool) error
	EnableSource(ctx context.Context, id string) error
	DisableSource(ctx context.Context, id string) error
	UpdateSource(ctx context.Context, id string, version string) error
	GetSourceStatus(id string) (*SourceStatus, bool)
	ListSources(category SourceCategory) []SourceStatus
	ListAllSources() []SourceStatus
	ConfigureSource(ctx context.Context, id string, cfg SourceConfig) error
	GetSourceConfig(id string) (*SourceConfig, bool)
	GetSourceSpec(id string) (*SourceSpec, bool)
	RunSourceNow(ctx context.Context, id string) error
	GetAuditLog(sourceID string, limit int) []AuditLogEntry
	HealthCheck(ctx context.Context) error
}
