package adapterhub

import (
	"context"
	"time"
)

// Builder builds an AdapterHub with custom configuration.
type Builder struct {
	config     *Config
	ruleEngine *RuleEngine
	manager    *Manager
}

// NewBuilder creates a new builder.
func NewBuilder() *Builder {
	cfg := DefaultConfig()
	ruleSet := cfg.GlobalRules.ToRuleSet()
	engine := NewRuleEngine(ruleSet)

	return &Builder{
		config:     cfg,
		ruleEngine: engine,
		manager:    NewManager(engine),
	}
}

// WithConfig sets the configuration.
func (b *Builder) WithConfig(cfg *Config) *Builder {
	b.config = cfg
	return b
}

// WithSyncInterval sets the sync interval.
func (b *Builder) WithSyncInterval(interval string) *Builder {
	b.manager.syncInterval = parseDuration(interval)
	return b
}

// WithGlobalRules sets global rules.
func (b *Builder) WithGlobalRules(rules *RuleSet) *Builder {
	b.ruleEngine.globalRules = rules
	return b
}

// WithToolRules sets tool-specific rules.
func (b *Builder) WithToolRules(tool string, rules *RuleSet) *Builder {
	b.ruleEngine.toolRules[tool] = rules
	return b
}

// WithAdapter registers an adapter.
func (b *Builder) WithAdapter(adapter UnifiedAdapter) *Builder {
	b.manager.adapters[adapter.Metadata().ID] = &adapterEntry{
		Adapter:  adapter,
		Metadata: adapter.Metadata(),
		State:    StateRegistered,
		Health: HealthInfo{
			Status:    HealthUnknown,
			Timestamp: timeNow(),
		},
	}
	return b
}

// WithBus sets the bus publisher.
func (b *Builder) WithBus(bus BusPublisher) *Builder {
	b.manager.bus = bus
	return b
}

// Build builds and initializes the manager.
func (b *Builder) Build(ctx context.Context) (*Manager, error) {
	if err := b.manager.Initialize(ctx); err != nil {
		return nil, err
	}

	if err := b.manager.Start(ctx); err != nil {
		return nil, err
	}

	return b.manager, nil
}

// AdapterBuilder helps build adapters with metadata and configuration.
type AdapterBuilder struct {
	metadata AdapterMetadata
	config   map[string]string
}

// NewAdapter creates a new adapter builder.
func NewAdapter(id, name string, category Category, priority Priority) *AdapterBuilder {
	return &AdapterBuilder{
		metadata: AdapterMetadata{
			ID:       id,
			Name:     name,
			Category: category,
			Priority: priority,
			Version:  "1.0",
			Tags:     []string{},
		},
		config: make(map[string]string),
	}
}

// WithVersion sets the adapter version.
func (b *AdapterBuilder) WithVersion(version string) *AdapterBuilder {
	b.metadata.Version = version
	return b
}

// WithDescription sets the adapter description.
func (b *AdapterBuilder) WithDescription(desc string) *AdapterBuilder {
	b.metadata.Description = desc
	return b
}

// WithAuthor sets the adapter author.
func (b *AdapterBuilder) WithAuthor(author string) *AdapterBuilder {
	b.metadata.Author = author
	return b
}

// WithTags sets the adapter tags.
func (b *AdapterBuilder) WithTags(tags ...string) *AdapterBuilder {
	b.metadata.Tags = tags
	return b
}

// WithConfig sets adapter-specific configuration.
func (b *AdapterBuilder) WithConfig(key, value string) *AdapterBuilder {
	b.config[key] = value
	return b
}

// GetMetadata returns the adapter metadata.
func (b *AdapterBuilder) GetMetadata() AdapterMetadata {
	return b.metadata
}

// GetConfig returns the adapter configuration.
func (b *AdapterBuilder) GetConfig() map[string]string {
	return b.config
}

// SimpleAdapter is a base implementation of UnifiedAdapter.
type SimpleAdapter struct {
	metadata AdapterMetadata
	execute  func(ctx AdapterContext, input Input) (Output, error)
	health   func(ctx AdapterContext) HealthInfo
}

// Metadata returns the adapter metadata.
func (a *SimpleAdapter) Metadata() AdapterMetadata {
	return a.metadata
}

// Initialize initializes the adapter.
func (a *SimpleAdapter) Initialize(ctx AdapterContext) error {
	return nil
}

// Execute executes the adapter.
func (a *SimpleAdapter) Execute(ctx AdapterContext, input Input) (Output, error) {
	if a.execute != nil {
		return a.execute(ctx, input)
	}
	return Output{AdapterID: a.metadata.ID, Findings: []*NormalizedFinding{}}, nil
}

// HealthCheck checks the adapter health.
func (a *SimpleAdapter) HealthCheck(ctx AdapterContext) HealthInfo {
	if a.health != nil {
		return a.health(ctx)
	}
	return HealthInfo{Status: HealthHealthy, Timestamp: timeNow()}
}

// Stop stops the adapter.
func (a *SimpleAdapter) Stop(ctx AdapterContext) error {
	return nil
}

// Capabilities returns the adapter capabilities.
func (a *SimpleAdapter) Capabilities() []Capability {
	return []Capability{
		{Type: CapabilityScan, Description: "Performs security scans"},
	}
}

// Build builds the simple adapter.
func (b *AdapterBuilder) Build(
	executeFn func(ctx AdapterContext, input Input) (Output, error),
	healthFn func(ctx AdapterContext) HealthInfo,
) *SimpleAdapter {
	return &SimpleAdapter{
		metadata: b.metadata,
		execute:  executeFn,
		health:   healthFn,
	}
}

// WrappedAdapter wraps an existing SSAM or SRD adapter to UnifiedAdapter.
type WrappedAdapter struct {
	id          string
	name        string
	category    Category
	priority    Priority
	wrapped     interface{}
	transformer func(finding interface{}) *NormalizedFinding
}

// WrapAdapter wraps an existing adapter.
func WrapAdapter(id, name string, category Category, priority Priority) *WrappedAdapter {
	return &WrappedAdapter{
		id:       id,
		name:     name,
		category: category,
		priority: priority,
	}
}

// WithWrapped sets the wrapped adapter and transformer.
func (w *WrappedAdapter) WithWrapped(adapter interface{}, transformer func(finding interface{}) *NormalizedFinding) *WrappedAdapter {
	w.wrapped = adapter
	w.transformer = transformer
	return w
}

// Metadata returns the adapter metadata.
func (w *WrappedAdapter) Metadata() AdapterMetadata {
	return AdapterMetadata{
		ID:       w.id,
		Name:     w.name,
		Category: w.category,
		Priority: w.priority,
		Version:  "1.0",
	}
}

// Initialize initializes the adapter.
func (w *WrappedAdapter) Initialize(ctx AdapterContext) error {
	return nil
}

// Execute executes the adapter.
func (w *WrappedAdapter) Execute(ctx AdapterContext, input Input) (Output, error) {
	return Output{AdapterID: w.id, Findings: []*NormalizedFinding{}}, nil
}

// HealthCheck checks the adapter health.
func (w *WrappedAdapter) HealthCheck(ctx AdapterContext) HealthInfo {
	return HealthInfo{Status: HealthHealthy, Timestamp: timeNow()}
}

// Stop stops the adapter.
func (w *WrappedAdapter) Stop(ctx AdapterContext) error {
	return nil
}

// Capabilities returns the adapter capabilities.
func (w *WrappedAdapter) Capabilities() []Capability {
	return []Capability{}
}

func timeNow() time.Time {
	return time.Now()
}

func parseDuration(s string) time.Duration {
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return 6 * time.Hour
}
