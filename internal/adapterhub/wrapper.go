//go:build adapter

package adapterhub

import (
	"context"
	"time"

	"github.com/asscor/asscor/internal/adapter"
	"github.com/asscor/asscor/internal/model"
)

// SSAMAdapter wraps an existing SSAM adapter to UnifiedAdapter.
type SSAMAdapter struct {
	id           string
	name         string
	priority     Priority
	ssamAdapter  adapter.Adapter
	transformer  adapterFindingsTransformer
}

// adapterFindingsTransformer transforms SSAM findings to NormalizedFinding.
type adapterFindingsTransformer func(findings []*adapter.NormalizedFinding) []*NormalizedFinding

// NewSSAMAdapter creates a new SSAM adapter wrapper.
func NewSSAMAdapter(ssamAdapter adapter.Adapter) *SSAMAdapter {
	id := ssamAdapter.ID()
	name := ssamAdapter.Name()
	priority := PriorityP2
	if ssamAdapter.Priority() == "P1" {
		priority = PriorityP1
	}

	return &SSAMAdapter{
		id:          id,
		name:        name,
		priority:    priority,
		ssamAdapter: ssamAdapter,
		transformer: defaultSSAMFindingsTransformer,
	}
}

// Metadata returns the adapter metadata.
func (a *SSAMAdapter) Metadata() AdapterMetadata {
	return AdapterMetadata{
		ID:       a.id,
		Name:     a.name,
		Category: CategoryScanner,
		Priority: a.priority,
		Version:  "1.0",
		Tags:     []string{"ssam", "adapter"},
	}
}

// Initialize initializes the SSAM adapter.
func (a *SSAMAdapter) Initialize(ctx AdapterContext) error {
	return nil
}

// Execute executes the SSAM adapter.
func (a *SSAMAdapter) Execute(ctx AdapterContext, input Input) (Output, error) {
	start := time.Now()

	cfg := make(map[string]string)
	for k, v := range ctx.Config {
		cfg[k] = v
	}

	findings, err := adapter.ExecuteAdapter(context.Background(), a.ssamAdapter, cfg)
	if err != nil {
		return Output{
			AdapterID: a.id,
			Error:     err,
			Duration:  time.Since(start),
			Timestamp: time.Now(),
		}, err
	}

	transformed := a.transformer(findings)

	return Output{
		AdapterID: a.id,
		Findings:   transformed,
		Duration:  time.Since(start),
		Timestamp: time.Now(),
	}, nil
}

// HealthCheck checks the SSAM adapter health.
func (a *SSAMAdapter) HealthCheck(ctx AdapterContext) HealthInfo {
	return HealthInfo{
		Status:    HealthHealthy,
		Message:   "SSAM adapter is healthy",
		Timestamp: time.Now(),
	}
}

// Stop stops the SSAM adapter.
func (a *SSAMAdapter) Stop(ctx AdapterContext) error {
	return nil
}

// Capabilities returns the adapter capabilities.
func (a *SSAMAdapter) Capabilities() []Capability {
	return []Capability{
		{Type: CapabilityScan, Description: "SSAM security scanner"},
	}
}

func defaultSSAMFindingsTransformer(findings []*adapter.NormalizedFinding) []*NormalizedFinding {
	result := make([]*NormalizedFinding, 0, len(findings))
	for _, f := range findings {
		checkResult := f.ToCheckResult()
		result = append(result, &NormalizedFinding{
			ID:          f.ID,
			Source:      f.Source,
			CheckID:     f.CheckID,
			RuleID:      f.CheckID,
			Title:       f.Title,
			Description: f.Description,
			Severity:    Severity(f.Severity),
			Domain:      f.Domain,
			Category:    string(f.FindingType),
			Result:      resultFromBool(f.Passed),
			Delta:       checkResult.Delta,
			CVSSScore:   f.CVSEScore,
			CVE:         f.CVE,
			Resource:    f.Resource,
			Timestamp:   f.Timestamp,
			References:  []string{f.Reference},
			Metadata:    f.Metadata,
			Passed:      f.Passed,
		})
	}
	return result
}

func resultFromBool(passed bool) Result {
	if passed {
		return ResultPass
	}
	return ResultFail
}

// SRDAdapter wraps an existing SRD adapter to UnifiedAdapter.
type SRDAdapter struct {
	id         string
	name       string
	priority   Priority
	srdAdapter srdAdapterInterface
}

// srdAdapterInterface matches the srd.Adapter interface.
type srdAdapterInterface interface {
	ToolID() string
	ToolName() string
	IsEnabled(cfg interface{}) bool
	Parse(ctx context.Context, input []byte) (interface{}, error)
	SupportsFormat(path string) bool
}

// NewSRDAdapter creates a new SRD adapter wrapper.
func NewSRDAdapter(srdAdapter srdAdapterInterface) *SRDAdapter {
	return &SRDAdapter{
		id:         srdAdapter.ToolID(),
		name:       srdAdapter.ToolName(),
		priority:   PriorityP2,
		srdAdapter: srdAdapter,
	}
}

// Metadata returns the adapter metadata.
func (a *SRDAdapter) Metadata() AdapterMetadata {
	return AdapterMetadata{
		ID:       a.id,
		Name:     a.name,
		Category: CategoryPrism,
		Priority: a.priority,
		Version:  "1.0",
		Tags:     []string{"srd", "prism", "adapter"},
	}
}

// Initialize initializes the SRD adapter.
func (a *SRDAdapter) Initialize(ctx AdapterContext) error {
	return nil
}

// Execute executes the SRD adapter.
func (a *SRDAdapter) Execute(ctx AdapterContext, input Input) (Output, error) {
	start := time.Now()

	report, err := a.srdAdapter.Parse(context.Background(), input.Data)
	if err != nil {
		return Output{
			AdapterID: a.id,
			Error:     err,
			Duration:  time.Since(start),
			Timestamp: time.Now(),
		}, err
	}

	return Output{
		AdapterID: a.id,
		RawReport: report,
		Duration:  time.Since(start),
		Timestamp: time.Now(),
	}, nil
}

// HealthCheck checks the SRD adapter health.
func (a *SRDAdapter) HealthCheck(ctx AdapterContext) HealthInfo {
	return HealthInfo{
		Status:    HealthHealthy,
		Message:   "SRD adapter is healthy",
		Timestamp: time.Now(),
	}
}

// Stop stops the SRD adapter.
func (a *SRDAdapter) Stop(ctx AdapterContext) error {
	return nil
}

// Capabilities returns the adapter capabilities.
func (a *SRDAdapter) Capabilities() []Capability {
	return []Capability{
		{Type: CapabilityImport, Description: "SRD/Prism data import"},
	}
}

// FromCheckResult creates a NormalizedFinding from a model.CheckResult.
func FromCheckResult(cr model.CheckResult) *NormalizedFinding {
	severity := SeverityInfo
	if cr.Delta <= -15 {
		severity = SeverityCritical
	} else if cr.Delta <= -10 {
		severity = SeverityHigh
	} else if cr.Delta <= -7.5 {
		severity = SeverityMedium
	} else if cr.Delta <= -5 {
		severity = SeverityLow
	}

	return &NormalizedFinding{
		CheckID:    cr.CheckID,
		Title:      cr.Name,
		Severity:   severity,
		Domain:     cr.Domain,
		Result:     resultFromBool(cr.Passed),
		Delta:      cr.Delta,
		Passed:     cr.Passed,
		References: []string{cr.ComplianceRef},
	}
}
