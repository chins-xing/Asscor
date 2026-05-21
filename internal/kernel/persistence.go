package kernel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/argus-security/argus/internal/config"
	"github.com/argus-security/argus/internal/logger"
	"github.com/argus-security/argus/internal/model"
	"github.com/argus-security/argus/internal/version"
)

type AssessmentRecord struct {
	Timestamp      time.Time `json:"timestamp"`
	HostID         string    `json:"host_id"`
	Hostname       string    `json:"hostname,omitempty"`
	FinalScore     float64   `json:"final_score"`
	Threshold      float64   `json:"threshold,omitempty"`
	Acceptable     bool      `json:"acceptable"`
	AttackSurface  float64   `json:"attack_surface"`
	BusinessCont   float64   `json:"business_continuity"`
	OperationTrust float64   `json:"operation_trust"`
	Resilience     float64   `json:"resilience"`
	KernelSecurity float64   `json:"kernel_security,omitempty"`
	TwoFactorFail  float64   `json:"two_factor_failure"`
	ThreatCoeff    float64   `json:"threat_coefficient"`
	SPCScore       float64   `json:"spc_score,omitempty"`
	CheckCount     int       `json:"check_count"`
	FailedCount    int       `json:"failed_count"`
	Checks         []CheckDetail `json:"checks,omitempty"`
}

type CheckDetail struct {
	CheckID       string  `json:"check_id"`
	Domain        string  `json:"domain"`
	Name          string  `json:"name"`
	Passed        bool    `json:"passed"`
	Delta         float64 `json:"delta"`
	Detail        string  `json:"detail"`
	ComplianceRef string  `json:"compliance_ref,omitempty"`
}

type DashboardReport struct {
	SchemaVersion string            `json:"schema_version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	HostID        string            `json:"host_id"`
	Hostname      string            `json:"hostname"`
	Framework     string            `json:"framework"`
	SSAMVersion   string            `json:"ssam_version"`

	FinalScore float64 `json:"final_score"`
	Threshold  float64 `json:"threshold"`
	Acceptable bool    `json:"acceptable"`

	DomainScores map[string]float64 `json:"domain_scores"`
	DomainWeights map[string]float64 `json:"domain_weights"`

	EdgeFactors map[string]float64 `json:"edge_factors"`
	ThreatCoeff float64            `json:"threat_coefficient"`
	SPCScore    float64            `json:"spc_score"`

	Summary struct {
		TotalChecks  int `json:"total_checks"`
		PassedChecks int `json:"passed_checks"`
		FailedChecks int `json:"failed_checks"`
	} `json:"summary"`

	Checks []CheckDetail `json:"checks"`

	ComplianceFramework string `json:"compliance_framework,omitempty"`
}

type AgentRegistrationRecord struct {
	Timestamp time.Time `json:"timestamp"`
	HostID    string    `json:"host_id"`
	Hostname  string    `json:"hostname"`
	Version   string    `json:"version"`
	Event     string    `json:"event"`
}

type AuditEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Actor     string                 `json:"actor"`
	Action    string                 `json:"action"`
	Target    string                 `json:"target"`
	Detail    map[string]interface{} `json:"detail"`
	Success   bool                   `json:"success"`
}

type CommandRecord struct {
	Timestamp time.Time         `json:"timestamp"`
	CommandID string            `json:"command_id"`
	HostID    string            `json:"host_id"`
	Command   string            `json:"command"`
	Params    map[string]string `json:"params"`
	Status    string            `json:"status"`
	Signature string            `json:"signature"`
}

type CVECacheRecord struct {
	Timestamp   time.Time              `json:"timestamp"`
	TotalCount  int                    `json:"total_count"`
	HighCount   int                    `json:"high_count"`
	KEVCount    int                    `json:"kev_count"`
	TopCVEs     []string               `json:"top_cves"`
	Sources     map[string]interface{} `json:"sources"`
}

type jsonlWriter struct {
	mu   sync.Mutex
	file *os.File
	path string
	day  int
}

func (w *jsonlWriter) write(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	today := time.Now().YearDay()
	if w.day != today && w.day != 0 {
		if w.file != nil {
			w.file.Close()
			w.file = nil
		}
	}

	if w.file == nil {
		dir := filepath.Dir(w.path)
		fname := filepath.Base(w.path)
		ext := filepath.Ext(fname)
		base := fname[:len(fname)-len(ext)]
		dated := filepath.Join(dir, fmt.Sprintf("%s-%s%s", base, time.Now().Format("20060102"), ext))

		f, err := os.OpenFile(dated, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("open jsonl: %w", err)
		}
		w.file = f
		w.day = today
	}

	_, err := w.file.Write(append(data, '\n'))
	if err != nil && w.file != nil {
		w.file.Close()
		w.file = nil
		w.day = 0
	}
	return err
}

func (w *jsonlWriter) sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Sync()
	}
	return nil
}

func (w *jsonlWriter) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}

type PersistenceModule struct {
	kernel *Kernel
	cfg    *config.Config

	mu          sync.Mutex
	dataDir     string
	writers     map[string]*jsonlWriter
	flushTicker *time.Ticker
	flushDone   chan struct{}
	bufSize     int

	enabled  bool
	state    PluginState
}

func NewPersistenceModule(dataDir string) *PersistenceModule {
	if dataDir == "" {
		dataDir = "data"
	}
	return &PersistenceModule{
		dataDir: dataDir,
		writers: make(map[string]*jsonlWriter),
		bufSize: 64,
		enabled: true,
	}
}

func (m *PersistenceModule) Info() PluginInfo {
	return PluginInfo{
		Name:        "persistence",
		Version:     "1.2.0",
		Description: "Persistence manager — JSONL-based 3-tier storage with daily rotation and batch flush",
		Author:      "ARGUS Core Team",
	}
}

func (m *PersistenceModule) Dependencies() []PluginDependency {
	return nil
}

func (m *PersistenceModule) Priority() int {
	return 3
}

func (m *PersistenceModule) Init(ctx context.Context, k *Kernel) error {
	m.kernel = k
	m.state = PluginInitialized

	if impl, ok := k.Container().ResolveNamed("config"); ok {
		if c, ok := impl.(*config.Config); ok {
			m.cfg = c
		}
	}
	if m.cfg == nil {
		m.cfg = config.Default()
	}

	if err := os.MkdirAll(m.dataDir, 0755); err != nil {
		return fmt.Errorf("persistence: create data dir: %w", err)
	}

	m.flushTicker = time.NewTicker(30 * time.Second)
	m.flushDone = make(chan struct{})

	k.Container().Bind((*PersistenceInterface)(nil), m)

	return nil
}

func (m *PersistenceModule) Start(ctx context.Context) error {
	m.state = PluginStarted

	m.kernel.Bus().Subscribe("assessor.result", "persistence", m.onAssessmentResult)
	m.kernel.Bus().Subscribe("agent.registered", "persistence", m.onAgentRegistered)
	m.kernel.Bus().Subscribe("agent.timeout", "persistence", m.onAgentTimeout)

	go m.flushLoop()
	logger.With("component", "persistence").Info("started", "data_dir", m.dataDir)
	return nil
}

func (m *PersistenceModule) Stop(ctx context.Context) error {
	m.state = PluginStopping

	m.kernel.Bus().UnsubscribeAll("persistence")

	close(m.flushDone)
	m.flushTicker.Stop()
	m.flushAll()

	m.mu.Lock()
	for _, w := range m.writers {
		w.close()
	}
	m.mu.Unlock()

	m.state = PluginStopped
	logger.With("component", "persistence").Info("stopped")
	return nil
}

func (m *PersistenceModule) State() PluginState {
	return m.state
}

func (m *PersistenceModule) HealthCheck(ctx context.Context) error {
	if m.state != PluginStarted {
		return fmt.Errorf("persistence not started (state=%s)", m.state)
	}
	info, err := os.Stat(m.dataDir)
	if err != nil {
		return fmt.Errorf("persistence data dir inaccessible: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("persistence data path is not a directory: %s", m.dataDir)
	}
	return nil
}

func (m *PersistenceModule) Append(dataset string, record interface{}) error {
	if !m.enabled {
		return nil
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("persistence marshal: %w", err)
	}

	writer := m.getOrCreateWriter(dataset)
	return writer.write(data)
}

func (m *PersistenceModule) AppendBatch(dataset string, records []interface{}) error {
	for _, rec := range records {
		if err := m.Append(dataset, rec); err != nil {
			return err
		}
	}
	return nil
}

func (m *PersistenceModule) WriteAudit(entry AuditEntry) error {
	return m.Append("audit", entry)
}

func (m *PersistenceModule) WriteCommand(record CommandRecord) error {
	return m.Append("commands", record)
}

func (m *PersistenceModule) WriteAssessment(record AssessmentRecord) error {
	return m.Append("assessments", record)
}

func (m *PersistenceModule) WriteDashboardReport(report *DashboardReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("dashboard marshal: %w", err)
	}

	path := filepath.Join(m.dataDir, "latest-assessment.json")
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("dashboard write tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("dashboard rename: %w", err)
	}
	return nil
}

func (m *PersistenceModule) WriteCVECache(record CVECacheRecord) error {
	return m.Append("cve_cache", record)
}

func (m *PersistenceModule) getOrCreateWriter(dataset string) *jsonlWriter {
	m.mu.Lock()
	defer m.mu.Unlock()

	if w, ok := m.writers[dataset]; ok {
		return w
	}

	filePath := filepath.Join(m.dataDir, dataset+".jsonl")
	w := &jsonlWriter{path: filePath}
	m.writers[dataset] = w
	return w
}

func (m *PersistenceModule) flushAll() {
	m.mu.Lock()
	writers := make([]*jsonlWriter, 0, len(m.writers))
	for _, w := range m.writers {
		writers = append(writers, w)
	}
	m.mu.Unlock()

	for _, w := range writers {
		w.sync()
	}
}

func (m *PersistenceModule) flushLoop() {
	for {
		select {
		case <-m.flushTicker.C:
			m.flushAll()
		case <-m.flushDone:
			m.flushAll()
			return
		}
	}
}

func (m *PersistenceModule) RotateAll() {
	m.mu.Lock()
	for _, w := range m.writers {
		w.close()
	}
	m.mu.Unlock()
}

func (m *PersistenceModule) DataDir() string {
	return m.dataDir
}

func (m *PersistenceModule) onAssessmentResult(ctx context.Context, msg Message) error {
	payload := msg.Payload
	logger.With("component", "persistence").Debug("received assessor.result event", "type", fmt.Sprintf("%T", payload))

	if ar, ok := payload.(*model.AssessmentResult); ok {
		logger.With("component", "persistence").Info("processing assessment",
			"host_id", ar.HostID, "score", ar.FinalScore, "acceptable", ar.Acceptable, "checks", len(ar.Checks))

		checkDetails := make([]CheckDetail, 0, len(ar.Checks))
		for _, c := range ar.Checks {
			checkDetails = append(checkDetails, CheckDetail{
				CheckID:       c.CheckID,
				Domain:        c.Domain,
				Name:          c.Name,
				Passed:        c.Passed,
				Delta:         c.Delta,
				Detail:        c.Detail,
				ComplianceRef: c.ComplianceRef,
			})
		}

		rec := AssessmentRecord{
			Timestamp:      time.Now(),
			HostID:         ar.HostID,
			Hostname:       ar.Hostname,
			FinalScore:     ar.FinalScore,
			Threshold:      ar.Threshold,
			Acceptable:     ar.Acceptable,
			AttackSurface:  ar.DomainScores.AttackSurface,
			BusinessCont:   ar.DomainScores.BusinessContinuity,
			OperationTrust: ar.DomainScores.OperationTrust,
			Resilience:     ar.DomainScores.Resilience,
			KernelSecurity: ar.DomainScores.KernelSecurity,
			TwoFactorFail:  ar.EdgeFactors.TwoFactorFailure,
			ThreatCoeff:    ar.ThreatCoeff,
			SPCScore:       ar.SPCScore,
			CheckCount:     len(ar.Checks),
			Checks:         checkDetails,
		}

		for _, c := range ar.Checks {
			if !c.Passed {
				rec.FailedCount++
			}
		}

		if err := m.WriteAssessment(rec); err != nil {
			logger.With("component", "persistence").Error("write assessment error", "error", err)
		} else {
			logger.With("component", "persistence").Info("assessment written", "host_id", ar.HostID, "score", ar.FinalScore)
		}

		passedCount := rec.CheckCount - rec.FailedCount
		domainScores := map[string]float64{
			"attack_surface":      ar.DomainScores.AttackSurface,
			"business_continuity": ar.DomainScores.BusinessContinuity,
			"operation_trust":     ar.DomainScores.OperationTrust,
			"resilience":          ar.DomainScores.Resilience,
			"kernel_security":     ar.DomainScores.KernelSecurity,
		}
		domainWeights := map[string]float64{
			"attack_surface":      m.cfg.Weights.AttackSurface,
			"business_continuity": m.cfg.Weights.BusinessContinuity,
			"operation_trust":     m.cfg.Weights.OperationTrust,
			"resilience":          m.cfg.Weights.Resilience,
		}
		edgeFactors := map[string]float64{
			"two_factor_failure": ar.EdgeFactors.TwoFactorFailure,
		}

		report := &DashboardReport{
			SchemaVersion: "1.0",
			GeneratedAt:   time.Now(),
			HostID:        ar.HostID,
			Hostname:      ar.Hostname,
			Framework:     "ARGUS",
			SSAMVersion:   version.SSAMVersion,
			FinalScore:    ar.FinalScore,
			Threshold:     ar.Threshold,
			Acceptable:    ar.Acceptable,
			DomainScores:  domainScores,
			DomainWeights: domainWeights,
			EdgeFactors:   edgeFactors,
			ThreatCoeff:   ar.ThreatCoeff,
			SPCScore:      ar.SPCScore,
			Checks:        checkDetails,
			ComplianceFramework: m.cfg.ComplianceFramework,
		}
		report.Summary.TotalChecks = rec.CheckCount
		report.Summary.PassedChecks = passedCount
		report.Summary.FailedChecks = rec.FailedCount

		if err := m.WriteDashboardReport(report); err != nil {
			logger.With("component", "persistence").Error("write dashboard report error", "error", err)
		}
		return nil
	}

	if v, ok := payload.(map[string]interface{}); ok {
		hostID, _ := v["HostID"].(string)
		finalScore, _ := v["FinalScore"].(float64)
		acceptable, _ := v["Acceptable"].(bool)

		rec := AssessmentRecord{
			Timestamp:  time.Now(),
			HostID:     hostID,
			FinalScore: finalScore,
			Acceptable: acceptable,
		}

		if ds, ok2 := v["DomainScores"].(map[string]interface{}); ok2 {
			rec.AttackSurface, _ = ds["attack_surface"].(float64)
			rec.BusinessCont, _ = ds["business_continuity"].(float64)
			rec.OperationTrust, _ = ds["operation_trust"].(float64)
			rec.Resilience, _ = ds["resilience"].(float64)
		}

		if spc, ok2 := v["SPCScore"].(float64); ok2 {
			rec.SPCScore = spc
		}

		rec.ThreatCoeff = 1.0
		if tc, ok2 := v["ThreatCoeff"].(float64); ok2 {
			rec.ThreatCoeff = tc
		}

		if checks, ok2 := v["Checks"].([]interface{}); ok2 {
			rec.CheckCount = len(checks)
			for _, c := range checks {
				if cm, ok3 := c.(map[string]interface{}); ok3 {
					if passed, _ := cm["passed"].(bool); !passed {
						rec.FailedCount++
					}
				}
			}
		}

		m.WriteAssessment(rec)
	}
	return nil
}

func (m *PersistenceModule) onAgentRegistered(ctx context.Context, msg Message) error {
	if hostID, ok := msg.Payload.(string); ok {
		hb, _ := m.kernel.GetPlugin("heartbeat")
		if hb == nil {
			return nil
		}
		var record *AgentRegistrationRecord
		if mi, ok2 := hb.(HeartbeatInterface); ok2 {
			agent := mi.GetAgent(hostID)
			if agent != nil {
				record = &AgentRegistrationRecord{
					Timestamp: time.Now(),
					HostID:    agent.HostID,
					Hostname:  agent.Hostname,
					Version:   agent.Version,
					Event:     "registered",
				}
			}
		}
		if record != nil {
			m.Append("agents", record)
		}
	}
	return nil
}

func (m *PersistenceModule) onAgentTimeout(ctx context.Context, msg Message) error {
	if hostID, ok := msg.Payload.(string); ok {
		record := &AgentRegistrationRecord{
			Timestamp: time.Now(),
			HostID:    hostID,
			Event:     "timeout",
		}
		m.Append("agents", record)
	}
	return nil
}

type PersistenceInterface interface {
	Append(dataset string, record interface{}) error
	AppendBatch(dataset string, records []interface{}) error
	WriteAudit(entry AuditEntry) error
	WriteCommand(record CommandRecord) error
	WriteAssessment(record AssessmentRecord) error
	WriteDashboardReport(report *DashboardReport) error
	WriteCVECache(record CVECacheRecord) error
	RotateAll()
	DataDir() string
}