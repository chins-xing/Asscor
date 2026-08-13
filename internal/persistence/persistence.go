//go:build persistence

package persistence

import (
	"github.com/asscor/asscor/internal/kernel"
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/asscor/asscor/internal/config"
	"github.com/asscor/asscor/internal/logger"
	"github.com/asscor/asscor/internal/model"
	"github.com/asscor/asscor/internal/version"
)

type jsonlWriter struct {
	mu     sync.Mutex
	file   *os.File
	buf    *bufio.Writer
	path   string
	day    int
}

func (w *jsonlWriter) write(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	today := time.Now().YearDay()
	if w.day != today && w.day != 0 {
		if w.buf != nil {
			w.buf.Flush()
		}
		if w.file != nil {
			w.file.Close()
			w.file = nil
			w.buf = nil
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
		w.buf = bufio.NewWriterSize(f, 4096)
		w.day = today
	}

	_, err := w.buf.Write(append(data, '\n'))
	if err != nil && w.file != nil {
		w.buf.Flush()
		w.file.Close()
		w.file = nil
		w.buf = nil
		w.day = 0
	}
	return err
}

func (w *jsonlWriter) sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf != nil {
		if err := w.buf.Flush(); err != nil {
			return err
		}
	}
	if w.file != nil {
		return w.file.Sync()
	}
	return nil
}

func (w *jsonlWriter) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf != nil {
		w.buf.Flush()
	}
	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		w.buf = nil
		return err
	}
	return nil
}

type Module struct {
	kc kernel.KernelContext
	cfg    *config.Config

	mu          sync.Mutex
	dataDir     string
	writers     map[string]*jsonlWriter
	flushTicker *time.Ticker
	flushDone   chan struct{}
	cleanupDone chan struct{}
	backupDone  chan struct{}
	bufSize     int
	retentionDays int
	history     *kernel.HistoricalStore

	enabled  bool
	state    kernel.PluginState
}

func New(dataDir string) *Module {
	if dataDir == "" {
		dataDir = "data"
	}
	return &Module{
		dataDir: dataDir,
		writers: make(map[string]*jsonlWriter),
		bufSize: 64,
		enabled: true,
		retentionDays: 90,
	}
}

func (m *Module) Info() kernel.PluginInfo {
	return kernel.PluginInfo{
		Name:        "persistence",
		Version:     "1.2.0",
		Description: "Persistence manager — JSONL-based 3-tier storage with daily rotation and batch flush",
		Author:      "ASSCOR Core Team",
	}
}

func (m *Module) Dependencies() []kernel.PluginDependency {
	return nil
}

func (m *Module) Priority() int {
	return 3
}

func (m *Module) Init(ctx context.Context, kc kernel.KernelContext) error {
	m.kc = kc
	m.mu.Lock()
	m.state = kernel.PluginInitialized
	m.mu.Unlock()

	if impl, ok := kc.Container().ResolveNamed("config"); ok {
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
	m.cleanupDone = make(chan struct{})
	m.backupDone = make(chan struct{})
	m.history = kernel.NewHistoricalStore(m.dataDir)

	kc.Container().Bind((*kernel.PersistenceInterface)(nil), m)

	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.mu.Lock()
	m.state = kernel.PluginStarted
	m.mu.Unlock()

	m.kc.Bus().Subscribe(kernel.TopicAssessorResult, "persistence", m.onAssessmentResult)
	m.kc.Bus().Subscribe(kernel.TopicAgentRegistered, "persistence", m.onAgentRegistered)
	m.kc.Bus().Subscribe(kernel.TopicAgentTimeout, "persistence", m.onAgentTimeout)

	go m.flushLoop()
	go m.cleanupLoop()
	go m.backupLoop()
	logger.WithComponent("persistence").Info("started", "data_dir", m.dataDir)
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	m.state = kernel.PluginStopping
	m.mu.Lock()
	closeChannel := func(ch chan struct{}) {
		if ch != nil {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
	}
	closeChannel(m.flushDone)
	closeChannel(m.cleanupDone)
	closeChannel(m.backupDone)
	m.mu.Unlock()
	m.flushTicker.Stop()
	m.flushAll()

	m.mu.Lock()
	for _, w := range m.writers {
		w.close()
	}
	m.mu.Unlock()

	m.state = kernel.PluginStopped
	logger.WithComponent("persistence").Info("stopped")
	return nil
}

func (m *Module) State() kernel.PluginState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *Module) HealthCheck(ctx context.Context) error {
	m.mu.Lock()
	state := m.state
	m.mu.Unlock()
	if state != kernel.PluginStarted {
		return fmt.Errorf("persistence not started (state=%s)", state)
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

func (m *Module) Append(dataset string, record interface{}) error {
	if !m.enabled {
		return nil
	}

	if m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "persistence.pre_append", map[string]interface{}{
			"dataset": dataset,
		})
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("persistence marshal: %w", err)
	}

	writer := m.getOrCreateWriter(dataset)
	if err := writer.write(data); err != nil {
		return err
	}

	if m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "persistence.post_append", map[string]interface{}{
			"dataset": dataset,
		})
	}
	return nil
}

func (m *Module) AppendBatch(dataset string, records []interface{}) error {
	for _, rec := range records {
		if err := m.Append(dataset, rec); err != nil {
			return err
		}
	}
	return nil
}

func (m *Module) WriteAudit(entry kernel.AuditEntry) error {
	return m.Append("audit", entry)
}

func (m *Module) WriteCommand(record kernel.CommandRecord) error {
	return m.Append("commands", record)
}

func (m *Module) WriteAssessment(record kernel.AssessmentRecord) error {
	if m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "archive.pre_write", map[string]interface{}{
			"dataset":  "assessments",
			"host_id":  record.HostID,
			"score":    record.FinalScore,
			"checks":   len(record.Checks),
		})
	}
	err := m.Append("assessments", record)
	if err == nil && m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "archive.post_write", map[string]interface{}{
			"dataset": "assessments",
			"host_id": record.HostID,
			"score":   record.FinalScore,
		})
		m.kc.Extensions().Execute(m.kc.Context(), "persistence.record_written", map[string]interface{}{
			"dataset":  "assessments",
			"host_id":  record.HostID,
			"score":    record.FinalScore,
			"checks":   len(record.Checks),
		})
	}
	return err
}

func (m *Module) WriteDashboardReport(report *kernel.DashboardReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("dashboard marshal: %w", err)
	}

	path := filepath.Join(m.dataDir, "latest-assessment.json")
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("dashboard write tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		if rmErr := os.Remove(tmpPath); rmErr != nil {
			logger.WithComponent("persistence").Warn("dashboard tmp cleanup failed", "path", tmpPath, "error", rmErr)
		}
		return fmt.Errorf("dashboard rename: %w", err)
	}
	if m.kc != nil && m.kc.Extensions() != nil {
		m.kc.Extensions().Execute(m.kc.Context(), "persistence.dashboard_written", map[string]interface{}{
			"path":    path,
			"host_id": report.HostID,
		})
	}
	return nil
}

func (m *Module) WriteCVECache(record kernel.CVECacheRecord) error {
	return m.Append("cve_cache", record)
}

func (m *Module) getOrCreateWriter(dataset string) *jsonlWriter {
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

func (m *Module) flushAll() {
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

func (m *Module) flushLoop() {
	defer func() {
		if r := recover(); r != nil {
			logger.WithComponent("persistence").Error("flushLoop panic recovered", "panic", r)
		}
	}()

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

func (m *Module) RotateAll() {
	m.mu.Lock()
	for _, w := range m.writers {
		w.close()
	}
	m.mu.Unlock()
}

func (m *Module) cleanupLoop() {
	defer func() {
		if r := recover(); r != nil {
			logger.WithComponent("persistence").Error("cleanupLoop panic recovered", "panic", r)
		}
	}()

	cleanupTicker := time.NewTicker(24 * time.Hour)
	defer cleanupTicker.Stop()

	m.cleanupOldLogs()

	for {
		select {
		case <-cleanupTicker.C:
			m.cleanupOldLogs()
		case <-m.cleanupDone:
			return
		}
	}
}

func (m *Module) cleanupOldLogs() {
	cutoff := time.Now().AddDate(0, 0, -m.retentionDays)
	entries, err := os.ReadDir(m.dataDir)
	if err != nil {
		logger.WithComponent("persistence").Error("failed to read data dir for cleanup", "error", err)
		return
	}

	var removed int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(m.dataDir, entry.Name())
			if err := os.Remove(path); err != nil {
				logger.WithComponent("persistence").Warn("failed to remove old log", "path", path, "error", err)
			} else {
				removed++
			}
		}
	}
	if removed > 0 {
		logger.WithComponent("persistence").Info("cleaned up old logs",
			"removed", removed, "retention_days", m.retentionDays)
	}
}

func (m *Module) backupLoop() {
	defer func() {
		if r := recover(); r != nil {
			logger.WithComponent("persistence").Error("backupLoop panic recovered", "panic", r)
		}
	}()

	snapshotTicker := time.NewTicker(1 * time.Hour)
	archiveTicker := time.NewTicker(24 * time.Hour)
	defer snapshotTicker.Stop()
	defer archiveTicker.Stop()

	for {
		select {
		case <-snapshotTicker.C:
			m.createHourlySnapshot()
		case <-archiveTicker.C:
			m.createDailyArchive()
		case <-m.backupDone:
			m.createHourlySnapshot()
			m.createDailyArchive()
			return
		}
	}
}

func (m *Module) createHourlySnapshot() {
	snapshotDir := filepath.Join(m.dataDir, "snapshots")
	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		logger.WithComponent("persistence").Error("failed to create snapshot dir", "error", err)
		return
	}

	timestamp := time.Now().Format("20060102-150405")
	snapshotName := fmt.Sprintf("snapshot-%s.jsonl", timestamp)
	snapshotPath := filepath.Join(snapshotDir, snapshotName)

	m.mu.Lock()
	defer m.mu.Unlock()

	var totalEntries int
	snapshotFile, err := os.Create(snapshotPath)
	if err != nil {
		logger.WithComponent("persistence").Error("failed to create snapshot file", "error", err)
		return
	}
	defer snapshotFile.Close()

	entries, err := os.ReadDir(m.dataDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		src := filepath.Join(m.dataDir, entry.Name())
		f, err := os.Open(src)
		if err != nil {
			continue
		}
		_, err = io.Copy(snapshotFile, f)
		f.Close()
		if err != nil {
			logger.WithComponent("persistence").Warn("snapshot copy error", "path", src, "error", err)
		} else {
			totalEntries++
		}
	}

	logger.WithComponent("persistence").Info("hourly snapshot created",
		"path", snapshotPath, "entries", totalEntries)

	m.kc.Extensions().Execute(m.kc.Context(), "archive.rotation", map[string]interface{}{
		"type":    "snapshot",
		"path":    snapshotPath,
		"entries": totalEntries,
	})

	m.pruneSnapshots(snapshotDir, 24)
}

func (m *Module) pruneSnapshots(dir string, maxKeep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	if len(entries) <= maxKeep {
		return
	}

	for i := 0; i < len(entries)-maxKeep; i++ {
		path := filepath.Join(dir, entries[i].Name())
		if err := os.Remove(path); err != nil {
			logger.WithComponent("persistence").Warn("failed to rotate old snapshot", "path", path, "error", err)
		}
	}
}

func (m *Module) createDailyArchive() {
	archiveDir := filepath.Join(m.dataDir, "archives")
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		logger.WithComponent("persistence").Error("failed to create archive dir", "error", err)
		return
	}

	timestamp := time.Now().Format("20060102")
	archiveName := fmt.Sprintf("asscor-data-%s.tar.gz", timestamp)
	archivePath := filepath.Join(archiveDir, archiveName)

	f, err := os.Create(archivePath)
	if err != nil {
		logger.WithComponent("persistence").Error("failed to create archive file", "error", err)
		return
	}
	defer f.Close()

	gzw := gzip.NewWriter(f)
	defer gzw.Close()
	tw := tar.NewWriter(gzw)
	defer tw.Close()

	entries, err := os.ReadDir(m.dataDir)
	if err != nil {
		return
	}

	var archived int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		src := filepath.Join(m.dataDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			continue
		}
		header.Name = entry.Name()
		if err := tw.WriteHeader(header); err != nil {
			continue
		}

		srcFile, err := os.Open(src)
		if err != nil {
			continue
		}
		if _, err := io.Copy(tw, srcFile); err != nil {
			logger.WithComponent("persistence").Warn("archive copy error", "path", src, "error", err)
		}
		srcFile.Close()
		archived++
	}

	logger.WithComponent("persistence").Info("daily archive created",
		"path", archivePath, "files", archived)

	m.kc.Extensions().Execute(m.kc.Context(), "archive.rotation", map[string]interface{}{
		"type":   "daily_archive",
		"path":   archivePath,
		"files":  archived,
	})

	m.pruneArchives(archiveDir, 90)
}

func (m *Module) pruneArchives(dir string, maxDays int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -maxDays)
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			os.Remove(path)
			logger.WithComponent("persistence").Info("pruned old archive", "path", path)
		}
	}
}

func (m *Module) DataDir() string {
	return m.dataDir
}

func (m *Module) ComputeTrends(days int) ([]kernel.HostTrend, error) {
	return m.history.ComputeTrends(days)
}

func (m *Module) ComputeRiskLevels(days int) (map[string]float64, error) {
	return m.history.ComputeRiskLevels(days)
}

func (m *Module) onAssessmentResult(ctx context.Context, msg kernel.Message) error {
	payload := msg.Payload
	logger.WithComponent("persistence").Debug("received assessor.result event", "type", fmt.Sprintf("%T", payload))

	if ar, ok := payload.(*model.AssessmentResult); ok {
		logger.WithComponent("persistence").Info("processing assessment",
			"host_id", ar.HostID, "score", ar.FinalScore, "acceptable", ar.Acceptable, "checks", len(ar.Checks))

		checkDetails := make([]kernel.CheckDetail, 0, len(ar.Checks))
		for _, c := range ar.Checks {
			checkDetails = append(checkDetails, kernel.CheckDetail{
				CheckID:       c.CheckID,
				Domain:        c.Domain,
				Name:          c.Name,
				Passed:        c.Passed,
				Delta:         c.Delta,
				Detail:        c.Detail,
				ComplianceRef: c.ComplianceRef,
			})
		}

		rec := kernel.AssessmentRecord{
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
			ExtraScores:    ar.DomainScores.Extra,
			TwoFactorFail:  ar.EdgeFactors.TwoFactorFailure,
			SYNCookieDis:   ar.EdgeFactors.SYNCookieDisabled,
			SELinuxDis:     ar.EdgeFactors.SELinuxDisabled,
			AppArmorDis:    ar.EdgeFactors.AppArmorDisabled,
			NoSIEM:         ar.EdgeFactors.NoSIEM,
			NoIDS:          ar.EdgeFactors.NoIDS,
			ThreatCoeff:    ar.ThreatCoeff,
			SPCScore:       ar.SPCScore,
			PrismResultFields:   kernel.PrismFieldsFromResult(ar),
			CheckCount:     len(ar.Checks),
			Checks:         checkDetails,
		}

		for _, c := range ar.Checks {
			if !c.Passed {
				rec.FailedCount++
			}
		}

		if len(ar.SPCCVEs) > 0 {
			rec.SPCCVEs = ar.SPCCVEs
		}
		if len(ar.DomainWeightShift) > 0 {
			rec.DomainWeightShift = ar.DomainWeightShift
		}
		if len(ar.ATTACKCoverage) > 0 {
			rec.ATTACKCoverage = ar.ATTACKCoverage
		}
		if ar.ATTACKKillChain != nil {
			rec.ATTACKKillChain = ar.ATTACKKillChain
		}
		if len(ar.ATTACKAPTMatches) > 0 {
			rec.ATTACKAPTMatches = ar.ATTACKAPTMatches
		}
		if ar.ATTACKPredictedRisk != nil {
			rec.ATTACKPredictedRisk = ar.ATTACKPredictedRisk
		}
		if len(ar.ATTACKFailedTechs) > 0 {
			rec.ATTACKFailedTechs = ar.ATTACKFailedTechs
		}

		if err := m.WriteAssessment(rec); err != nil {
			logger.WithComponent("persistence").Error("write assessment failed", "host_id", ar.HostID, "error", err)
		} else {
			logger.WithComponent("persistence").Info("assessment written", "host_id", ar.HostID, "score", ar.FinalScore)
		}

		passedCount := rec.CheckCount - rec.FailedCount
		domainScores := ar.DomainScores.GetAllDomainScores()
		domainWeights := map[string]float64{
			"attack_surface":      m.cfg.Weights.AttackSurface,
			"business_continuity": m.cfg.Weights.BusinessContinuity,
			"operation_trust":     m.cfg.Weights.OperationTrust,
			"resilience":          m.cfg.Weights.Resilience,
		}
		for k, v := range m.cfg.ExtensionWeights {
			domainWeights[k] = v
		}
		edgeFactors := map[string]float64{
			"two_factor_failure":  ar.EdgeFactors.TwoFactorFailure,
			"syn_cookie_disabled": ar.EdgeFactors.SYNCookieDisabled,
			"selinux_disabled":    ar.EdgeFactors.SELinuxDisabled,
			"apparmor_disabled":   ar.EdgeFactors.AppArmorDisabled,
			"no_siem":             ar.EdgeFactors.NoSIEM,
			"no_ids":              ar.EdgeFactors.NoIDS,
		}

		report := &kernel.DashboardReport{
			SchemaVersion: "1.0",
			GeneratedAt:   time.Now(),
			HostID:        ar.HostID,
			Hostname:      ar.Hostname,
			Framework:     "ASSCOR",
			SSAMVersion:   version.SSAMVersion,
			FinalScore:    ar.FinalScore,
			Threshold:     ar.Threshold,
			Acceptable:    ar.Acceptable,
			DomainScores:  domainScores,
			DomainWeights: domainWeights,
			EdgeFactors:   edgeFactors,
			ThreatCoeff:   ar.ThreatCoeff,
			SPCScore:      ar.SPCScore,
			PrismResultFields: kernel.PrismFieldsFromResult(ar),
			Checks:        checkDetails,
			ComplianceFramework: m.cfg.ComplianceFramework,
		}
		report.Summary.TotalChecks = rec.CheckCount
		report.Summary.PassedChecks = passedCount
		report.Summary.FailedChecks = rec.FailedCount

		if len(ar.SPCCVEs) > 0 {
			report.SPCCVEs = ar.SPCCVEs
		}
		if len(ar.DomainWeightShift) > 0 {
			report.DomainWeightShift = ar.DomainWeightShift
		}
		if len(ar.ATTACKCoverage) > 0 {
			report.ATTACKCoverage = ar.ATTACKCoverage
		}
		if ar.ATTACKKillChain != nil {
			report.ATTACKKillChain = ar.ATTACKKillChain
		}
		if len(ar.ATTACKAPTMatches) > 0 {
			report.ATTACKAPTMatches = ar.ATTACKAPTMatches
		}
		if ar.ATTACKPredictedRisk != nil {
			report.ATTACKPredictedRisk = ar.ATTACKPredictedRisk
		}
		if len(ar.ATTACKFailedTechs) > 0 {
			report.ATTACKFailedTechs = ar.ATTACKFailedTechs
		}

		if err := m.WriteDashboardReport(report); err != nil {
			logger.WithComponent("persistence").Error("write dashboard report error", "error", err)
		}
		return nil
	}

	if v, ok := payload.(map[string]interface{}); ok {
		hostID, _ := v["HostID"].(string)
		finalScore, _ := v["FinalScore"].(float64)
		acceptable, _ := v["Acceptable"].(bool)

		if hostID == "" && finalScore == 0 {
			logger.WithComponent("persistence").Warn("dashboard record missing host/score, skipping")
			return nil
		}

		rec := kernel.AssessmentRecord{
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

func (m *Module) onAgentRegistered(ctx context.Context, msg kernel.Message) error {
	if hostID, ok := msg.Payload.(string); ok {
		hb, _ := m.kc.GetPlugin("heartbeat")
		if hb == nil {
			return nil
		}
		var record *kernel.AgentRegistrationRecord
		if mi, ok2 := hb.(kernel.HeartbeatInterface); ok2 {
			agent := mi.GetAgent(hostID)
			if agent != nil {
				record = &kernel.AgentRegistrationRecord{
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

func (m *Module) onAgentTimeout(ctx context.Context, msg kernel.Message) error {
	if hostID, ok := msg.Payload.(string); ok {
		record := &kernel.AgentRegistrationRecord{
			Timestamp: time.Now(),
			HostID:    hostID,
			Event:     "timeout",
		}
		m.Append("agents", record)
	}
	return nil
}