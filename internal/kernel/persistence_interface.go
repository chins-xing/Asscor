package kernel

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
	ComputeTrends(days int) ([]HostTrend, error)
	ComputeRiskLevels(days int) (map[string]float64, error)
}
