package kernel

import "time"

type SourceState string

const (
	SourceStateNotInstalled SourceState = "not_installed"
	SourceStateInstalled    SourceState = "installed"
	SourceStateEnabled      SourceState = "enabled"
	SourceStateRunning      SourceState = "running"
	SourceStateError        SourceState = "error"
	SourceStateDisabled     SourceState = "disabled"
	SourceStateUninstalling SourceState = "uninstalling"
)

type SourceCategory string

const (
	SourceCategoryScanner    SourceCategory = "scanner"
	SourceCategoryManagement SourceCategory = "management"
)

type SourcePriority string

const (
	SourcePriorityP0 SourcePriority = "P0"
	SourcePriorityP1 SourcePriority = "P1"
	SourcePriorityP2 SourcePriority = "P2"
)

type SourceSpec struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Category        SourceCategory `json:"category"`
	Priority        SourcePriority `json:"priority"`
	Version         string         `json:"version"`
	Description     string         `json:"description"`
	Interface       string         `json:"interface,omitempty"`
	AdapterID       string         `json:"adapter_id"`
	OutputFormat    string         `json:"output_format"`
	AdaptDiff       string         `json:"adapt_difficulty"`
	AccessValue     string         `json:"access_value"`
	DelegatedChecks []string       `json:"delegated_checks,omitempty"`
	DependsOn       []string       `json:"depends_on,omitempty"`
}

type SourceStatus struct {
	ID           string      `json:"id"`
	State        SourceState `json:"state"`
	Version      string      `json:"version"`
	Enabled      bool        `json:"enabled"`
	LastSync     time.Time   `json:"last_sync,omitempty"`
	LastError    string      `json:"last_error,omitempty"`
	Findings     int         `json:"findings_count"`
	SyncCount    int64       `json:"sync_count"`
	ErrorCount   int64       `json:"error_count"`
	InstalledAt  time.Time   `json:"installed_at,omitempty"`
	ConfiguredAt time.Time   `json:"configured_at,omitempty"`
}

type SourceConfig struct {
	ID       string            `json:"id"`
	Settings map[string]string `json:"settings"`
}

type AuditLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	SourceID  string    `json:"source_id"`
	Operator  string    `json:"operator"`
	Detail    string    `json:"detail"`
	Success   bool      `json:"success"`
}
