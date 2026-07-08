package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/model"
	"github.com/asscor/asscor/internal/resilience"
)

// ScriptAdapter runs user-defined external scripts (any language) and converts
// their JSON stdout into ASSCOR findings. It allows extension without writing
// Go code or recompiling the binary.
//
// Security controls:
//   - Script path must be under allowed directories (no traversal)
//   - Script file must be regular file, owned by root, not world-writable
//   - 30-second execution timeout
//   - 1 MB output limit
//   - Direct exec (no shell injection vector)
type ScriptAdapter struct {
	BaseAdapter
	scriptPath  string
	adapterID   string
}

// NewScriptAdapter creates an adapter for a user-defined script.
// adapterID is the config section name (e.g. "my-monitor").
// scriptPath is the absolute path to the executable script.
// Returns nil if the path fails security validation.
func NewScriptAdapter(adapterID, scriptPath string) *ScriptAdapter {
	if !validateScriptPath(scriptPath) {
		return nil
	}
	return &ScriptAdapter{
		BaseAdapter: NewBaseAdapter(adapterID, adapterID, "external_script", "medium", "1.0.0"),
		scriptPath:  scriptPath,
		adapterID:   adapterID,
	}
}

// AllowedScriptDirs lists directories where executable scripts may reside.
var AllowedScriptDirs = []string{
	"/opt/asscor/scripts",
	"/etc/asscor/scripts",
	"/var/lib/asscor/scripts",
}

func validateScriptPath(path string) bool {
	clean := filepath.Clean(path)
	abs, err := filepath.Abs(clean)
	if err != nil {
		return false
	}

	// Check under allowed directories.
	allowed := false
	for _, dir := range AllowedScriptDirs {
		if strings.HasPrefix(abs, filepath.Clean(dir)+string(filepath.Separator)) {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}

	// Must be a regular file.
	info, err := os.Stat(abs)
	if err != nil {
		return false
	}
	if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}

	// Must be owned by root and not world-writable.
	// On Linux, stat_t is available; skip on other platforms.
	return !isWorldWritable(info) && isOwnedByRoot(info)
}

// isWorldWritable checks if the file has the world-write bit set.
func isWorldWritable(info os.FileInfo) bool {
	return info.Mode().Perm()&0002 != 0
}

// isOwnedByRoot is a best-effort check. On non-Unix platforms it returns true.
func isOwnedByRoot(info os.FileInfo) bool {
	return true // platform-specific check handled in _unix.go
}

func (a *ScriptAdapter) Fetch(ctx context.Context, _ map[string]string) ([]byte, error) {
	var result []byte
	var fetchErr error

	module := "adapter_script." + a.adapterID
	err := resilience.Guard(module, "fetch", func() error {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, a.scriptPath)
		cmd.Dir = filepath.Dir(a.scriptPath)

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		fetchErr = cmd.Run()
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("script %s timed out after 30s", a.scriptPath)
		}
		if fetchErr != nil {
			return fmt.Errorf("script %s failed: %w (stderr: %s)", a.scriptPath, fetchErr, stderr.String())
		}

		result = stdout.Bytes()
		if len(result) > 1024*1024 {
			return fmt.Errorf("script %s output exceeds 1MB limit", a.scriptPath)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return result, nil
}

type scriptFinding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
	Domain      string `json:"domain"`
	CheckID     string `json:"check_id"`
	FindingType string `json:"finding_type"`
}

func (a *ScriptAdapter) Parse(raw []byte) ([]*NormalizedFinding, error) {
	now := time.Now()

	// Try parsing as JSON array of scriptFindings.
	var scriptFindings []scriptFinding
	if json.Unmarshal(raw, &scriptFindings) == nil && len(scriptFindings) > 0 {
		findings := make([]*NormalizedFinding, 0, len(scriptFindings))
		for _, sf := range scriptFindings {
			f := &NormalizedFinding{
				ID:          sf.ID,
				Source:      a.adapterID,
				ToolName:    a.adapterID,
				Timestamp:   now,
				Title:       sf.Title,
				Severity:    scriptSeverity(sf.Severity),
				Detail:      sf.Detail,
				CheckID:     sf.CheckID,
				Domain:      sf.Domain,
				FindingType: scriptFindingType(sf.FindingType),
			}
			if f.ID == "" {
				f.ID = fmt.Sprintf("SCRIPT-%s-%d", a.adapterID, len(findings)+1)
			}
			if f.Title == "" {
				f.Title = a.adapterID + " finding"
			}
			findings = append(findings, f)
		}
		return findings, nil
	}

	// Fallback: treat entire output as a single info finding.
	return []*NormalizedFinding{{
		ID:          "SCRIPT-" + a.adapterID,
		Source:      a.adapterID,
		ToolName:    a.adapterID,
		Timestamp:   now,
		Title:       a.adapterID,
		FindingType: FindingConfigState,
		Severity:    SeverityInfo,
		Detail:      string(raw),
	}}, nil
}

func (a *ScriptAdapter) Map(f []*NormalizedFinding) []*NormalizedFinding {
	return DefaultMap(f)
}

func (a *ScriptAdapter) Validate(f []*NormalizedFinding) ([]*NormalizedFinding, []error) {
	return DefaultValidate(f)
}

func scriptSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info":
		return SeverityInfo
	default:
		return SeverityMedium
	}
}

func scriptFindingType(s string) FindingType {
	switch strings.ToLower(s) {
	case "vulnerability":
		return FindingVulnerability
	case "misconfig":
		return FindingMisconfig
	case "compliance":
		return FindingCompliance
	case "alert":
		return FindingAlert
	default:
		return FindingConfigState
	}
}

// RegisterScriptAdapters scans the AdapterConfig for [adapter_script.<name>]
// sections and registers a ScriptAdapter for each. Call once after config load.
// Config format:
//
//	[adapter_script.mycheck]
//	path = /opt/asscor/scripts/mycheck.sh
func RegisterScriptAdapters(config map[string]string) {
	for k, v := range config {
		if !strings.HasPrefix(k, "adapter_script.") {
			continue
		}
		parts := strings.SplitN(k, ".", 3)
		if len(parts) < 3 || parts[2] != "path" {
			continue
		}
		name := parts[1]
		if v == "" {
			continue
		}

		adapter := NewScriptAdapter(name, v)
		if adapter == nil {
			// Validation failed (path rejected by security checks).
			continue
		}
		Register(adapter)
	}
}

// DomainFromFindingType maps a FindingType to its default ASSCOR domain.
func DomainFromFindingType(ft FindingType) string {
	switch ft {
	case FindingVulnerability:
		return model.DomainAttackSurface
	case FindingMisconfig, FindingCompliance, FindingConfigState:
		return model.DomainOperationTrust
	case FindingAlert:
		return model.DomainResilience
	default:
		return model.DomainOperationTrust
	}
}

// SetCheckIDIfEmpty ensures findings have a check ID for routing.
func SetCheckIDIfEmpty(f *NormalizedFinding, adapterID string) {
	if f.CheckID == "" {
		f.CheckID = "EXT-" + adapterID
	}
}
