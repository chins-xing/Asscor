package extmgr

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/argus-security/argus/internal/logger"
)

type extensionRecord struct {
	Spec       ExtensionSpec `json:"spec"`
	EnabledAt  time.Time     `json:"enabled_at,omitempty"`
	DisabledAt time.Time     `json:"disabled_at,omitempty"`
}

type ExtensionLifecycle struct {
	mu       sync.RWMutex
	records  map[string]*extensionRecord
	stateDir string
	order    []string
}

func NewExtensionLifecycle(stateDir string) *ExtensionLifecycle {
	os.MkdirAll(stateDir, 0755)
	el := &ExtensionLifecycle{
		records:  make(map[string]*extensionRecord),
		stateDir: stateDir,
	}
	el.loadState()
	return el
}

func (el *ExtensionLifecycle) stateFile() string {
	return filepath.Join(el.stateDir, "extensions_state.json")
}

func (el *ExtensionLifecycle) Register(spec ExtensionSpec, installPath string) error {
	el.mu.Lock()
	defer el.mu.Unlock()

	if _, exists := el.records[spec.ID]; exists {
		return fmt.Errorf("extension %s is already registered", spec.ID)
	}

	spec.InstallPath = installPath
	spec.State = ExtStateInstalled
	if spec.InstallTime.IsZero() {
		spec.InstallTime = time.Now()
	}

	el.records[spec.ID] = &extensionRecord{Spec: spec}
	el.order = append(el.order, spec.ID)

	if err := el.saveState(); err != nil {
		return fmt.Errorf("save state: %w", err)
	}

	logger.WithComponent("extmgr").Info("registered extension", "extension_id", spec.ID, "version", spec.Version)
	return nil
}

func (el *ExtensionLifecycle) Enable(id string) error {
	el.mu.Lock()
	defer el.mu.Unlock()

	rec, exists := el.records[id]
	if !exists {
		return fmt.Errorf("extension %s not found", id)
	}

	if rec.Spec.State == ExtStateEnabled {
		return fmt.Errorf("extension %s is already enabled", id)
	}

	for _, dep := range rec.Spec.Dependencies {
		depRec, ok := el.records[dep.ExtensionID]
		if !ok {
			return fmt.Errorf("dependency %s not installed for %s", dep.ExtensionID, id)
		}
		if depRec.Spec.State != ExtStateEnabled {
			return fmt.Errorf("dependency %s is not enabled for %s", dep.ExtensionID, id)
		}
		depVer, err := depRec.Spec.SemVer()
		if err != nil {
			return fmt.Errorf("dependency %s has invalid version: %w", dep.ExtensionID, err)
		}
		if !dep.Constraint.SatisfiedBy(depVer) {
			return fmt.Errorf("dependency %s version %s does not satisfy constraint (min=%s max=%s)",
				dep.ExtensionID, depVer, dep.Constraint.Min, dep.Constraint.Max)
		}
	}

	rec.Spec.State = ExtStateEnabled
	rec.EnabledAt = time.Now()
	rec.Spec.Error = ""

	if err := el.saveState(); err != nil {
		return fmt.Errorf("save state: %w", err)
	}

	logger.WithComponent("extmgr").Info("enabled extension", "extension_id", id)
	return nil
}

func (el *ExtensionLifecycle) Disable(id string) error {
	el.mu.Lock()
	defer el.mu.Unlock()

	rec, exists := el.records[id]
	if !exists {
		return fmt.Errorf("extension %s not found", id)
	}

	if rec.Spec.State == ExtStateDisabled {
		return fmt.Errorf("extension %s is already disabled", id)
	}

	for checkID, checkRec := range el.records {
		if checkID == id {
			continue
		}
		if checkRec.Spec.State != ExtStateEnabled {
			continue
		}
		for _, dep := range checkRec.Spec.Dependencies {
			if dep.ExtensionID == id {
				return fmt.Errorf("cannot disable %s: depended on by %s", id, checkID)
			}
		}
	}

	rec.Spec.State = ExtStateDisabled
	rec.DisabledAt = time.Now()

	if err := el.saveState(); err != nil {
		return fmt.Errorf("save state: %w", err)
	}

	logger.WithComponent("extmgr").Info("disabled extension", "extension_id", id)
	return nil
}

func (el *ExtensionLifecycle) Delete(id string) error {
	el.mu.Lock()
	defer el.mu.Unlock()

	rec, exists := el.records[id]
	if !exists {
		return fmt.Errorf("extension %s not found", id)
	}

	for checkID, checkRec := range el.records {
		if checkID == id {
			continue
		}
		for _, dep := range checkRec.Spec.Dependencies {
			if dep.ExtensionID == id {
				return fmt.Errorf("cannot delete %s: depended on by %s", id, checkID)
			}
		}
	}

	installPath := rec.Spec.InstallPath
	if installPath != "" {
		if err := os.RemoveAll(installPath); err != nil {
			logger.WithComponent("extmgr").Warn("failed to remove path", "path", installPath, "error", err)
		}
	}

	delete(el.records, id)
	newOrder := make([]string, 0, len(el.order))
	for _, oid := range el.order {
		if oid != id {
			newOrder = append(newOrder, oid)
		}
	}
	el.order = newOrder

	if err := el.saveState(); err != nil {
		return fmt.Errorf("save state: %w", err)
	}

	logger.WithComponent("extmgr").Info("deleted extension", "extension_id", id)
	return nil
}

func (el *ExtensionLifecycle) Get(id string) (ExtensionSpec, bool) {
	el.mu.RLock()
	defer el.mu.RUnlock()
	rec, exists := el.records[id]
	if !exists {
		return ExtensionSpec{}, false
	}
	return rec.Spec, true
}

func (el *ExtensionLifecycle) List() []ExtensionSpec {
	el.mu.RLock()
	defer el.mu.RUnlock()

	result := make([]ExtensionSpec, 0, len(el.records))
	for _, id := range el.order {
		if rec, exists := el.records[id]; exists {
			result = append(result, rec.Spec)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].InstallTime.Before(result[j].InstallTime)
	})
	return result
}

func (el *ExtensionLifecycle) ListByType(extType ExtensionType) []ExtensionSpec {
	all := el.List()
	var result []ExtensionSpec
	for _, s := range all {
		if s.ExtType == extType {
			result = append(result, s)
		}
	}
	return result
}

func (el *ExtensionLifecycle) ListByState(state ExtensionState) []ExtensionSpec {
	all := el.List()
	var result []ExtensionSpec
	for _, s := range all {
		if s.State == state {
			result = append(result, s)
		}
	}
	return result
}

func (el *ExtensionLifecycle) ListEnabled() []ExtensionSpec {
	return el.ListByState(ExtStateEnabled)
}

func (el *ExtensionLifecycle) IsInstalled(id string) bool {
	el.mu.RLock()
	defer el.mu.RUnlock()
	_, exists := el.records[id]
	return exists
}

func (el *ExtensionLifecycle) SetError(id string, errMsg string) {
	el.mu.Lock()
	defer el.mu.Unlock()
	if rec, exists := el.records[id]; exists {
		rec.Spec.State = ExtStateError
		rec.Spec.Error = errMsg
	}
}

func (el *ExtensionLifecycle) UpdateConfig(id string, config map[string]string) error {
	el.mu.Lock()
	defer el.mu.Unlock()

	rec, exists := el.records[id]
	if !exists {
		return fmt.Errorf("extension %s not found", id)
	}

	if rec.Spec.CustomConfig == nil {
		rec.Spec.CustomConfig = make(map[string]string)
	}
	for k, v := range config {
		rec.Spec.CustomConfig[k] = v
	}

	return el.saveState()
}

func (el *ExtensionLifecycle) Count() int {
	el.mu.RLock()
	defer el.mu.RUnlock()
	return len(el.records)
}

func (el *ExtensionLifecycle) GetDependents(id string) []string {
	el.mu.RLock()
	defer el.mu.RUnlock()

	var dependents []string
	for oid, rec := range el.records {
		for _, dep := range rec.Spec.Dependencies {
			if dep.ExtensionID == id {
				dependents = append(dependents, oid)
				break
			}
		}
	}
	return dependents
}

func (el *ExtensionLifecycle) ValidateDependencies(spec ExtensionSpec) error {
	el.mu.RLock()
	defer el.mu.RUnlock()

	for _, dep := range spec.Dependencies {
		rec, exists := el.records[dep.ExtensionID]
		if !exists {
			return fmt.Errorf("missing dependency: %s", dep.ExtensionID)
		}
		depVer, err := rec.Spec.SemVer()
		if err != nil {
			return fmt.Errorf("dependency %s has invalid version: %w", dep.ExtensionID, err)
		}
		if !dep.Constraint.SatisfiedBy(depVer) {
			return fmt.Errorf("dependency %s version %s does not satisfy constraint (min=%s max=%s)", dep.ExtensionID, depVer, dep.Constraint.Min, dep.Constraint.Max)
		}
	}
	return nil
}

func (el *ExtensionLifecycle) saveState() error {
	data := make(map[string]extensionRecord, len(el.records))
	for id, rec := range el.records {
		data[id] = *rec
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(el.stateFile(), jsonData, 0644)
}

func (el *ExtensionLifecycle) loadState() {
	data, err := os.ReadFile(el.stateFile())
	if err != nil {
		return
	}

	var records map[string]extensionRecord
	if err := json.Unmarshal(data, &records); err != nil {
		logger.WithComponent("extmgr").Error("failed to load state", "error", err)
		return
	}

	for id, rec := range records {
		r := rec
		el.records[id] = &r
		el.order = append(el.order, id)
	}

	logger.WithComponent("extmgr").Info("loaded extension records from state", "count", len(records))
}
