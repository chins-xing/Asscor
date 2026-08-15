package extmgr

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/asscor/asscor/internal/kernel"
)

func TestParseSemVer(t *testing.T) {
	tests := []struct {
		input    string
		expected SemVer
		hasErr   bool
	}{
		{"1.0.0", SemVer{1, 0, 0, ""}, false},
		{"0.1.1", SemVer{0, 1, 1, ""}, false},
		{"2.3.4-beta", SemVer{2, 3, 4, "beta"}, false},
		{"10.20.30-rc1", SemVer{10, 20, 30, "rc1"}, false},
		{"1.0", SemVer{1, 0, 0, ""}, false},
		{"2", SemVer{2, 0, 0, ""}, false},
		{"invalid", SemVer{}, true},
		{"a.b.c", SemVer{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			v, err := ParseSemVer(tt.input)
			if tt.hasErr && err == nil {
				t.Errorf("expected error for %q, got %v", tt.input, v)
			}
			if !tt.hasErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tt.input, err)
			}
			if err == nil && v != tt.expected {
				t.Errorf("ParseSemVer(%q) = %v, want %v", tt.input, v, tt.expected)
			}
		})
	}
}

func TestSemVerCompare(t *testing.T) {
	tests := []struct {
		a, b     string
		expected int
	}{
		{"1.0.0", "1.0.0", 0},
		{"2.0.0", "1.0.0", 1},
		{"1.2.0", "1.1.0", 1},
		{"1.0.3", "1.0.2", 1},
		{"0.1.0", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0", "1.0.0-alpha", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
	}

	for _, tt := range tests {
		t.Run(tt.a+" vs "+tt.b, func(t *testing.T) {
			va, _ := ParseSemVer(tt.a)
			vb, _ := ParseSemVer(tt.b)
			got := va.Compare(vb)
			if got != tt.expected {
				t.Errorf("%s.Compare(%s) = %d, want %d", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestVersionConstraint(t *testing.T) {
	tests := []struct {
		constraint string
		version    string
		satisfied  bool
	}{
		{">=1.0.0", "1.0.0", true},
		{">=1.0.0", "1.1.0", true},
		{">=1.0.0", "0.9.0", false},
		{">1.0.0", "1.0.0", false},
		{">1.0.0", "1.0.1", true},
		{"<=2.0.0", "2.0.0", true},
		{"<=2.0.0", "1.9.0", true},
		{"<=2.0.0", "2.1.0", false},
		{"<2.0.0", "2.0.0", false},
		{"<2.0.0", "1.9.0", true},
		{"1.0.0 - 2.0.0", "1.5.0", true},
		{"1.0.0 - 2.0.0", "0.9.0", false},
		{"1.0.0 - 2.0.0", "2.1.0", false},
		{"1.5.0", "1.5.0", true},
		{"1.5.0", "1.5.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.constraint+"|"+tt.version, func(t *testing.T) {
			vc, err := ParseVersionConstraint(tt.constraint)
			if err != nil {
				t.Fatalf("parse constraint: %v", err)
			}
			ver, _ := ParseSemVer(tt.version)
			got := vc.SatisfiedBy(ver)
			if got != tt.satisfied {
				t.Errorf("%s.SatisfiedBy(%s) = %v, want %v", tt.constraint, tt.version, got, tt.satisfied)
			}
		})
	}
}

func TestExtensionSpecValidate(t *testing.T) {
	tests := []struct {
		name   string
		spec   ExtensionSpec
		hasErr bool
	}{
		{
			name: "valid spec",
			spec: ExtensionSpec{
				ID:      "test-ext",
				Name:    "Test Extension",
				Version: "1.0.0",
				ExtType: ExtTypeCheckModule,
				Source:  SourceSpec{URL: "https://example.com/ext.zip", Type: "http", Checksum: "sha256:abcdef"},
			},
			hasErr: false,
		},
		{
			name: "missing id",
			spec: ExtensionSpec{
				Name:    "No ID",
				Version: "1.0.0",
				Source:  SourceSpec{URL: "https://example.com"},
			},
			hasErr: true,
		},
		{
			name: "invalid version",
			spec: ExtensionSpec{
				ID:      "test-ext",
				Name:    "Bad Version",
				Version: "abc",
				Source:  SourceSpec{URL: "https://example.com"},
			},
			hasErr: true,
		},
		{
			name: "missing source URL",
			spec: ExtensionSpec{
				ID:      "test-ext",
				Name:    "No Source",
				Version: "1.0.0",
			},
			hasErr: true,
		},
		{
			name: "unknown type",
			spec: ExtensionSpec{
				ID:      "test-ext",
				Name:    "Bad Type",
				Version: "1.0.0",
				ExtType: "invalid_type",
				Source:  SourceSpec{URL: "https://example.com"},
			},
			hasErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()
			if tt.hasErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.hasErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestExtensionLifecycleCRUD(t *testing.T) {
	dir := t.TempDir()
	el := NewExtensionLifecycle(dir)

	spec := ExtensionSpec{
		ID:           "test-ext-1",
		Name:         "Test Extension 1",
		Version:      "1.0.0",
		ExtType:      ExtTypeCheckModule,
		Description:  "A test extension",
		Author:       "Test Author",
		Source:       SourceSpec{URL: "https://example.com/ext.zip", Type: "http"},
		CustomConfig: map[string]string{"mode": "strict"},
	}

	if err := el.Register(spec, filepath.Join(dir, "test-ext-1-1.0.0")); err != nil {
		t.Fatalf("register: %v", err)
	}

	if !el.IsInstalled("test-ext-1") {
		t.Error("expected extension to be installed")
	}

	retrieved, ok := el.Get("test-ext-1")
	if !ok || retrieved.ID != "test-ext-1" {
		t.Error("failed to retrieve extension")
	}
	if retrieved.State != ExtStateInstalled {
		t.Errorf("expected state installed, got %s", retrieved.State)
	}

	if err := el.Enable("test-ext-1"); err != nil {
		t.Fatalf("enable: %v", err)
	}

	retrieved, _ = el.Get("test-ext-1")
	if retrieved.State != ExtStateEnabled {
		t.Errorf("expected state enabled, got %s", retrieved.State)
	}

	list := el.ListEnabled()
	if len(list) != 1 || list[0].ID != "test-ext-1" {
		t.Error("list enabled mismatch")
	}

	if err := el.UpdateConfig("test-ext-1", map[string]string{"timeout": "60"}); err != nil {
		t.Fatalf("update config: %v", err)
	}
	retrieved, _ = el.Get("test-ext-1")
	if retrieved.CustomConfig["timeout"] != "60" {
		t.Error("config update failed")
	}

	if err := el.Disable("test-ext-1"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	retrieved, _ = el.Get("test-ext-1")
	if retrieved.State != ExtStateDisabled {
		t.Errorf("expected state disabled, got %s", retrieved.State)
	}

	if err := el.Delete("test-ext-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if el.IsInstalled("test-ext-1") {
		t.Error("expected extension to be deleted")
	}

	if el.Count() != 0 {
		t.Errorf("expected 0 extensions, got %d", el.Count())
	}
}

func TestExtensionDependencyCheck(t *testing.T) {
	dir := t.TempDir()
	el := NewExtensionLifecycle(dir)

	base := ExtensionSpec{
		ID: "base-ext", Name: "Base", Version: "1.0.0",
		ExtType: ExtTypeDomain, Source: SourceSpec{URL: "local:base"},
	}
	if err := el.Register(base, filepath.Join(dir, "base")); err != nil {
		t.Fatalf("register base: %v", err)
	}
	el.Enable("base-ext")

	depSpec := ExtensionSpec{
		ID: "dependent-ext", Name: "Dependent", Version: "1.0.0",
		ExtType: ExtTypeCheckModule,
		Source:  SourceSpec{URL: "local:dep"},
		Dependencies: []DependencySpec{
			{ExtensionID: "base-ext", Constraint: VersionConstraint{Min: SemVer{1, 0, 0, ""}}},
		},
	}
	if err := el.Register(depSpec, filepath.Join(dir, "dep")); err != nil {
		t.Fatalf("register dep: %v", err)
	}

	if err := el.Enable("dependent-ext"); err != nil {
		t.Fatalf("enable with satisfied dep: %v", err)
	}

	el.Disable("dependent-ext")
	el.Disable("base-ext")

	if err := el.Enable("dependent-ext"); err == nil {
		t.Error("expected error enabling when dependency is not enabled")
	}

	el.Enable("base-ext")
	el.Enable("dependent-ext")

	if err := el.Disable("base-ext"); err == nil {
		t.Error("expected error disabling when depended upon")
	}
}

func TestExtensionPersistence(t *testing.T) {
	dir := t.TempDir()
	el := NewExtensionLifecycle(dir)

	spec := ExtensionSpec{
		ID: "persist-ext", Name: "Persist", Version: "2.0.0",
		ExtType: ExtTypeHook, Source: SourceSpec{URL: "local:persist"},
	}
	el.Register(spec, filepath.Join(dir, "persist-2.0.0"))
	el.Enable("persist-ext")

	el2 := NewExtensionLifecycle(dir)
	retrieved, ok := el2.Get("persist-ext")
	if !ok {
		t.Fatal("extension not found after reload")
	}
	if retrieved.State != ExtStateEnabled {
		t.Errorf("state not persisted: got %s", retrieved.State)
	}
	if retrieved.Version != "2.0.0" {
		t.Errorf("version not persisted: got %s", retrieved.Version)
	}
	el2.Delete("persist-ext")
}

func TestExtensionLifecycleListByType(t *testing.T) {
	dir := t.TempDir()
	el := NewExtensionLifecycle(dir)

	checkExt := ExtensionSpec{
		ID: "check-ext", Name: "Check", Version: "1.0.0",
		ExtType: ExtTypeCheckModule, Source: SourceSpec{URL: "local:check"},
	}
	domainExt := ExtensionSpec{
		ID: "domain-ext", Name: "Domain", Version: "1.0.0",
		ExtType: ExtTypeDomain, Source: SourceSpec{URL: "local:domain"},
	}
	hookExt := ExtensionSpec{
		ID: "hook-ext", Name: "Hook", Version: "1.0.0",
		ExtType: ExtTypeHook, Source: SourceSpec{URL: "local:hook"},
	}

	el.Register(checkExt, filepath.Join(dir, "check"))
	el.Register(domainExt, filepath.Join(dir, "domain"))
	el.Register(hookExt, filepath.Join(dir, "hook"))

	checks := el.ListByType(ExtTypeCheckModule)
	if len(checks) != 1 || checks[0].ID != "check-ext" {
		t.Errorf("list by type check module: got %d", len(checks))
	}

	all := el.List()
	if len(all) != 3 {
		t.Errorf("list all: got %d, want 3", len(all))
	}
}

func TestExtensionSpecJSON(t *testing.T) {
	spec := ExtensionSpec{
		ID:          "json-ext",
		Name:        "JSON Extension",
		Version:     "1.2.3-beta",
		ExtType:     ExtTypeAdapter,
		Description: "An adapter extension",
		Author:      "ASSCOR Team",
		License:     "MIT",
		Source: SourceSpec{
			URL:      "https://ext.example.com/json-ext.zip",
			Type:     "http",
			Checksum: "sha256:deadbeef",
		},
		Dependencies: []DependencySpec{
			{ExtensionID: "base-lib", Constraint: VersionConstraint{Min: SemVer{1, 0, 0, ""}}},
		},
		CustomConfig: map[string]string{"log_level": "debug"},
	}

	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ExtensionSpec
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != spec.ID {
		t.Errorf("ID mismatch: %s vs %s", decoded.ID, spec.ID)
	}
	if decoded.Version != spec.Version {
		t.Errorf("Version mismatch: %s vs %s", decoded.Version, spec.Version)
	}
	if decoded.Description != spec.Description {
		t.Errorf("Description mismatch")
	}
	if len(decoded.Dependencies) != 1 {
		t.Errorf("Dependencies count: %d, want 1", len(decoded.Dependencies))
	}
}

func TestExtensionManagerInstallFromSpec(t *testing.T) {
	dir := t.TempDir()
	extDir := filepath.Join(dir, "extensions")
	stateDir := filepath.Join(dir, "state")

	localSrc := filepath.Join(dir, "local-src")
	os.MkdirAll(localSrc, 0755)
	os.WriteFile(filepath.Join(localSrc, "manifest.json"), []byte(`{"name":"test"}`), 0644)

	cfg := ManagerConfig{
		ExtensionsDir:    extDir,
		StateDir:         stateDir,
		AutoEnable:       true,
		ExecutionPolicy:  ExecPolicyWhitelist,
		ExecutionTimeout: 30 * time.Second,
		WhiteListedCmds:  []string{"test"},
	}

	mgr := NewExtensionManager(cfg)

	spec := ExtensionSpec{
		ID:      "mgr-test-ext",
		Name:    "Manager Test",
		Version: "1.0.0",
		ExtType: ExtTypeDomain,
		Source:  SourceSpec{URL: localSrc, Type: "local"},
	}

	if err := mgr.InstallFromSpec(spec); err != nil {
		t.Fatalf("install from spec: %v", err)
	}

	if !mgr.IsInstalled("mgr-test-ext") {
		t.Error("extension not installed")
	}

	retrieved, ok := mgr.Get("mgr-test-ext")
	if !ok {
		t.Fatal("extension not found")
	}
	if retrieved.State != ExtStateEnabled {
		t.Errorf("expected enabled, got %s", retrieved.State)
	}

	if err := mgr.Disable("mgr-test-ext"); err != nil {
		t.Fatalf("disable: %v", err)
	}

	if err := mgr.Delete("mgr-test-ext"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if mgr.IsInstalled("mgr-test-ext") {
		t.Error("extension still installed after delete")
	}
}

func TestExtensionManagerRepository(t *testing.T) {
	dir := t.TempDir()

	cfg := ManagerConfig{
		ExtensionsDir:  filepath.Join(dir, "extensions"),
		StateDir:       filepath.Join(dir, "state"),
		RepositoryURLs: []string{"https://repo1.example.com", "https://repo2.example.com"},
	}

	mgr := NewExtensionManager(cfg)

	repos := mgr.ListRepositories()
	if len(repos) != 2 {
		t.Errorf("expected 2 repos, got %d", len(repos))
	}

	mgr.AddRepository("test-repo", "https://test.example.com")
	if len(mgr.ListRepositories()) != 3 {
		t.Error("add repository failed")
	}

	mgr.RemoveRepository("test-repo")
	if len(mgr.ListRepositories()) != 2 {
		t.Error("remove repository failed")
	}
}

func TestExtensionSpecVerifyIntegrity(t *testing.T) {
	tests := []struct {
		name    string
		spec    ExtensionSpec
		data    []byte
		wantErr bool
	}{
		{
			name:    "no checksum - should pass",
			spec:    ExtensionSpec{Source: SourceSpec{Checksum: ""}},
			data:    []byte("hello"),
			wantErr: false,
		},
		{
			name: "correct sha256",
			spec: ExtensionSpec{
				Source: SourceSpec{Checksum: "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
			},
			data:    []byte("hello"),
			wantErr: false,
		},
		{
			name: "incorrect sha256",
			spec: ExtensionSpec{
				Source: SourceSpec{Checksum: "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
			},
			data:    []byte("hello"),
			wantErr: true,
		},
		{
			name: "unsupported algorithm",
			spec: ExtensionSpec{
				Source: SourceSpec{Checksum: "md5:abc"},
			},
			data:    []byte("hello"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.VerifyIntegrity(tt.data)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestDetectSourceType(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://example.com/ext.zip", "http"},
		{"http://example.com/ext.tar.gz", "http"},
		{"git://github.com/user/repo.git", "git"},
		{"git+https://github.com/user/repo", "git"},
		{"https://github.com/ASSCOR/extensions.git", "git"},
		{"https://gitlab.com/group/project.git", "git"},
		{"/local/path/to/ext", "local"},
		{"C:\\local\\path", "local"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := detectSourceType(tt.url)
			if got != tt.expected {
				t.Errorf("detectSourceType(%s) = %s, want %s", tt.url, got, tt.expected)
			}
		})
	}
}

func TestExtensionExecutorConfig(t *testing.T) {
	cfg := DefaultExecutionConfig()
	if cfg.Policy != ExecPolicyWhitelist {
		t.Errorf("default policy: %s", cfg.Policy)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("default timeout: %v", cfg.Timeout)
	}

	executor := NewExtensionExecutor(cfg)
	executor.SetWhitelist([]string{"python3", "node"})

	if !executor.isCommandAllowed("python3") {
		t.Error("python3 should be allowed")
	}
	if executor.isCommandAllowed("malware") {
		t.Error("malware should not be allowed")
	}
}

func TestExtensionLifecycleSetError(t *testing.T) {
	dir := t.TempDir()
	el := NewExtensionLifecycle(dir)

	spec := ExtensionSpec{
		ID: "error-ext", Name: "Error Test", Version: "1.0.0",
		ExtType: ExtTypeCustom, Source: SourceSpec{URL: "local:err"},
	}
	el.Register(spec, filepath.Join(dir, "err-ext"))

	el.SetError("error-ext", "something went wrong")

	retrieved, _ := el.Get("error-ext")
	if retrieved.State != ExtStateError {
		t.Errorf("expected error state, got %s", retrieved.State)
	}
	if retrieved.Error != "something went wrong" {
		t.Errorf("expected error message, got %s", retrieved.Error)
	}
}

func TestExtensionSpecSemVer(t *testing.T) {
	spec := ExtensionSpec{ID: "vtest", Name: "VTest", Version: "3.2.1-rc2"}
	sv, err := spec.SemVer()
	if err != nil {
		t.Fatalf("SemVer: %v", err)
	}
	if sv.Major != 3 || sv.Minor != 2 || sv.Patch != 1 || sv.Pre != "rc2" {
		t.Errorf("unexpected semver: %v", sv)
	}
}

func TestDuplicateRegistration(t *testing.T) {
	dir := t.TempDir()
	el := NewExtensionLifecycle(dir)

	spec := ExtensionSpec{
		ID: "dup-ext", Name: "Dup", Version: "1.0.0",
		ExtType: ExtTypeScoringPlugin, Source: SourceSpec{URL: "local:dup"},
	}
	el.Register(spec, filepath.Join(dir, "dup"))

	err := el.Register(spec, filepath.Join(dir, "dup2"))
	if err == nil {
		t.Error("expected error on duplicate registration")
	}
}

func TestGetDependents(t *testing.T) {
	dir := t.TempDir()
	el := NewExtensionLifecycle(dir)

	base := ExtensionSpec{
		ID: "base-lib", Name: "Base Lib", Version: "2.0.0",
		ExtType: ExtTypeDomain, Source: SourceSpec{URL: "local:base"},
	}
	el.Register(base, filepath.Join(dir, "base"))
	el.Enable("base-lib")

	dep1 := ExtensionSpec{
		ID: "consumer-1", Name: "Consumer 1", Version: "1.0.0",
		ExtType: ExtTypeCheckModule, Source: SourceSpec{URL: "local:c1"},
		Dependencies: []DependencySpec{
			{ExtensionID: "base-lib", Constraint: VersionConstraint{Min: SemVer{1, 0, 0, ""}}},
		},
	}
	el.Register(dep1, filepath.Join(dir, "c1"))

	dep2 := ExtensionSpec{
		ID: "consumer-2", Name: "Consumer 2", Version: "1.0.0",
		ExtType: ExtTypeHook, Source: SourceSpec{URL: "local:c2"},
		Dependencies: []DependencySpec{
			{ExtensionID: "base-lib", Constraint: VersionConstraint{Min: SemVer{1, 0, 0, ""}}},
		},
	}
	el.Register(dep2, filepath.Join(dir, "c2"))

	deps := el.GetDependents("base-lib")
	if len(deps) != 2 {
		t.Errorf("expected 2 dependents, got %d: %v", len(deps), deps)
	}
}

func TestExportState(t *testing.T) {
	dir := t.TempDir()
	extDir := filepath.Join(dir, "extensions")
	stateDir := filepath.Join(dir, "state")

	localSrc := filepath.Join(dir, "local-src-export")
	os.MkdirAll(localSrc, 0755)
	os.WriteFile(filepath.Join(localSrc, "data.json"), []byte(`{"name":"test"}`), 0644)

	cfg := ManagerConfig{
		ExtensionsDir:   extDir,
		StateDir:        stateDir,
		AutoEnable:      false,
		ExecutionPolicy: ExecPolicyWhitelist,
	}

	mgr := NewExtensionManager(cfg)

	spec := ExtensionSpec{
		ID: "export-ext", Name: "Export Test", Version: "1.0.0",
		ExtType: ExtTypeDomain, Source: SourceSpec{URL: localSrc, Type: "local"},
	}
	mgr.InstallFromSpec(spec)

	data, err := mgr.ExportState()
	if err != nil {
		t.Fatalf("export state: %v", err)
	}

	var extensions []ExtensionSpec
	if err := json.Unmarshal(data, &extensions); err != nil {
		t.Fatalf("unmarshal exported state: %v", err)
	}
	if len(extensions) != 1 {
		t.Fatalf("expected 1 extension in export, got %d", len(extensions))
	}
	if extensions[0].ID != "export-ext" {
		t.Errorf("unexpected extension ID: %s", extensions[0].ID)
	}
}

func TestExtensionExecutorValidation(t *testing.T) {
	dir := t.TempDir()
	specDir := filepath.Join(dir, "test-ext")
	os.MkdirAll(specDir, 0755)
	os.WriteFile(filepath.Join(specDir, "run.sh"), []byte("#!/bin/sh\necho hello\n"), 0755)
	os.MkdirAll(filepath.Join(specDir, "scripts"), 0755)
	os.WriteFile(filepath.Join(specDir, "scripts", "deploy.sh"), []byte("#!/bin/sh\necho deploy\n"), 0755)

	spec := ExtensionSpec{
		ID: "exec-ext", Name: "Exec Test", Version: "1.0.0",
		ExtType: ExtTypeCustom, InstallPath: specDir,
		State: ExtStateEnabled,
	}

	cfg := ExecutionConfig{
		Policy:      ExecPolicyAllowed,
		Timeout:     5 * time.Second,
		BinaryPaths: make(map[string]string),
		Environment: make(map[string]string),
	}
	executor := NewExtensionExecutor(cfg)

	if err := executor.ValidateScript(nil, spec, "run.sh"); err != nil {
		t.Errorf("validate run.sh: %v", err)
	}
	if err := executor.ValidateScript(nil, spec, "scripts/deploy.sh"); err != nil {
		t.Errorf("validate scripts/deploy.sh: %v", err)
	}
	if err := executor.ValidateScript(nil, spec, "nonexistent.sh"); err == nil {
		t.Error("expected error for nonexistent script")
	}
}

func TestManagerSingleton(t *testing.T) {
	mgr1 := GetManager()
	mgr2 := GetManager()
	if mgr1 != mgr2 {
		t.Error("GetManager should return the same instance")
	}
}

func TestSemVerString(t *testing.T) {
	tests := []struct {
		sv       SemVer
		expected string
	}{
		{SemVer{1, 0, 0, ""}, "1.0.0"},
		{SemVer{2, 5, 3, "beta"}, "2.5.3-beta"},
		{SemVer{0, 1, 0, ""}, "0.1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.sv.String()
			if got != tt.expected {
				t.Errorf("String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExtensionBridgeToKernelExtensionPoints(t *testing.T) {
	extReg := kernel.NewExtensionRegistry()
	extReg.RegisterPoint(kernel.ExtensionPoint{Name: "assessor.pre_evaluate"})

	mgr := NewExtensionManager(DefaultManagerConfig())
	mgr.SetKernelExtensions(extReg)

	spec := ExtensionSpec{
		ID:           "test-bridge-plugin",
		Name:         "Test Bridge Plugin",
		Version:      "1.0.0",
		ExtType:      ExtTypeHook,
		InstallPath:  t.TempDir(),
		CustomConfig: map[string]string{"extension_point": "assessor.pre_evaluate"},
		State:        ExtStateEnabled,
	}

	mgr.onExtensionInstalled(spec)

	exts := extReg.ListExtensions("assessor.pre_evaluate")
	if len(exts) != 1 {
		t.Fatalf("expected 1 extension on assessor.pre_evaluate, got %d: %v", len(exts), exts)
	}
	if exts[0] != "test-bridge-plugin" {
		t.Errorf("expected 'test-bridge-plugin', got %s", exts[0])
	}
}

func TestExtensionBridgeDisableUnregisters(t *testing.T) {
	extReg := kernel.NewExtensionRegistry()
	extReg.RegisterPoint(kernel.ExtensionPoint{Name: "assessor.pre_evaluate"})

	mgr := NewExtensionManager(DefaultManagerConfig())
	mgr.SetKernelExtensions(extReg)

	spec := ExtensionSpec{
		ID:           "test-disable-plugin",
		Name:         "Test Disable",
		Version:      "1.0.0",
		ExtType:      ExtTypeHook,
		InstallPath:  t.TempDir(),
		CustomConfig: map[string]string{"extension_point": "assessor.pre_evaluate"},
		State:        ExtStateEnabled,
	}

	mgr.onExtensionInstalled(spec)
	if exts := extReg.ListExtensions("assessor.pre_evaluate"); len(exts) != 1 {
		t.Fatalf("expected 1 after install, got %d", len(exts))
	}

	mgr.onExtensionDisabled(spec)
	if exts := extReg.ListExtensions("assessor.pre_evaluate"); len(exts) != 0 {
		t.Fatalf("expected 0 after disable, got %d", len(exts))
	}
}
