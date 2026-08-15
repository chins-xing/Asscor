package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/asscor/asscor/internal/semver"
)

// PackageManifest represents a package.json file.
type PackageManifest struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Author      string            `json:"author"`
	License     string            `json:"license"`
	Modules     []ModuleEntry     `json:"modules"`
	ExternalSrc []ExternalSource  `json:"external_sources"`
	Deps        []DepEntry        `json:"dependencies"`
	Conflicts   []ConflictEntry   `json:"conflicts"`
	Compat      Compatibility     `json:"compatibility"`
	Build       BuildConfig       `json:"build"`
	Hooks       map[string]string `json:"hooks"`
}

// ModuleEntry describes one module shipped in this package.
type ModuleEntry struct {
	ID    string `json:"id"`
	Path  string `json:"path"`
	Type  string `json:"type"`  // single | library
	Entry string `json:"entry"` // Go import path override
}

// ExternalSource defines a git repository to fetch and integrate.
type ExternalSource struct {
	Repo        string `json:"repo"`
	Ref         string `json:"ref"`
	Path        string `json:"path"`
	Target      string `json:"target"`
	StripPrefix string `json:"strip_prefix"`
}

// DepEntry declares a dependency on another package or repo.
type DepEntry struct {
	Package  string `json:"package"`
	Version  string `json:"version"`
	Optional bool   `json:"optional"`
	Repo     string `json:"repo"`
	Ref      string `json:"ref"`
}

// ConflictEntry declares incompatibilities.
type ConflictEntry struct {
	Package  string `json:"package"`
	Versions string `json:"versions"`
	Reason   string `json:"reason"`
}

// Compatibility defines version/platform constraints.
type Compatibility struct {
	ASSCORVer string   `json:"asscor_version"`
	GoVer     string   `json:"go_version"`
	SSAMVer   string   `json:"ssam_version"`
	Platform  []string `json:"platform"`
}

// BuildConfig for compilation.
type BuildConfig struct {
	Tags      string            `json:"tags"`
	LDFlags   string            `json:"ldflags"`
	Env       map[string]string `json:"env"`
	PreBuild  string            `json:"pre_build"`
	PostBuild string            `json:"post_build"`
}

// LoadManifest reads and validates a package.json.
func LoadManifest(dir string) (*PackageManifest, error) {
	path := filepath.Join(dir, "package.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var m PackageManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := m.Validate(dir); err != nil {
		return nil, fmt.Errorf("validate %s: %w", path, err)
	}
	return &m, nil
}

// Validate checks required fields and format. dir is the directory containing package.json.
func (m *PackageManifest) Validate(pkgDir string) error {
	if m.Name == "" {
		return fmt.Errorf("name is required")
	}
	if !isValidPackageName(m.Name) {
		return fmt.Errorf("invalid package name %q (use lowercase alphanumeric + hyphens)", m.Name)
	}
	if m.Version == "" {
		return fmt.Errorf("version is required")
	}
	if !isSemVer(m.Version) {
		return fmt.Errorf("invalid version %q (must be SemVer 2.0)", m.Version)
	}
	if m.Compat.ASSCORVer == "" {
		return fmt.Errorf("compatibility.asscor_version is required")
	}
	modIDs := make(map[string]bool)
	for _, mod := range m.Modules {
		if mod.ID == "" {
			return fmt.Errorf("module id is required")
		}
		if mod.Path == "" {
			return fmt.Errorf("module %s path is required", mod.ID)
		}
		if modIDs[mod.ID] {
			return fmt.Errorf("duplicate module id %q", mod.ID)
		}
		modIDs[mod.ID] = true
		fullPath := filepath.Join(pkgDir, mod.Path)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			return fmt.Errorf("module %s path %s does not exist (%s)", mod.ID, mod.Path, fullPath)
		}
	}
	for _, ext := range m.ExternalSrc {
		if ext.Repo == "" {
			return fmt.Errorf("external_sources repo is required")
		}
		if ext.Target == "" {
			return fmt.Errorf("external_sources target is required")
		}
	}
	for _, dep := range m.Deps {
		if dep.Package == "" && dep.Repo == "" {
			return fmt.Errorf("dependency must specify package or repo")
		}
	}
	return nil
}

// dirOf returns the directory of the manifest file (hack: we know it's relative).
func dirOf(m *PackageManifest) string { return "" }

// DependencyGraph represents resolved relationships.
type DependencyGraph struct {
	Packages   []*PackageManifest
	Edges      []DepEdge
	Unresolved []UnresolvedDep
	Cycles     [][]string
}

// DepEdge is a directed dependency edge.
type DepEdge struct {
	From     string
	To       string
	Version  string
	Optional bool
}

// UnresolvedDep tracks a dependency that could not be satisfied.
type UnresolvedDep struct {
	Depender string
	Dep      DepEntry
	Reason   string
}

// ResolveDependencies scans a directory tree for packages and resolves their deps.
func ResolveDependencies(rootDir string) (*DependencyGraph, error) {
	g := &DependencyGraph{}

	// Phase 1: Discover all local packages
	localPkgs, err := discoverPackages(rootDir)
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	g.Packages = localPkgs

	// Phase 2: Build package index
	pkgIndex := make(map[string]*PackageManifest)
	for _, pkg := range localPkgs {
		if existing, ok := pkgIndex[pkg.Name]; ok {
			return nil, fmt.Errorf("duplicate package name %q: found in %s and %s",
				pkg.Name, existing.Name, pkg.Name)
		}
		pkgIndex[pkg.Name] = pkg
	}

	// Phase 3: Resolve each package's dependencies
	for _, pkg := range localPkgs {
		for _, dep := range pkg.Deps {
			if dep.Repo != "" {
				// External repo dependency — check if target dir exists
				targetDir := dep.Repo // placeholder: actual target would be derived
				_ = targetDir
				g.Edges = append(g.Edges, DepEdge{
					From: pkg.Name, To: dep.Repo,
					Version: dep.Ref, Optional: dep.Optional,
				})
				continue
			}

			if dep.Package == "" {
				continue
			}

			// Local package dependency
			depPkg, ok := pkgIndex[dep.Package]
			if !ok {
				g.Unresolved = append(g.Unresolved, UnresolvedDep{
					Depender: pkg.Name,
					Dep:      dep,
					Reason:   fmt.Sprintf("package %q not found in local index", dep.Package),
				})
				continue
			}

			// Version constraint check
			if dep.Version != "" {
				if !versionSatisfies(depPkg.Version, dep.Version) {
					g.Unresolved = append(g.Unresolved, UnresolvedDep{
						Depender: pkg.Name,
						Dep:      dep,
						Reason:   fmt.Sprintf("package %s version %s does not satisfy constraint %s", dep.Package, depPkg.Version, dep.Version),
					})
					continue
				}
			}

			g.Edges = append(g.Edges, DepEdge{
				From: pkg.Name, To: dep.Package,
				Version: dep.Version, Optional: dep.Optional,
			})
		}

		// Check conflicts
		for _, c := range pkg.Conflicts {
			confPkg, ok := pkgIndex[c.Package]
			if ok && (c.Versions == "" || versionSatisfies(confPkg.Version, c.Versions)) {
				g.Unresolved = append(g.Unresolved, UnresolvedDep{
					Depender: pkg.Name,
					Dep:      DepEntry{Package: c.Package},
					Reason:   fmt.Sprintf("conflict: %s", c.Reason),
				})
			}
		}
	}

	// Phase 4: Detect cycles
	g.Cycles = detectCycles(g)

	return g, nil
}

func discoverPackages(rootDir string) ([]*PackageManifest, error) {
	var pkgs []*PackageManifest
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.Name() == "package.json" {
			dir := filepath.Dir(path)
			// Skip packages inside modules (modules are not packages)
			if strings.Contains(filepath.ToSlash(dir), "/modules/") {
				return nil
			}
			m, loadErr := LoadManifest(dir)
			if loadErr != nil {
				return fmt.Errorf("load %s: %w", dir, loadErr)
			}
			pkgs = append(pkgs, m)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pkgs, nil
}

func detectCycles(g *DependencyGraph) [][]string {
	adj := make(map[string][]string)
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	var cycles [][]string
	visited := make(map[string]int) // 0=unvisited, 1=in-progress, 2=done

	var dfs func(node string, path []string)
	dfs = func(node string, path []string) {
		if visited[node] == 1 {
			// Found cycle
			start := -1
			for i, n := range path {
				if n == node {
					start = i
					break
				}
			}
			if start >= 0 {
				cycle := append([]string{}, path[start:]...)
				cycle = append(cycle, node)
				cycles = append(cycles, cycle)
			}
			return
		}
		if visited[node] == 2 {
			return
		}
		visited[node] = 1
		path = append(path, node)
		for _, neighbor := range adj[node] {
			dfs(neighbor, path)
		}
		visited[node] = 2
	}
	for node := range adj {
		if visited[node] == 0 {
			dfs(node, nil)
		}
	}
	return cycles
}

func isSemVer(v string) bool {
	_, err := semver.Parse(v)
	return err == nil
}

var pkgNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func isValidPackageName(n string) bool { return pkgNameRe.MatchString(n) }

func versionSatisfies(actual, constraint string) bool {
	if constraint == "" || actual == constraint {
		return true
	}
	av, err := semver.Parse(actual)
	if err != nil {
		return false
	}
	vc, err := semver.ParseConstraint(constraint)
	if err != nil {
		return actual == constraint
	}
	return vc.SatisfiedBy(av)
}
