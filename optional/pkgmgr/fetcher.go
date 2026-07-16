package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// FetchExternalSources resolves all external_sources entries for a package.
func FetchExternalSources(pkg *PackageManifest, pkgDir string, force bool) error {
	for _, src := range pkg.ExternalSrc {
		targetDir := filepath.Join(pkgDir, src.Target)

		// Skip if already fetched and not forced
		if !force {
			if info, err := os.Stat(targetDir); err == nil && info.IsDir() {
				fmt.Printf("  [skip] %s already exists at %s (use --force to re-fetch)\n", src.Repo, src.Target)
				continue
			}
		}

		fmt.Printf("  [fetch] %s", src.Repo)
		if src.Ref != "" {
			fmt.Printf(" @ %s", src.Ref)
		}
		fmt.Println()

		if err := gitClone(src.Repo, src.Ref, targetDir, src.Path, src.StripPrefix); err != nil {
			return fmt.Errorf("fetch %s: %w", src.Repo, err)
		}
	}
	return nil
}

func gitClone(repoURL, ref, targetDir, subPath, stripPrefix string) error {
	// Create temp directory for clone
	tmpDir, err := os.MkdirTemp("", "asscor-pkg-clone-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Shallow clone
	args := []string{"clone", "--depth=1"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, repoURL, tmpDir)

	cmd := exec.Command("git", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone %s: %w", repoURL, err)
	}

	// Determine source directory
	srcDir := tmpDir
	if subPath != "" {
		srcDir = filepath.Join(tmpDir, subPath)
	}

	// Apply strip prefix
	if stripPrefix != "" {
		prefix := filepath.Join(srcDir, stripPrefix)
		if info, err := os.Stat(prefix); err == nil && info.IsDir() {
			srcDir = prefix
		}
	}

	// Ensure parent dir exists
	parentDir := filepath.Dir(targetDir)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("create parent dir %s: %w", parentDir, err)
	}

	// Move to target
	os.RemoveAll(targetDir) // clean old
	if err := os.Rename(srcDir, targetDir); err != nil {
		// Fallback: copy
		return copyDir(srcDir, targetDir)
	}
	return nil
}

func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			data, err := os.ReadFile(srcPath)
			if err != nil {
				return err
			}
			if err := os.WriteFile(dstPath, data, 0644); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateCompatibility checks version and platform constraints.
func ValidateCompatibility(pkg *PackageManifest) []string {
	var warnings []string

	if pkg.Compat.ASSCORVer != "" {
		if !versionSatisfies(getASSCORVersion(), pkg.Compat.ASSCORVer) {
			warnings = append(warnings, fmt.Sprintf("ASSCOR %s required, but detected %s — package may not work correctly",
				pkg.Compat.ASSCORVer, getASSCORVersion()))
		}
	}
	if pkg.Compat.GoVer != "" {
		if !versionSatisfies(getGoVersion(), pkg.Compat.GoVer) {
			warnings = append(warnings, fmt.Sprintf("Go %s required", pkg.Compat.GoVer))
		}
	}
	if len(pkg.Compat.Platform) > 0 {
		currentPlatform := getCurrentPlatform()
		found := false
		for _, p := range pkg.Compat.Platform {
			if strings.EqualFold(currentPlatform, p) {
				found = true
				break
			}
		}
		if !found {
			warnings = append(warnings, fmt.Sprintf("package requires one of %v, but current platform is %s",
				pkg.Compat.Platform, currentPlatform))
		}
	}
	return warnings
}

func getASSCORVersion() string { return "0.2.1" }
func getGoVersion() string     { return "1.26" }
func getCurrentPlatform() string {
	if _, err := exec.LookPath("uname"); err == nil {
		out, _ := exec.Command("uname", "-s").Output()
		return strings.TrimSpace(strings.ToLower(string(out)))
	}
	return "unknown"
}
