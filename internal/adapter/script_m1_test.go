//go:build linux

package adapter

import (
	"os"
	"path/filepath"
	"testing"
)

// TestValidateScriptPathRejectsSymlink (audit M-1): os.Lstat must be used so a
// symlink planted in an allowed scripts directory is rejected outright —
// os.Stat follows the link, making ModeSymlink always 0 and letting the
// symlink masquerade as a regular file pointing at an arbitrary binary.
func TestValidateScriptPathRejectsSymlink(t *testing.T) {
	dir := t.TempDir()

	// Point the allowlist at our temp dir so the path-prefix check passes and
	// the test isolates the symlink behaviour. Restore afterwards.
	orig := AllowedScriptDirs
	AllowedScriptDirs = []string{dir}
	defer func() { AllowedScriptDirs = orig }()

	// A real regular file inside the allowed dir (owner may be non-root; we
	// only assert the symlink REJECTION path here, which fires before the
	// owner check — see validateScriptPath order).
	realFile := filepath.Join(dir, "real.sh")
	if err := os.WriteFile(realFile, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Symlink inside the allowed dir pointing at the regular file.
	link := filepath.Join(dir, "evil.sh")
	if err := os.Symlink(realFile, link); err != nil {
		t.Fatalf("cannot create symlink (needs privilege?): %v", err)
	}

	if validateScriptPath(link) {
		t.Error("symlink inside an allowed scripts dir must be rejected (audit M-1)")
	}

	// Sanity: the symlink actually resolves (so the test is meaningful — the
	// target is a real executable the old os.Stat path would have followed).
	target, err := os.Readlink(link)
	if err != nil || target != realFile {
		t.Fatalf("symlink setup broken: target=%q err=%v", target, err)
	}
}
