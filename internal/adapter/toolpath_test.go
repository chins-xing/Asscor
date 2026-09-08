package adapter

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestResolveToolBinaryRejectsUnsafeConfig covers audit H-2: a tampered or
// misconfigured adapter_paths entry must never resolve to an arbitrary
// program for the kernel to execute. Permission semantics are Unix-only
// (Go's os.Chmod is a no-op for these bits on Windows), so the write-bit
// assertions run only on Unix.
func TestResolveToolBinaryRejectsUnsafeConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission semantics are unix-only")
	}
	tmp := t.TempDir()

	// Relative paths are refused outright.
	if _, err := ResolveToolBinary(map[string]string{"adapter_paths.x": "mybin"}, "adapter_paths.x", "fallback"); err == nil {
		t.Error("relative configured path must be rejected")
	}

	// A group/world-writable absolute binary is refused. Explicit Chmod
	// after write: os.WriteFile applies umask, which would silently strip
	// the other-write bit under the typical 022.
	evil := filepath.Join(tmp, "evil")
	if err := os.WriteFile(evil, []byte("#!/bin/sh\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(evil, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveToolBinary(map[string]string{"adapter_paths.x": evil}, "adapter_paths.x", "fallback"); err == nil {
		t.Error("world-writable binary must be rejected")
	}

	// A non-existent absolute path is refused.
	if _, err := ResolveToolBinary(map[string]string{"adapter_paths.x": filepath.Join(tmp, "nope")}, "adapter_paths.x", "fallback"); err == nil {
		t.Error("non-existent binary must be rejected")
	}
}

func TestResolveToolBinaryAcceptsSafeAbsolute(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission semantics are unix-only")
	}
	tmp := t.TempDir()
	good := filepath.Join(tmp, "goodbin")
	if err := os.WriteFile(good, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveToolBinary(map[string]string{"adapter_paths.x": good}, "adapter_paths.x", "fallback")
	if err != nil {
		t.Fatalf("safe absolute path rejected: %v", err)
	}
	if got != good {
		t.Fatalf("got %q, want %q", got, good)
	}
}

func TestResolveConfiguredToolUnsetReturnsEmpty(t *testing.T) {
	got, err := ResolveConfiguredTool(map[string]string{}, "adapter_paths.none")
	if err != nil {
		t.Fatalf("unset key must not error: %v", err)
	}
	if got != "" {
		t.Fatalf("unset key must return empty string, got %q", got)
	}

	// A configured but unsafe value is an error, never a silent fallback.
	if _, err := ResolveConfiguredTool(map[string]string{"adapter_paths.x": "barename"}, "adapter_paths.x"); err == nil {
		t.Error("bare-name configured path must be rejected")
	}
}
