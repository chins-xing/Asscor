package adapter

import (
	"fmt"
	"os"
	"path/filepath"
)

// toolFallbackDirs are the fixed system directories probed when an adapter
// binary is not explicitly configured. Deliberately NOT a PATH lookup: an
// attacker who can influence the kernel process environment (cwd/PATH) must
// not be able to redirect `exec` at an arbitrary binary (audit H-2).
var toolFallbackDirs = []string{
	"/usr/local/bin",
	"/usr/bin",
	"/bin",
}

// ResolveConfiguredTool validates an EXPLICITLY configured adapter binary path
// (config[configKey]) and returns it when present. When the key is unset or
// empty it returns "" so the caller can substitute its own fixed, safe
// default (e.g. an install-path constant). Used by adapters whose binaries do
// not live in the standard toolFallbackDirs. A malformed configured value
// (relative path, missing file, group/world-writable) is an error — never a
// silent fallback to a different program (audit H-2).
func ResolveConfiguredTool(config map[string]string, configKey string) (string, error) {
	v := config[configKey]
	if v == "" {
		return "", nil
	}
	if err := verifyToolBinary(v); err != nil {
		return "", err
	}
	return v, nil
}

// ResolveToolBinary returns the verified absolute path of an external
// adapter binary (scanner/management CLI) that the kernel will execute.
//
// Security model (audit H-2): whatever this returns is executed by the
// kernel, so a misconfigured or tampered adapter_paths entry must never
// resolve to an arbitrary program. The rules are therefore strict:
//
//   - a configured value must be an ABSOLUTE path to a regular file that is
//     not writable by other users (no bare names, no PATH resolution, no
//     group/world-writable targets);
//   - an empty value falls back to probing toolFallbackDirs for fallbackName
//     and only accepts a regular, non-other-writable file there;
//   - anything else returns an error and the adapter reports a failed fetch
//     instead of executing.
func ResolveToolBinary(config map[string]string, configKey, fallbackName string) (string, error) {
	if v := config[configKey]; v != "" {
		if err := verifyToolBinary(v); err != nil {
			return "", err
		}
		return v, nil
	}
	for _, dir := range toolFallbackDirs {
		p := filepath.Join(dir, fallbackName)
		if err := verifyToolBinary(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("adapter binary %q not configured and not found in %v (set %s to an absolute path)",
		fallbackName, toolFallbackDirs, configKey)
}

// verifyToolBinary enforces: absolute path, existing regular file, not
// writable by group/others (so an unprivileged local user cannot swap the
// binary the kernel will execute).
func verifyToolBinary(p string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("adapter binary path must be absolute: %q", p)
	}
	info, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("adapter binary %q: %w", p, err)
	}
	if info.IsDir() || !info.Mode().IsRegular() {
		return fmt.Errorf("adapter binary %q is not a regular file", p)
	}
	if perm := info.Mode().Perm(); perm&0022 != 0 {
		return fmt.Errorf("adapter binary %q must not be group/world-writable (mode %04o)", p, perm)
	}
	return nil
}
