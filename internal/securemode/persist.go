package securemode

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SecretsFilePath returns the encrypted registry path under dataDir. The
// registry is only persisted while the kernel is in run mode (spec §10.1
// P0-1): it is written after every registration/rotation, recovered on the
// run-mode restart path, re-encrypted on kernel password rotation, and removed
// when the kernel exits run mode.
func SecretsFilePath(dataDir string) string {
	return filepath.Join(dataDir, ".asscor-secrets.enc")
}

// PersistSecrets atomically writes the current registry encrypted under the
// retained kernel run-mode password (spec §10.1: "用内核自身运行模式密钥加密登记
// 表"). In default mode there is no run-mode registry to persist, so it is a
// no-op (the kernel wiring calls it after every heartbeat registration without
// checking the mode). The run-mode password is retained in memory by
// EnterRun/Unlock and refreshed by SetPassword, so registrations arriving at
// any time can re-persist without operator input; it is dropped on ExitRun.
//
// The payload is the plaintext Marshal JSON wrapped with the standard envelope
// encryption (Encrypt) — the same primitive that protects the kernel config,
// so the registry is never stored in plaintext on disk.
func (c *Controller) PersistSecrets() error {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if c.Mode != ModeRun {
		return nil // default mode: nothing to persist
	}
	if c.runPassword == "" {
		return errors.New("persist secrets: no run-mode password retained (enter or unlock first)")
	}
	return c.persistSecretsLocked()
}

// LoadSecrets restores the registry from the encrypted file (kernel restart
// recovery, spec §10.1 recovery flow step 1). A missing file means nothing was
// persisted — the registry is left as-is (a fresh controller already starts
// empty; agents re-register on their next heartbeat). A file that cannot be
// decrypted (wrong password, tampering, disk corruption) fails CLOSED: the
// error is returned, the file is preserved for manual recovery, and the
// registry is not modified. Unlock calls this automatically so a corrupt
// registry refuses the kernel to serve run mode.
func (c *Controller) LoadSecrets(password string) error {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	return c.loadSecretsLocked(password)
}

// persistSecretsLocked encrypts and atomically writes the registry with the
// retained run-mode password. Caller holds c.Mu.
func (c *Controller) persistSecretsLocked() error {
	data, err := c.Secrets.Marshal()
	if err != nil {
		return fmt.Errorf("persist secrets: marshal: %w", err)
	}
	payload, err := Encrypt(data, c.runPassword)
	if err != nil {
		return fmt.Errorf("persist secrets: encrypt: %w", err)
	}
	path := SecretsFilePath(c.DataDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return fmt.Errorf("persist secrets: %w", err)
	}
	if err := syncFile(tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("persist secrets: fsync: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("persist secrets: rename: %w", err)
	}
	if err := syncDir(c.DataDir); err != nil {
		return fmt.Errorf("persist secrets: sync dir: %w", err)
	}
	return nil
}

// loadSecretsLocked reads, decrypts and validates the persisted registry.
// Caller holds c.Mu.
func (c *Controller) loadSecretsLocked(password string) error {
	path := SecretsFilePath(c.DataDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // nothing persisted yet — fresh registration path
		}
		return fmt.Errorf("load secrets: read: %w", err)
	}
	plain, err := Decrypt(data, password)
	if err != nil {
		// Fail-closed (spec §10.1 point 3 / §11): never degrade to an empty
		// registry on a decrypt failure — that would silently lock every
		// agent out of its config. The file stays for manual recovery.
		return fmt.Errorf("load secrets: decrypt: %w (fail-closed: registry preserved for manual recovery)", err)
	}
	reg := NewSecretRegistry()
	if err := reg.Unmarshal(plain); err != nil {
		return fmt.Errorf("load secrets: %w (fail-closed: registry preserved)", err)
	}
	c.Secrets = reg
	return nil
}
