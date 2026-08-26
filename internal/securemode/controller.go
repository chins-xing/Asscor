package securemode

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrResidue reports a crash residue (plaintext + .enc both present) that
// needs manual recovery — see spec §6.
var ErrResidue = errors.New("plaintext and .enc both present — crash residue, manual recovery required")

// Controller orchestrates the default<->run state machine for the kernel:
// mode transitions, password verification, memory guard lifecycle, and
// startup recovery. Agent secrets are tracked separately (SecretRegistry) and
// persisted encrypted (spec §10.1 P0-1) so a kernel restart can recover them.
type Controller struct {
	Mu       sync.RWMutex
	DataDir  string
	Vaults   []*Vault
	Password *PasswordVerifier
	Guard    *MemoryGuard
	Mode     Mode
	Secrets  *SecretRegistry
	// runPassword is the kernel run-mode password retained in memory while in
	// run mode, used to re-encrypt the persisted registry after every
	// registration/rotation without operator input (spec §10.1). Set by
	// EnterRun/Unlock, refreshed by SetPassword, cleared by ExitRun. It is the
	// same secret the operator already supplies to enter/unlock — retaining it
	// in-process is the only way the heartbeat registration path can persist.
	runPassword string
}

// NewController creates a controller in default mode with no guard.
func NewController(dataDir string, vaults []*Vault) *Controller {
	return &Controller{
		DataDir:  dataDir,
		Vaults:   vaults,
		Password: &PasswordVerifier{File: PasswordVerifierPath(dataDir)},
		Mode:     ModeDefault,
		Secrets:  NewSecretRegistry(),
	}
}

// EnterRun transitions default -> run (NO password required). Encrypts all
// vaults, stores the password verifier, writes the run marker, and builds the
// memory guard from the plaintext config.
func (c *Controller) EnterRun(password string) error {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if c.Mode == ModeRun {
		return nil // idempotent
	}
	for _, v := range c.Vaults {
		if err := v.EncryptFile(password); err != nil {
			return fmt.Errorf("enter run: %w", err)
		}
	}
	if err := c.Password.Set(password); err != nil {
		return err
	}
	// Build the guard from the first vault's plaintext view (decrypt from
	// freshly-written .enc to exercise the round trip).
	plain, err := c.Vaults[0].LoadCiphertext(password)
	if err != nil {
		return fmt.Errorf("enter run: verify plaintext: %w", err)
	}
	c.Guard = NewMemoryGuard([]byte(plain))
	if err := WriteMarker(MarkerPath(c.DataDir), ModeRun); err != nil {
		return err
	}
	c.Mode = ModeRun
	c.runPassword = password
	// Persist whatever the registry holds at entry time (may include agents
	// that registered while the kernel was still in default mode). A failure
	// does not undo run-mode entry — the in-memory registry is authoritative
	// and the next registration/set-password re-persists — but the operator
	// must see it (a restart before then would start with an empty registry).
	if err := c.persistSecretsLocked(); err != nil {
		return fmt.Errorf("enter run: persist registry: %w", err)
	}
	return nil
}

// ExitRun transitions run -> default (password REQUIRED). Rejects on wrong
// password or memory-guard tampering.
func (c *Controller) ExitRun(password string) error {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if c.Mode == ModeDefault {
		return nil
	}
	if !c.Password.Verify(password) {
		return errors.New("exit run: incorrect password")
	}
	if c.Guard != nil && !c.Guard.IntegrityOK() {
		return errors.New("exit run: in-memory config integrity check failed — suspected tampering")
	}
	// Drop the retained password and the persisted registry BEFORE any state
	// change: in default mode no agent should be in run mode (spec §10.1), so
	// the encrypted registry file is removed. If removal fails, nothing has
	// been modified yet and a retry is clean. The stale-file edge (removal
	// succeeds, a later step fails) self-heals: registrations re-persist it.
	c.runPassword = ""
	if err := os.Remove(SecretsFilePath(c.DataDir)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("exit run: remove persisted registry: %w", err)
	}
	for _, v := range c.Vaults {
		if err := v.DecryptFile(password); err != nil {
			return fmt.Errorf("exit run: %w", err)
		}
	}
	if err := c.Password.Clear(); err != nil {
		return err
	}
	if err := WriteMarker(MarkerPath(c.DataDir), ModeDefault); err != nil {
		return err
	}
	c.Mode = ModeDefault
	c.Guard = nil
	return nil
}

// SetPassword rotates the password after verifying the old one. Two-phase to
// stay safe under crashes and write failures (review I-1): phase 1 decrypts
// every vault with the old password into memory with NO state change; phase 2
// writes the new verifier first, then re-encrypts each vault from memory (no
// plaintext ever touches disk); a mid-loop failure rolls everything back to
// the old password. The old verifier can never be left stale against
// new-password vaults.
func (c *Controller) SetPassword(oldPassword, newPassword string) error {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if c.Mode != ModeRun {
		return errors.New("set password: only allowed in run mode")
	}
	if !c.Password.Verify(oldPassword) {
		return errors.New("set password: incorrect current password")
	}
	// Phase 1 — preflight: the old password must decrypt every vault before
	// any state changes, so a partial/bad rotation can never be started.
	plains := make([]string, len(c.Vaults))
	for i, v := range c.Vaults {
		p, err := v.LoadCiphertext(oldPassword)
		if err != nil {
			return fmt.Errorf("set password: decrypt %s: %w", v.ConfigPath, err)
		}
		plains[i] = p
	}
	// Phase 2 — commit: verifier first, then re-encrypt each vault; roll back
	// on failure.
	if err := c.Password.Set(newPassword); err != nil {
		return err
	}
	for i, v := range c.Vaults {
		if err := c.reencryptVault(v, plains[i], newPassword); err != nil {
			rollbackErr := c.rollbackSetPassword(oldPassword, newPassword)
			return fmt.Errorf("set password: re-encrypt %s: %w (rollback: %v)", v.ConfigPath, err, rollbackErr)
		}
	}
	// Re-encrypt the persisted registry under the new password too; otherwise
	// a later kernel restart could never recover it (unlock would fail closed
	// against the old-password registry). The persist is atomic, so a failure
	// leaves the file under the OLD password — consistent with the rollback,
	// which restores verifier and vaults to the old password as well.
	c.runPassword = newPassword
	if err := c.persistSecretsLocked(); err != nil {
		c.runPassword = oldPassword
		rollbackErr := c.rollbackSetPassword(oldPassword, newPassword)
		return fmt.Errorf("set password: persist registry: %w (rollback: %v)", err, rollbackErr)
	}
	return nil
}

// reencryptVault atomically replaces v's .enc with a new encryption of plain
// built purely in memory (no plaintext touches disk during rotation). A
// leftover plaintext file is deliberately NOT removed: in run mode none should
// exist, and if one does it is recovery evidence, not something to delete
// silently.
func (c *Controller) reencryptVault(v *Vault, plain, password string) error {
	payload, err := v.EncryptContent(password, []byte(plain))
	if err != nil {
		return err
	}
	tmp := v.encPath() + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	if err := syncFile(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, v.encPath()); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(v.ConfigPath))
}

// rollbackSetPassword restores old-password encryption after a failed
// SetPassword commit. Vaults still decryptable with the old password are left
// untouched; vaults already switched to the new password are decrypted with
// the new password and re-encrypted with the old one; the verifier is reset
// to the old password. Both passwords remain known to the operator, so even a
// partial rollback keeps the state recoverable — the first error is returned,
// not swallowed.
func (c *Controller) rollbackSetPassword(oldPassword, newPassword string) error {
	var firstErr error
	for _, v := range c.Vaults {
		if _, err := v.LoadCiphertext(oldPassword); err == nil {
			continue // still under the old password
		}
		plain, err := v.LoadCiphertext(newPassword)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("rollback: vault %s under unknown password: %w", v.ConfigPath, err)
			}
			continue
		}
		if err := c.reencryptVault(v, plain, oldPassword); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("rollback: re-encrypt %s with old password: %w", v.ConfigPath, err)
			}
		}
	}
	if err := c.Password.Set(oldPassword); err != nil {
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Startup recovers state from the marker. Corrupt marker => fail-closed
// error. Run marker => controller stays in run mode awaiting Unlock.
func (c *Controller) Startup() error {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	mode, err := ReadMarker(MarkerPath(c.DataDir))
	if err != nil {
		if errors.Is(err, ErrCorruptMarker) {
			return fmt.Errorf("startup: %w (fail-closed: refusing to degrade to default)", err)
		}
		return err
	}
	// Residue detection: plaintext + .enc both present.
	for _, v := range c.Vaults {
		st := v.State()
		if st.hasPlain && st.hasEnc {
			return fmt.Errorf("startup: %w (%s)", ErrResidue, v.ConfigPath)
		}
	}
	// Half-state detection (interrupted EnterRun / tampering) — fail-closed
	// (review I-2): an enc-only vault is only legitimate paired with a run
	// marker AND a live verifier. Any other combination means a transition
	// crashed between stages; starting normally would silently orphan the
	// encrypted config.
	for _, v := range c.Vaults {
		st := v.State()
		if !st.hasPlain && st.hasEnc {
			switch {
			case mode == ModeDefault && c.Password.Exists():
				return fmt.Errorf("startup: enc-only vault %s with verifier present while marker=default — crash residue of interrupted EnterRun, manual recovery required", v.ConfigPath)
			case mode == ModeRun && !c.Password.Exists():
				return fmt.Errorf("startup: run marker but no password verifier (vault %s) — interrupted EnterRun or tampering, fail-closed", v.ConfigPath)
			}
		}
	}
	c.Mode = mode
	return nil
}

// Unlock loads the ciphertext configs into memory after password verification
// (kernel restart with a run marker). It also recovers the persisted agent
// registry (spec §10.1 P0-1 recovery flow: unlock, then restore the
// fingerprint->agent->password tuples) — a registry that cannot be decrypted
// fails closed, because serving run mode without the registry would leave
// every locked agent permanently unable to unlock.
func (c *Controller) Unlock(password string) error {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if c.Mode != ModeRun {
		return errors.New("unlock: only needed in run mode")
	}
	if !c.Password.Verify(password) {
		return errors.New("unlock: incorrect password")
	}
	plain, err := c.Vaults[0].LoadCiphertext(password)
	if err != nil {
		return err
	}
	if err := c.loadSecretsLocked(password); err != nil {
		return err
	}
	c.Guard = NewMemoryGuard([]byte(plain))
	c.runPassword = password
	return nil
}
