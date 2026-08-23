package securemode

import (
	"errors"
	"fmt"
	"os"
	"sync"
)

// ErrResidue reports a crash residue (plaintext + .enc both present) that
// needs manual recovery — see spec §6.
var ErrResidue = errors.New("plaintext and .enc both present — crash residue, manual recovery required")

// Controller orchestrates the default<->run state machine for the kernel:
// mode transitions, password verification, memory guard lifecycle, and
// startup recovery. Agent secrets are tracked separately (SecretRegistry).
type Controller struct {
	Mu       sync.RWMutex
	DataDir  string
	Vaults   []*Vault
	Password *PasswordVerifier
	Guard    *MemoryGuard
	Mode     Mode
	Secrets  *SecretRegistry
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

// SetPassword rotates the password after verifying the old one. Re-encrypts
// all vaults with the new password.
func (c *Controller) SetPassword(oldPassword, newPassword string) error {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if c.Mode != ModeRun {
		return errors.New("set password: only allowed in run mode")
	}
	if !c.Password.Verify(oldPassword) {
		return errors.New("set password: incorrect current password")
	}
	// Decrypt each vault with old password, re-encrypt with new.
	for _, v := range c.Vaults {
		plain, err := v.LoadCiphertext(oldPassword)
		if err != nil {
			return fmt.Errorf("set password: decrypt %s: %w", v.ConfigPath, err)
		}
		// Temporarily restore plaintext, then encrypt with new password.
		if err := osWriteFileAll(v.ConfigPath, []byte(plain), 0o600); err != nil {
			return err
		}
		if err := v.EncryptFile(newPassword); err != nil {
			return fmt.Errorf("set password: re-encrypt %s: %w", v.ConfigPath, err)
		}
	}
	return c.Password.Set(newPassword)
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
	c.Mode = mode
	return nil
}

// Unlock loads the ciphertext configs into memory after password verification
// (kernel restart with a run marker).
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
	c.Guard = NewMemoryGuard([]byte(plain))
	return nil
}

// osWriteFileAll wraps os.WriteFile for the controller's internal rewrites.
func osWriteFileAll(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}
