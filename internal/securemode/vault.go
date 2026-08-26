package securemode

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Vault manages one protected config file (plaintext <-> .enc) with
// crash-safe three-stage conversion and an optional plaintext bootstrap
// section that stays readable even in run mode.
type Vault struct {
	DataDir         string
	ConfigPath      string
	BootstrapHeader string // e.g. "[bootstrap]"; encrypted sections come after
}

type vaultState struct {
	hasPlain bool
	hasEnc   bool
}

// State reports which files currently exist (used for startup recovery).
func (v *Vault) State() vaultState {
	st := vaultState{}
	if _, err := os.Stat(v.ConfigPath); err == nil {
		st.hasPlain = true
	}
	if _, err := os.Stat(v.encPath()); err == nil {
		st.hasEnc = true
	}
	return st
}

// HasPlaintext reports whether the plaintext config file currently exists.
// Exported so external packages (the agent) can classify startup state.
func (v *Vault) HasPlaintext() bool { return v.State().hasPlain }

// IsEncrypted reports whether the .enc file currently exists (run-mode disk
// state). Exported so external packages (the agent) can classify startup state.
func (v *Vault) IsEncrypted() bool { return v.State().hasEnc }

func (v *Vault) encPath() string { return v.ConfigPath + ".enc" }

// EncryptFile converts the plaintext config to .enc with three-stage atomic
// conversion. On any failure the plaintext is left untouched:
//
//  1. encrypt + write .enc.tmp, fsync
//  2. decrypt the tmp with the same password and compare byte-for-byte
//  3. rename tmp -> .enc (atomic), then delete the plaintext
//
// The payload layout is [bootstrap plaintext]["\n\n"][encrypted rest] when a
// bootstrap section is configured, or pure ciphertext otherwise.
func (v *Vault) EncryptFile(password string) error {
	plain, err := os.ReadFile(v.ConfigPath)
	if err != nil {
		return fmt.Errorf("read plaintext config: %w", err)
	}
	content := string(plain)

	// Stage 1: encrypt (bootstrap kept plaintext if configured).
	payload, err := v.EncryptContent(password, plain)
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

	// Stage 2: verify — decrypt the tmp with the same password and compare the
	// reassembled result with the original full text.
	ver, err := v.decryptPayload(payload, password)
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("verification decrypt failed: %w", err)
	}
	if !bytes.Equal([]byte(ver), []byte(content)) {
		os.Remove(tmp)
		return fmt.Errorf("verification mismatch: encrypted output does not round-trip")
	}

	// Stage 3: commit — .enc durable before the plaintext is removed.
	if err := os.Rename(tmp, v.encPath()); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := syncDir(filepath.Dir(v.ConfigPath)); err != nil {
		return err
	}
	if err := os.Remove(v.ConfigPath); err != nil {
		return fmt.Errorf(".enc committed but plaintext removal failed: %w", err)
	}
	return syncDir(filepath.Dir(v.ConfigPath))
}

// EncryptContent builds the encrypted .enc payload for content entirely in
// memory (no disk access), honoring the bootstrap section layout:
// [bootstrap plaintext]["\n\n"][encrypted rest] or pure ciphertext. The
// caller writes the payload atomically. Used by EncryptFile and by the
// Controller's password rotation, which must never let plaintext touch disk.
func (v *Vault) EncryptContent(password string, content []byte) ([]byte, error) {
	c := string(content)
	bootstrap, rest, ok := v.splitBootstrap(c)
	if ok && v.BootstrapHeader != "" {
		encRest, err := Encrypt([]byte(rest), password)
		if err != nil {
			return nil, err
		}
		// splitBootstrap guarantees the bootstrap block contains no "\n\n"
		// after the header, so the first blank line is always the boundary for
		// decryptPayload (symmetric with splitBootstrap).
		payload := make([]byte, 0, len(bootstrap)+2+len(encRest))
		payload = append(payload, bootstrap...)
		payload = append(payload, '\n', '\n')
		payload = append(payload, encRest...)
		return payload, nil
	}
	return Encrypt(content, password)
}

// DecryptFile reverses EncryptFile: .enc -> plaintext, removing .enc. On any
// failure (including a wrong password) neither file is modified.
func (v *Vault) DecryptFile(password string) error {
	enc, err := os.ReadFile(v.encPath())
	if err != nil {
		return fmt.Errorf("read .enc: %w", err)
	}
	content, err := v.decryptPayload(enc, password)
	if err != nil {
		return err
	}
	tmp := v.ConfigPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	if err := syncFile(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, v.ConfigPath); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := syncDir(filepath.Dir(v.ConfigPath)); err != nil {
		return err
	}
	if err := os.Remove(v.encPath()); err != nil {
		return fmt.Errorf("plaintext committed but .enc removal failed: %w", err)
	}
	return syncDir(filepath.Dir(v.ConfigPath))
}

// splitBootstrap splits content into (bootstrap, rest, ok). The split point is
// the first blank line ("\n\n") at or after the header line; the bootstrap
// block keeps everything up to (excluding) that blank line. No header (or no
// configured header) means the whole content is the protected rest. A header
// with no blank line after it means the whole content is bootstrap (nothing to
// protect) — such files cannot be encrypted byte-exactly and EncryptFile
// rejects them during verification.
//
// decryptPayload must mirror this split exactly so that encrypt/decrypt
// round-trips byte-for-byte.
func (v *Vault) splitBootstrap(content string) (string, string, bool) {
	if v.BootstrapHeader == "" {
		return "", content, false
	}
	idx := strings.Index(content, v.BootstrapHeader)
	if idx < 0 {
		return "", content, false
	}
	after := content[idx:]
	blank := strings.Index(after, "\n\n")
	if blank < 0 {
		// No protected section after the bootstrap block — everything is
		// bootstrap.
		return content, "", true
	}
	return content[:idx+blank], content[idx+blank+2:], true
}

// decryptPayload decrypts a possibly bootstrap-prefixed payload produced by
// EncryptFile: [bootstrap plaintext]["\n\n"][encrypted rest], or pure
// ciphertext when there is no bootstrap section. The split point is the first
// blank line at or after the header, symmetric with splitBootstrap.
func (v *Vault) decryptPayload(payload []byte, password string) (string, error) {
	raw := payload
	var bootstrap string
	if v.BootstrapHeader != "" {
		if idx := bytes.Index(payload, []byte(v.BootstrapHeader)); idx >= 0 {
			if blank := bytes.Index(payload[idx:], []byte("\n\n")); blank >= 0 {
				split := idx + blank
				bootstrap = string(payload[:split])
				raw = payload[split+2:]
			}
			// Header present but no blank line: treat the whole payload as
			// ciphertext (never produced by EncryptFile; a malformed .enc will
			// fail loudly in Decrypt below).
		}
	}
	plain, err := Decrypt(raw, password)
	if err != nil {
		return "", err
	}
	return v.reassemble(bootstrap, string(plain)), nil
}

// reassemble joins the bootstrap block and the (decrypted) protected rest.
// When there is no bootstrap block the rest is returned unchanged.
func (v *Vault) reassemble(bootstrap, rest string) string {
	if bootstrap == "" {
		return rest
	}
	return bootstrap + "\n\n" + rest
}

// LoadPlaintext reads the current plaintext config.
func (v *Vault) LoadPlaintext() (string, error) {
	data, err := os.ReadFile(v.ConfigPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// LoadCiphertext reads and decrypts the .enc config. With a bootstrap section
// the result is the reassembled full plaintext (bootstrap + protected rest).
func (v *Vault) LoadCiphertext(password string) (string, error) {
	enc, err := os.ReadFile(v.encPath())
	if err != nil {
		return "", err
	}
	return v.decryptPayload(enc, password)
}

// ReadBootstrap returns the plaintext bootstrap section from the .enc payload
// (the part after the header up to the first blank line) WITHOUT the password.
// The agent uses it on a run-mode restart to recover connectivity essentials
// (kernel address, cert paths) when the plaintext config file no longer
// exists (spec §3.1 / §8.2). No header configured => empty result; a payload
// without a header/blank line yields whatever plaintext prefix exists (never
// an error).
func (v *Vault) ReadBootstrap() (string, error) {
	if v.BootstrapHeader == "" {
		return "", nil
	}
	enc, err := os.ReadFile(v.encPath())
	if err != nil {
		return "", err
	}
	idx := bytes.Index(enc, []byte(v.BootstrapHeader))
	if idx < 0 {
		return "", nil
	}
	if blank := bytes.Index(enc[idx:], []byte("\n\n")); blank >= 0 {
		return string(enc[idx : idx+blank]), nil
	}
	return string(enc[idx:]), nil
}

// RotatePassword re-encrypts the .enc with a new password, decrypting with the
// old one purely in memory (no plaintext touches disk). Used by the agent's
// securemode_rotate instruction and mirroring EncryptFile's atomic commit: on
// any failure the existing .enc is left untouched.
func (v *Vault) RotatePassword(oldPassword, newPassword string) error {
	enc, err := os.ReadFile(v.encPath())
	if err != nil {
		return fmt.Errorf("rotate: read .enc: %w", err)
	}
	plain, err := v.decryptPayload(enc, oldPassword)
	if err != nil {
		return fmt.Errorf("rotate: decrypt with old password: %w", err)
	}
	payload, err := v.EncryptContent(newPassword, []byte(plain))
	if err != nil {
		return fmt.Errorf("rotate: encrypt with new password: %w", err)
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
