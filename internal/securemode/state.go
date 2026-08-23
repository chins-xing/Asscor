package securemode

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Mode is the secure-mode state.
type Mode string

const (
	ModeDefault Mode = "default"
	ModeRun     Mode = "run"
)

// ErrCorruptMarker reports a marker file that exists but fails validation.
// Callers MUST treat this as fail-closed (refuse to silently degrade to
// default mode) — a corrupt marker may indicate tampering that tries to
// force the system back to plaintext.
var ErrCorruptMarker = errors.New("secure mode marker corrupt (possible tampering)")

// Marker layout: version(1) + modeLen(1) + mode + hash(32)
// hash = SHA-256(version || modeLen || mode)
type markerFile struct {
	Version byte
	Mode    Mode
	Hash    [sha256.Size]byte
}

// MarkerPath returns the mode marker path under dataDir.
func MarkerPath(dataDir string) string {
	return filepath.Join(dataDir, ".asscor-mode")
}

// WriteMarker atomically writes the mode marker (tmp + rename).
func WriteMarker(path string, mode Mode) error {
	if mode != ModeDefault && mode != ModeRun {
		return fmt.Errorf("invalid mode: %q", mode)
	}
	mk := markerFile{Version: 1, Mode: mode}
	mk.Hash = markerHash(mk)

	var payload []byte
	payload = append(payload, mk.Version)
	payload = append(payload, byte(len(mk.Mode)))
	payload = append(payload, []byte(mk.Mode)...)
	payload = append(payload, mk.Hash[:]...)

	tmp := path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	if err := syncFile(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// ReadMarker reads the marker. Missing file => (ModeDefault, nil).
// Corrupt/invalid content => ("", ErrCorruptMarker) — fail-closed.
func ReadMarker(path string) (Mode, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ModeDefault, nil
		}
		return "", err
	}
	if len(data) < 1+1+sha256.Size {
		return "", fmt.Errorf("%w: truncated marker (%d bytes)", ErrCorruptMarker, len(data))
	}
	mk := markerFile{Version: data[0]}
	modeLen := int(data[1])
	if modeLen < 1 || 1+1+modeLen+sha256.Size != len(data) {
		return "", fmt.Errorf("%w: malformed marker", ErrCorruptMarker)
	}
	mk.Mode = Mode(data[2 : 2+modeLen])
	copy(mk.Hash[:], data[2+modeLen:])

	if mk.Hash != markerHash(mk) {
		return "", fmt.Errorf("%w: integrity hash mismatch", ErrCorruptMarker)
	}
	if mk.Version != 1 {
		return "", fmt.Errorf("%w: unsupported marker version %d", ErrCorruptMarker, mk.Version)
	}
	if mk.Mode != ModeDefault && mk.Mode != ModeRun {
		return "", fmt.Errorf("%w: unknown mode %q", ErrCorruptMarker, mk.Mode)
	}
	return mk.Mode, nil
}

func markerHash(mk markerFile) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte{mk.Version, byte(len(mk.Mode))})
	h.Write([]byte(mk.Mode))
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
