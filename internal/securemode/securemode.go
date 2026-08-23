// Package securemode implements default/run dual-mode config protection:
// envelope encryption (AES-256-GCM + argon2id), atomic plaintext->ciphertext
// conversion, persistent mode markers, and kernel-managed agent mode control.
package securemode

const (
	// Magic is the .enc file header magic (4 bytes, "ASCM").
	Magic = "ASCM"
	// Version is the current .enc format version.
	Version = 1
	// MaxConfigSize caps config files at 10MB (mirrors config.Load).
	MaxConfigSize = 10 << 20
)
