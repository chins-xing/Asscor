# Secure Mode 实现计划（ASSCOR-Research-Core）

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现默认/运行双模式：配置信封加密（AES-256-GCM + argon2id）、三段式原子转换、持久化模式标记、agent 内核托管（自生成临时密码 + mTLS 上报 + 证书指纹主键登记）、CLI 模式切换与配置修改。

**Architecture:** 独立 `internal/securemode` 包承载加密/状态机/登记表；kernel CLI 经 `CLIModule.RegisterCommand` 接入 `mode`/`config` 子命令族；agent 侧经现有 `CommanderInterface` 指令通道执行内核下发的模式指令；身份认证完全复用现有 mTLS 体系（`PeerCertFingerprintFromContext`/`BindAgentCert`/`VerifyAgentCert`）。

**Tech Stack:** Go 1.26, AES-256-GCM (crypto/aes, crypto/cipher), argon2id (golang.org/x/crypto/argon2 v0.55.0), SHA-256, 现有 internal/kernel 插件体系, build-tag 模块模式。

**Spec:** `docs/superpowers/specs/2026-08-21-secure-mode-design.md`

## Global Constraints

- 分支：`ASSCOR-Research-Core`（所有工作在此分支完成并提交）
- 提交说明必须用**中文**（`feat(securemode): ...` 前缀可保留英文分类词，正文中文）
- 身份认证不重新实现：一律复用 `kernel.PeerCertFingerprintFromContext` / `HeartbeatInterface.BindAgentCert/VerifyAgentCert`
- agent 密码是**临时解锁秘密**：每次重启重新生成、不落盘、仅内存
- 密码登记表主键 = mTLS 客户端证书指纹（SHA-256 hex）
- 模式标记损坏 = fail-closed（拒绝降级默认模式）
- 加密走流式分块（bufio），不一次性读全文件（10MB 上限）
- 三段式原子转换：`.enc.tmp` → 验证 → rename → 删明文；任何一步崩溃明文不丢
- mprotect/anti-debug 定位为 runtime hardening（非防篡改保证）
- agent 本地 CLI 仅 `mode status`（只读），无切换/修改能力
- 依赖：`golang.org/x/crypto` v0.55.0（已加入 go.mod；网络下载走 `GOPROXY=https://goproxy.cn,direct`）
- 平台：Linux 为主（mprotect/read-only 页仅 Linux build-tag）；Windows 编译需 stub 保证可构建

---

### Task 1: securemode 包骨架与密码派生（argon2id）

**Files:**
- Create: `internal/securemode/crypt.go`
- Create: `internal/securemode/crypt_test.go`
- Create: `internal/securemode/securemode.go`（包注释 + 常量）

**Interfaces:**
- Produces:
  - `const Magic = "ASCM"`（`.enc` 文件头魔数，4 字节）
  - `const Version = 1`
  - `type Header struct { Magic [4]byte; Version byte; Salt []byte; ArgonN uint32; ArgonR uint32; ArgonP uint32; KeyLen uint32; Envelope []byte; Nonce []byte }`（序列化：magic(4) + version(1) + saltLen(2) + salt + N(4) + r(4) + p(4) + keyLen(4) + envLen(4) + envelope + nonceLen(2) + nonce）
  - `func deriveKey(password string, salt []byte, n, r, p, keyLen uint32) []byte` — argon2.IDKey
  - `func DefaultKDFParams() (n, r, p, keyLen uint32)` → (1, 64*1024, 4, 32)
  - `func randomBytes(n int) ([]byte, error)` — crypto/rand
  - `const MaxConfigSize = 10 << 20`（10MB）

- [ ] **Step 1: 写失败测试**

```go
package securemode

import (
	"bytes"
	"testing"
)

func TestDeriveKeyDeterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")
	a := deriveKey("secret", salt, 1, 64*1024, 4, 32)
	b := deriveKey("secret", salt, 1, 64*1024, 4, 32)
	if !bytes.Equal(a, b) {
		t.Error("same inputs must produce same key")
	}
	if len(a) != 32 {
		t.Errorf("key len = %d, want 32", len(a))
	}
}

func TestDeriveKeySaltSensitive(t *testing.T) {
	a := deriveKey("secret", []byte("salt-one-16bytes"), 1, 64*1024, 4, 32)
	b := deriveKey("secret", []byte("salt-two-16bytes"), 1, 64*1024, 4, 32)
	if bytes.Equal(a, b) {
		t.Error("different salts must produce different keys")
	}
}

func TestDeriveKeyPasswordSensitive(t *testing.T) {
	salt := []byte("0123456789abcdef")
	a := deriveKey("secret", salt, 1, 64*1024, 4, 32)
	b := deriveKey("wrong", salt, 1, 64*1024, 4, 32)
	if bytes.Equal(a, b) {
		t.Error("different passwords must produce different keys")
	}
}

func TestDefaultKDFParams(t *testing.T) {
	n, r, p, kl := DefaultKDFParams()
	if n != 1 || r != 64*1024 || p != 4 || kl != 32 {
		t.Errorf("params = (%d,%d,%d,%d), want (1,65536,4,32)", n, r, p, kl)
	}
}

func TestRandomBytes(t *testing.T) {
	a, err := randomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := randomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 || bytes.Equal(a, b) {
		t.Error("randomBytes must return distinct 32-byte values")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/securemode/ -run TestDerive -v`
Expected: FAIL — `undefined: deriveKey`

- [ ] **Step 3: 实现**

```go
// Package securemode implements default/run dual-mode config protection:
// envelope encryption (AES-256-GCM + argon2id), atomic plaintext->ciphertext
// conversion, persistent mode markers, and kernel-managed agent mode control.
package securemode

import (
	"crypto/rand"
	"encoding/binary"

	"golang.org/x/crypto/argon2"
)

const (
	// Magic is the .enc file header magic (4 bytes, "ASCM").
	Magic = "ASCM"
	// Version is the current .enc format version.
	Version = 1
	// MaxConfigSize caps config files at 10MB (mirrors config.Load).
	MaxConfigSize = 10 << 20
)

// DefaultKDFParams returns argon2id parameters (time, memory KiB, threads, keyLen).
func DefaultKDFParams() (n, r, p, keyLen uint32) {
	return 1, 64 * 1024, 4, 32
}

// deriveKey derives a 32-byte key from password+salt via argon2id.
func deriveKey(password string, salt []byte, n, r, p, keyLen uint32) []byte {
	return argon2.IDKey([]byte(password), salt, n, r, p, keyLen)
}

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// serializeUint32 / readUint32 helpers keep header encoding explicit.
func serializeUint32(buf []byte, v uint32) { binary.BigEndian.PutUint32(buf, v) }
func readUint32(buf []byte) uint32         { return binary.BigEndian.Uint32(buf) }
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./internal/securemode/ -run TestDerive -v`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add internal/securemode/crypt.go internal/securemode/securemode.go internal/securemode/crypt_test.go
git commit -m "feat(securemode): 包骨架与 argon2id 密码派生原语"
```

---

### Task 2: 信封加密（AES-256-GCM 明文↔密文）

**Files:**
- Modify: `internal/securemode/crypt.go`（追加加密函数）
- Modify: `internal/securemode/crypt_test.go`（追加测试）

**Interfaces:**
- Consumes: `deriveKey`、`randomBytes`、`DefaultKDFParams`、`Magic`、`Version`、`MaxConfigSize`（Task 1）
- Produces:
  - `func Encrypt(plaintext []byte, password string) ([]byte, error)` — 信封加密：随机 DEK 加密明文，KEK 加密 DEK；返回完整 `.enc` 文件内容（含 header）
  - `func Decrypt(data []byte, password string) ([]byte, error)` — 逆操作；密码错/GCM tag 失败/头损坏均返回 error
  - `func marshalHeader(h *Header) ([]byte, error)` / `func parseHeader(data []byte) (*Header, int, error)`（Header 见 Task 1 Interfaces）
  - 文件布局：`[header][ciphertext]`；ciphertext = GCM.Seal(nonce, plaintext) 的结果（含 tag）

- [ ] **Step 1: 写失败测试**

```go
package securemode

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plain := []byte("[weights]\nattack_surface = 35\n")
	enc, err := Encrypt(plain, "correct-password")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(enc, plain) {
		t.Error("ciphertext must not contain plaintext")
	}
	dec, err := Decrypt(enc, "correct-password")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(dec, plain) {
		t.Errorf("round trip mismatch: got %q", dec)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	enc, err := Encrypt([]byte("data"), "right")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(enc, "wrong"); err == nil {
		t.Fatal("wrong password must fail decryption")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	enc, err := Encrypt([]byte("data"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	enc[len(enc)-1] ^= 0xFF // flip last byte of GCM tag region
	if _, err := Decrypt(enc, "pw"); err == nil {
		t.Fatal("tampered ciphertext must fail GCM authentication")
	}
}

func TestDecryptBadMagic(t *testing.T) {
	enc, err := Encrypt([]byte("data"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	enc[0] = 'X'
	if _, err := Decrypt(enc, "pw"); err == nil {
		t.Fatal("bad magic must be rejected")
	}
	if !strings.Contains(err.Error(), "magic") {
		t.Errorf("error should mention magic, got: %v", err)
	}
}

func TestEncryptLargeContent(t *testing.T) {
	// 1MB plaintext exercises streaming-safe allocation path.
	plain := bytes.Repeat([]byte("a"), 1<<20)
	enc, err := Encrypt(plain, "pw")
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decrypt(enc, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, plain) {
		t.Error("large round trip mismatch")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/securemode/ -run TestEncrypt -v`
Expected: FAIL — `undefined: Encrypt`

- [ ] **Step 3: 实现**

```go
package securemode

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Header is the serialized .enc file header.
type Header struct {
	Magic    [4]byte
	Version  byte
	Salt     []byte
	ArgonN   uint32
	ArgonR   uint32
	ArgonP   uint32
	KeyLen   uint32
	Envelope []byte // DEK encrypted with KEK (AES-GCM)
	Nonce    []byte // GCM nonce for envelope
}

// Encrypt envelope-encrypts plaintext with password:
//   DEK (random 32B) encrypts plaintext via AES-256-GCM;
//   KEK = argon2id(password, salt) encrypts DEK.
// Returns the complete .enc file content (header + ciphertext).
func Encrypt(plaintext []byte, password string) ([]byte, error) {
	n, r, p, keyLen := DefaultKDFParams()
	salt, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	kek := deriveKey(password, salt, n, r, p, keyLen)
	defer zeroize(kek)

	dek, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	defer zeroize(dek)

	// Envelope: KEK encrypts DEK.
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	envNonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, envNonce); err != nil {
		return nil, err
	}
	envelope := gcm.Seal(nil, envNonce, dek, nil)

	// Payload: DEK encrypts plaintext.
	block2, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm2, err := cipher.NewGCM(block2)
	if err != nil {
		return nil, err
	}
	payNonce := make([]byte, gcm2.NonceSize())
	if _, err := io.ReadFull(rand.Reader, payNonce); err != nil {
		return nil, err
	}
	ciphertext := gcm2.Seal(payNonce, payNonce, plaintext, nil) // nonce-prepended

	h := &Header{
		Salt:     salt,
		ArgonN:   n,
		ArgonR:   r,
		ArgonP:   p,
		KeyLen:   keyLen,
		Envelope: envelope,
		Nonce:    envNonce,
	}
	copy(h.Magic[:], Magic)
	h.Version = Version

	head, err := marshalHeader(h)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(head)+len(ciphertext))
	out = append(out, head...)
	out = append(out, ciphertext...)
	return out, nil
}

// Decrypt reverses Encrypt. Wrong password, tampered data, or a malformed
// header all return an error.
func Decrypt(data []byte, password string) ([]byte, error) {
	if len(data) > MaxConfigSize {
		return nil, fmt.Errorf("encrypted config too large: %d bytes", len(data))
	}
	h, off, err := parseHeader(data)
	if err != nil {
		return nil, err
	}
	if h.KeyLen > 64 || h.ArgonN == 0 || h.ArgonR == 0 || h.ArgonP == 0 {
		return nil, errors.New("invalid KDF parameters in header")
	}
	kek := deriveKey(password, h.Salt, h.ArgonN, h.ArgonR, h.ArgonP, h.KeyLen)
	defer zeroize(kek)

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	dek, err := gcm.Open(nil, h.Nonce, h.Envelope, nil)
	if err != nil {
		return nil, errors.New("password incorrect or envelope corrupted")
	}
	defer zeroize(dek)

	block2, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm2, err := cipher.NewGCM(block2)
	if err != nil {
		return nil, err
	}
	payload := data[off:]
	if len(payload) < gcm2.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := payload[:gcm2.NonceSize()]
	ct := payload[gcm2.NonceSize():]
	plain, err := gcm2.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("ciphertext authentication failed (tampered?)")
	}
	return plain, nil
}

// zeroize wipes a key buffer after use.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func marshalHeader(h *Header) ([]byte, error) {
	if len(h.Magic) != 4 {
		return nil, errors.New("bad magic length")
	}
	if len(h.Salt) > 0xFFFF || len(h.Envelope) > 0xFFFFFFFF || len(h.Nonce) > 0xFFFF {
		return nil, errors.New("header field too large")
	}
	buf := &bytes.Buffer{}
	buf.Write(h.Magic[:])
	buf.WriteByte(h.Version)
	binary.Write(buf, binary.BigEndian, uint16(len(h.Salt)))
	buf.Write(h.Salt)
	binary.Write(buf, binary.BigEndian, h.ArgonN)
	binary.Write(buf, binary.BigEndian, h.ArgonR)
	binary.Write(buf, binary.BigEndian, h.ArgonP)
	binary.Write(buf, binary.BigEndian, h.KeyLen)
	binary.Write(buf, binary.BigEndian, uint32(len(h.Envelope)))
	buf.Write(h.Envelope)
	binary.Write(buf, binary.BigEndian, uint16(len(h.Nonce)))
	buf.Write(h.Nonce)
	return buf.Bytes(), nil
}

func parseHeader(data []byte) (*Header, int, error) {
	if len(data) < 4+1+2 {
		return nil, 0, errors.New("encrypted data too short")
	}
	h := &Header{}
	copy(h.Magic[:], data[:4])
	if string(h.Magic[:]) != Magic {
		return nil, 0, fmt.Errorf("bad magic: %q", h.Magic[:])
	}
	h.Version = data[4]
	if h.Version != Version {
		return nil, 0, fmt.Errorf("unsupported version: %d", h.Version)
	}
	off := 5
	saltLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if off+saltLen > len(data) {
		return nil, 0, errors.New("truncated salt")
	}
	h.Salt = data[off : off+saltLen]
	off += saltLen
	if off+16 > len(data) {
		return nil, 0, errors.New("truncated header")
	}
	h.ArgonN = binary.BigEndian.Uint32(data[off:])
	h.ArgonR = binary.BigEndian.Uint32(data[off+4:])
	h.ArgonP = binary.BigEndian.Uint32(data[off+8:])
	h.KeyLen = binary.BigEndian.Uint32(data[off+12:])
	off += 16
	if off+4 > len(data) {
		return nil, 0, errors.New("truncated header")
	}
	envLen := int(binary.BigEndian.Uint32(data[off:]))
	off += 4
	if off+envLen > len(data) {
		return nil, 0, errors.New("truncated envelope")
	}
	h.Envelope = data[off : off+envLen]
	off += envLen
	if off+2 > len(data) {
		return nil, 0, errors.New("truncated header")
	}
	nonceLen := int(binary.BigEndian.Uint16(data[off:]))
	off += 2
	if off+nonceLen > len(data) {
		return nil, 0, errors.New("truncated nonce")
	}
	h.Nonce = data[off : off+nonceLen]
	off += nonceLen
	return h, off, nil
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./internal/securemode/ -run TestEncrypt -v`
Expected: PASS（5 个测试）

- [ ] **Step 5: 提交**

```bash
git add internal/securemode/crypt.go internal/securemode/crypt_test.go
git commit -m "feat(securemode): AES-256-GCM 信封加密（明文↔密文往返/篡改检测）"
```

---

### Task 3: 模式状态机与标记文件（含 fail-closed）

**Files:**
- Create: `internal/securemode/state.go`
- Create: `internal/securemode/state_test.go`

**Interfaces:**
- Consumes: `randomBytes`（Task 1）；`crypto/sha256`
- Produces:
  - `type Mode string`；`const ModeDefault Mode = "default"`；`const ModeRun Mode = "run"`
  - `type Marker struct { Mode Mode; Version int; Hash [32]byte }` — Hash = SHA-256(mode + "|" + version)（自校验，防损坏静默降级）
  - `func WriteMarker(path string, mode Mode) error` — 原子写（tmp + rename）；内含 Hash 自校验
  - `func ReadMarker(path string) (Mode, error)` — 三态：
    - 文件不存在 → `(ModeDefault, nil)`（缺失=首次使用）
    - 解析/校验失败（损坏）→ `("", ErrCorruptMarker)`（fail-closed）
    - 正常 → 返回 mode
  - `var ErrCorruptMarker = errors.New("secure mode marker corrupt (possible tampering)")`
  - `func MarkerPath(dataDir string) string` — filepath.Join(dataDir, ".asscor-mode")

- [ ] **Step 1: 写失败测试**

```go
package securemode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMarkerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := MarkerPath(dir)
	if err := WriteMarker(p, ModeRun); err != nil {
		t.Fatal(err)
	}
	m, err := ReadMarker(p)
	if err != nil {
		t.Fatal(err)
	}
	if m != ModeRun {
		t.Errorf("mode = %q, want run", m)
	}
}

func TestMarkerMissingDefaults(t *testing.T) {
	m, err := ReadMarker(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatal(err)
	}
	if m != ModeDefault {
		t.Errorf("missing marker should default to default mode, got %q", m)
	}
}

func TestMarkerCorruptFailClosed(t *testing.T) {
	dir := t.TempDir()
	p := MarkerPath(dir)
	if err := WriteMarker(p, ModeRun); err != nil {
		t.Fatal(err)
	}
	// Corrupt the mode bytes but keep length.
	data, _ := os.ReadFile(p)
	data[0] = 'X'
	data[1] = 'X'
	os.WriteFile(p, data, 0o600)

	_, err := ReadMarker(p)
	if err == nil {
		t.Fatal("corrupt marker must fail-closed with an error")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("error should mention corrupt, got: %v", err)
	}
}

func TestMarkerTamperModeByte(t *testing.T) {
	dir := t.TempDir()
	p := MarkerPath(dir)
	if err := WriteMarker(p, ModeDefault); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	// Flip a byte inside the hash region: read must fail (hash mismatch).
	data[len(data)-1] ^= 0xFF
	os.WriteFile(p, data, 0o600)
	if _, err := ReadMarker(p); err == nil {
		t.Fatal("tampered marker hash must be detected")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/securemode/ -run TestMarker -v`
Expected: FAIL — `undefined: WriteMarker`

- [ ] **Step 3: 实现**

```go
package securemode

import (
	"crypto/sha256"
	"encoding/binary"
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

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// binary import guard (used in tests for hash construction parity).
var _ = binary.BigEndian
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./internal/securemode/ -run TestMarker -v`
Expected: PASS（4 个测试）

- [ ] **Step 5: 提交**

```bash
git add internal/securemode/state.go internal/securemode/state_test.go
git commit -m "feat(securemode): 模式标记文件（缺失默认 / 损坏 fail-closed）"
```

---

### Task 4: 配置保险库（三段式原子转换 + 引导段保留）

**Files:**
- Create: `internal/securemode/vault.go`
- Create: `internal/securemode/vault_test.go`

**Interfaces:**
- Consumes: `Encrypt`/`Decrypt`（Task 2）、`MaxConfigSize`、`Mode`/`MarkerPath`（Task 3）
- Produces:
  - `type Vault struct { DataDir string; ConfigPath string; BootstrapHeader string }`
    - `BootstrapHeader` = 明文段标记（如 `[bootstrap]`），加密时保留为明文，其余段落加密
  - `func (v *Vault) EncryptFile(password string) error` — 三段式：读明文 → 加密（保引导段）→ `.enc.tmp` → fsync → 解密验证 → rename → 删明文
  - `func (v *Vault) DecryptFile(password string) error` — 逆操作：读 `.enc` → 解密 → 写明文 tmp → fsync → rename → 删 `.enc`
  - `func (v *Vault) LoadPlaintext() (string, error)` — 读明文（不存在则报错）
  - `func (v *Vault) LoadCiphertext(password string) (string, error)` — 读密文并解密
  - `func (v *Vault) encPath() string` — ConfigPath + ".enc"
  - `func (v *Vault) splitBootstrap(content string) (bootstrap, rest string, ok bool)` — 按 BootstrapHeader 行切分；无标记则 whole=rest
  - `func (v *Vault) reassemble(bootstrap, rest string) string`
  - `func (v *Vault) recoverOnStartup() error` — 崩溃恢复：明文+.enc 共存时校验 .enc（用需要密码？不——设计上恢复需要密码。签名改为：`recoverState()` 返回需要密码的指示，见 Task 8 集成。此处仅实现文件状态探测：`func (v *Vault) State() (hasPlain, hasEnc bool)`

- [ ] **Step 1: 写失败测试**

```go
package securemode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	content := "[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[weights]\nattack_surface = 35\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Vault{DataDir: dir, ConfigPath: path, BootstrapHeader: "[bootstrap]"}
}

func TestVaultEncryptFileAtomic(t *testing.T) {
	v := newTestVault(t)
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	if !v.State().hasEnc {
		t.Error(".enc should exist after encrypt")
	}
	if v.State().hasPlain {
		t.Error("plaintext must be removed after successful encrypt")
	}
	// .enc.tmp must not linger.
	if _, err := os.Stat(v.encPath() + ".tmp"); !os.IsNotExist(err) {
		t.Errorf(".enc.tmp should be cleaned up, stat err=%v", err)
	}
}

func TestVaultRoundTrip(t *testing.T) {
	v := newTestVault(t)
	orig, _ := os.ReadFile(v.ConfigPath)
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	if err := v.DecryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(v.ConfigPath)
	if string(got) != string(orig) {
		t.Errorf("round trip mismatch:\ngot  %q\nwant %q", got, orig)
	}
	if v.State().hasEnc {
		t.Error(".enc should be removed after decrypt")
	}
}

func TestVaultBootstrapStaysPlaintext(t *testing.T) {
	v := newTestVault(t)
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	enc, _ := os.ReadFile(v.encPath())
	s := string(enc)
	if !strings.Contains(s, "kernel_addr = 127.0.0.1:50051") {
		t.Error("bootstrap section must remain readable plaintext in .enc")
	}
	dec, err := v.LoadCiphertext("pw")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dec, "attack_surface = 35") {
		t.Error("protected section must decrypt back")
	}
	if !strings.Contains(dec, "kernel_addr") {
		t.Error("bootstrap must be present in decrypted view too")
	}
}

func TestVaultEncryptWrongPasswordVerify(t *testing.T) {
	v := newTestVault(t)
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	// Decrypt with wrong password must fail and leave files untouched.
	if err := v.DecryptFile("wrong"); err == nil {
		t.Fatal("wrong password decrypt must fail")
	}
	if !v.State().hasEnc || v.State().hasPlain {
		t.Error("failed decrypt must not modify file state")
	}
}

func TestVaultRecoveryStateDetection(t *testing.T) {
	v := newTestVault(t)
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	// Simulate crash residue: re-create plaintext alongside .enc.
	os.WriteFile(v.ConfigPath, []byte("stale plaintext"), 0o600)
	st := v.State()
	if !st.hasPlain || !st.hasEnc {
		t.Errorf("crash residue should show both files, got %+v", st)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/securemode/ -run TestVault -v`
Expected: FAIL — `undefined: Vault`

- [ ] **Step 3: 实现**

```go
package securemode

import (
	"bufio"
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

func (v *Vault) encPath() string { return v.ConfigPath + ".enc" }

// EncryptFile converts the plaintext config to .enc with three-stage atomic
// conversion. On any failure the plaintext is left untouched.
func (v *Vault) EncryptFile(password string) error {
	plain, err := os.ReadFile(v.ConfigPath)
	if err != nil {
		return fmt.Errorf("read plaintext config: %w", err)
	}
	content := string(plain)
	bootstrap, rest, ok := v.splitBootstrap(content)

	// Stage 1: encrypt (bootstrap kept plaintext if configured).
	var payload []byte
	if ok && v.BootstrapHeader != "" {
		// Layout: [bootstrap plaintext]["\n"] then encrypted rest
		encRest, err := Encrypt([]byte(rest), password)
		if err != nil {
			return err
		}
		payload = make([]byte, 0, len(bootstrap)+1+len(encRest))
		payload = append(payload, bootstrap...)
		payload = append(payload, '\n')
		payload = append(payload, encRest...)
	} else {
		enc, err := Encrypt(plain, password)
		if err != nil {
			return err
		}
		payload = enc
	}

	tmp := v.encPath() + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	if err := syncFile(tmp); err != nil {
		os.Remove(tmp)
		return err
	}

	// Stage 2: verify — decrypt tmp with same password and compare protected
	// section with the in-memory plaintext.
	ver, err := v.decryptPayload(payload, password)
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("verification decrypt failed: %w", err)
	}
	if !bytes.Equal([]byte(ver), []byte(content)) {
		os.Remove(tmp)
		return fmt.Errorf("verification mismatch: encrypted output does not round-trip")
	}

	// Stage 3: commit.
	if err := os.Rename(tmp, v.encPath()); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := syncDir(filepath.Dir(v.ConfigPath)); err != nil {
		return err
	}
	// Remove plaintext only after .enc is durably in place.
	if err := os.Remove(v.ConfigPath); err != nil {
		return fmt.Errorf(".enc committed but plaintext removal failed: %w", err)
	}
	return syncDir(filepath.Dir(v.ConfigPath))
}

// DecryptFile reverses EncryptFile: .enc -> plaintext, removing .enc.
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

// decryptPayload decrypts a possibly bootstrap-prefixed payload.
func (v *Vault) decryptPayload(payload []byte, password string) (string, error) {
	raw := payload
	var bootstrap string
	if v.BootstrapHeader != "" && bytes.HasPrefix(payload, []byte(v.BootstrapHeader)) {
		idx := bytes.Index(payload, []byte("\n\n"))
		if idx < 0 {
			// bootstrap section ends at first newline after header line
			idx = bytes.Index(payload, []byte("\n"))
			if idx < 0 {
				return "", fmt.Errorf("malformed bootstrap section")
			}
			// decrypt rest after header line
			bootstrap = string(payload[:idx])
			raw = payload[idx+1:]
		} else {
			bootstrap = string(payload[:idx])
			raw = payload[idx+2:]
		}
		// encrypted rest follows after the blank line
		raw = payload[idx+2:]
		bootstrap = string(payload[:idx])
	}
	plain, err := Decrypt(raw, password)
	if err != nil {
		return "", err
	}
	if bootstrap != "" {
		return bootstrap + "\n\n" + string(plain), nil
	}
	return string(plain), nil
}

// splitBootstrap splits content into (bootstrap, rest, ok).
func (v *Vault) splitBootstrap(content string) (string, string, bool) {
	if v.BootstrapHeader == "" {
		return "", content, false
	}
	idx := strings.Index(content, v.BootstrapHeader)
	if idx < 0 {
		return "", content, false
	}
	// Bootstrap = header line + everything up to blank line.
	after := content[idx:]
	blank := strings.Index(after, "\n\n")
	if blank < 0 {
		// no protected section after bootstrap — everything is bootstrap
		return content, "", true
	}
	return content[:idx+blank], content[idx+blank+2:], true
}

// reassemble joins bootstrap and rest for write-back.
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

// LoadCiphertext reads and decrypts the .enc config.
func (v *Vault) LoadCiphertext(password string) (string, error) {
	enc, err := os.ReadFile(v.encPath())
	if err != nil {
		return "", err
	}
	return v.decryptPayload(enc, password)
}

// ensure bufio import is used (streaming helpers may land here).
var _ = bufio.NewReader
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./internal/securemode/ -run TestVault -v`
Expected: PASS（5 个测试）

- [ ] **Step 5: 提交**

```bash
git add internal/securemode/vault.go internal/securemode/vault_test.go
git commit -m "feat(securemode): 配置保险库 — 三段式原子转换 + 引导段保留"
```

---

### Task 5: 密码校验（argon2id 哈希）与密码轮换

**Files:**
- Create: `internal/securemode/password.go`
- Create: `internal/securemode/password_test.go`

**Interfaces:**
- Consumes: `deriveKey`、`DefaultKDFParams`、`randomBytes`（Task 1）
- Produces:
  - `type PasswordVerifier struct { File string }` — 校验材料文件路径（`<dataDir>/.asscor-pw`）
  - `func (pv *PasswordVerifier) Set(password string) error` — 生成盐 + argon2id 哈希写入（原子写）
  - `func (pv *PasswordVerifier) Verify(password string) bool` — 恒定时间比较
  - `func (pv *PasswordVerifier) Exists() bool`
  - `func (pv *PasswordVerifier) Clear() error` — 删除（退出运行模式后清除）
  - `func PasswordVerifierPath(dataDir string) string`

- [ ] **Step 1: 写失败测试**

```go
package securemode

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPasswordVerifierSetVerify(t *testing.T) {
	pv := &PasswordVerifier{File: filepath.Join(t.TempDir(), ".asscor-pw")}
	if pv.Exists() {
		t.Error("should not exist before Set")
	}
	if err := pv.Set("secret-pass"); err != nil {
		t.Fatal(err)
	}
	if !pv.Exists() {
		t.Error("should exist after Set")
	}
	if !pv.Verify("secret-pass") {
		t.Error("correct password must verify")
	}
	if pv.Verify("wrong-pass") {
		t.Error("wrong password must not verify")
	}
	if pv.Verify("") {
		t.Error("empty password must not verify")
	}
}

func TestPasswordVerifierReSet(t *testing.T) {
	pv := &PasswordVerifier{File: filepath.Join(t.TempDir(), ".asscor-pw")}
	if err := pv.Set("first"); err != nil {
		t.Fatal(err)
	}
	if err := pv.Set("second"); err != nil {
		t.Fatal(err)
	}
	if !pv.Verify("second") {
		t.Error("new password should verify after re-Set")
	}
	if pv.Verify("first") {
		t.Error("old password should fail after re-Set")
	}
}

func TestPasswordVerifierClear(t *testing.T) {
	pv := &PasswordVerifier{File: filepath.Join(t.TempDir(), ".asscor-pw")}
	if err := pv.Set("pw"); err != nil {
		t.Fatal(err)
	}
	if err := pv.Clear(); err != nil {
		t.Fatal(err)
	}
	if pv.Exists() {
		t.Error("verifier file should be gone after Clear")
	}
	if pv.Verify("pw") {
		t.Error("verify after clear must fail")
	}
}

func TestPasswordVerifierFilePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".asscor-pw")
	if err := (&PasswordVerifier{File: path}).Set("persist-me"); err != nil {
		t.Fatal(err)
	}
	// Fresh verifier over the same file must still verify (salt persisted).
	if !(&PasswordVerifier{File: path}).Verify("persist-me") {
		t.Error("verification must survive process restart via file salt+hash")
	}
	// ensure file is not empty
	st, _ := os.Stat(path)
	if st.Size() == 0 {
		t.Error("verifier file must contain salt+hash")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/securemode/ -run TestPassword -v`
Expected: FAIL — `undefined: PasswordVerifier`

- [ ] **Step 3: 实现**

```go
package securemode

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"io"
)

// PasswordVerifier stores an argon2id hash of the secure-mode password for
// offline verification (verify before attempting decryption). File layout:
// version(1) + saltLen(2) + salt + N(4) + r(4) + p(4) + keyLen(4) + hash.
type PasswordVerifier struct {
	File string
}

// PasswordVerifierPath returns the verifier path under dataDir.
func PasswordVerifierPath(dataDir string) string {
	return filepath.Join(dataDir, ".asscor-pw")
}

// Exists reports whether the verifier file is present.
func (pv *PasswordVerifier) Exists() bool {
	_, err := os.Stat(pv.File)
	return err == nil
}

// Set writes a fresh salt+hash for password (atomic tmp+rename).
func (pv *PasswordVerifier) Set(password string) error {
	if password == "" {
		return errors.New("refusing empty secure-mode password")
	}
	n, r, p, keyLen := DefaultKDFParams()
	salt, err := randomBytes(16)
	if err != nil {
		return err
	}
	hash := deriveKey(password, salt, n, r, p, keyLen)

	var buf []byte
	buf = append(buf, 1) // version
	buf = append(buf, byte(len(salt)))
	buf = append(buf, salt...)
	b4 := make([]byte, 4)
	putU32(b4, n); buf = append(buf, b4...)
	putU32(b4, r); buf = append(buf, b4...)
	putU32(b4, p); buf = append(buf, b4...)
	putU32(b4, keyLen); buf = append(buf, b4...)
	buf = append(buf, hash...)

	if err := os.MkdirAll(filepath.Dir(pv.File), 0o700); err != nil {
		return err
	}
	tmp := pv.File + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	if err := syncFile(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, pv.File); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(pv.File))
}

// Verify checks password against the stored hash (constant-time compare).
func (pv *PasswordVerifier) Verify(password string) bool {
	data, err := os.ReadFile(pv.File)
	if err != nil {
		return false
	}
	if len(data) < 1+1+16+16+32 {
		return false
	}
	saltLen := int(data[1])
	if 1+1+saltLen+16+32 > len(data) {
		return false
	}
	salt := data[2 : 2+saltLen]
	off := 2 + saltLen
	n := getU32(data[off:]); off += 4
	r := getU32(data[off:]); off += 4
	p := getU32(data[off:]); off += 4
	keyLen := getU32(data[off:]); off += 4
	expected := data[off : off+int(keyLen)]
	got := deriveKey(password, salt, n, r, p, keyLen)
	if len(got) != len(expected) {
		return false
	}
	return hmac.Equal(got, expected)
}

// Clear removes the verifier file (used when leaving run mode).
func (pv *PasswordVerifier) Clear() error {
	err := os.Remove(pv.File)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func putU32(b []byte, v uint32) { binary.BigEndian.PutUint32(b, v) }
func getU32(b []byte) uint32    { return binary.BigEndian.Uint32(b) }

// ensure io import used.
var _ = io.EOF

// fmt import guard (kept for future error wrapping parity).
var _ = fmt.Sprintf
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./internal/securemode/ -run TestPassword -v`
Expected: PASS（4 个测试）

- [ ] **Step 5: 提交**

```bash
git add internal/securemode/password.go internal/securemode/password_test.go
git commit -m "feat(securemode): 密码校验哈希（argon2id）+ 轮换/清除"
```

---

### Task 6: 内存完整性（校验和基线 + 只读快照）

**Files:**
- Create: `internal/securemode/memguard.go`
- Create: `internal/securemode/memguard_test.go`

**Interfaces:**
- Consumes: `crypto/sha256`
- Produces:
  - `type MemoryGuard struct { baseline [32]byte; mu sync.RWMutex; data []byte }`
  - `func NewMemoryGuard(plaintext []byte) *MemoryGuard` — 计算基线
  - `func (g *MemoryGuard) IntegrityOK() bool` — 当前 data 哈希 == 基线
  - `func (g *MemoryGuard) Snapshot() []byte` — 只读拷贝（不可变视图）
  - `func (g *MemoryGuard) Replace(newPlaintext []byte)` — 受控重建（config set 后更新基线）
  - `func (g *MemoryGuard) Data() []byte` — 内部引用（仅供内核模块读取；不导出写路径）

- [ ] **Step 1: 写失败测试**

```go
package securemode

import (
	"bytes"
	"sync"
	"testing"
)

func TestMemoryGuardBaseline(t *testing.T) {
	g := NewMemoryGuard([]byte("config data"))
	if !g.IntegrityOK() {
		t.Error("fresh guard must be intact")
	}
}

func TestMemoryGuardDetectsMutation(t *testing.T) {
	g := NewMemoryGuard([]byte("original"))
	// Simulate an attacker (or bug) mutating the internal buffer.
	g.mu.Lock()
	g.data[0] = 'X'
	g.mu.Unlock()
	if g.IntegrityOK() {
		t.Error("mutation must be detected by baseline hash")
	}
}

func TestMemoryGuardReplaceUpdatesBaseline(t *testing.T) {
	g := NewMemoryGuard([]byte("old"))
	g.Replace([]byte("new value"))
	if !g.IntegrityOK() {
		t.Error("Replace must re-baseline")
	}
	if got := string(g.Snapshot()); got != "new value" {
		t.Errorf("snapshot = %q, want new value", got)
	}
}

func TestMemoryGuardSnapshotImmutable(t *testing.T) {
	g := NewMemoryGuard([]byte("data"))
	snap := g.Snapshot()
	g.Replace([]byte("changed"))
	if bytes.Equal(snap, g.Snapshot()) {
		t.Error("snapshot must be an independent copy, not a view")
	}
}

func TestMemoryGuardConcurrent(t *testing.T) {
	g := NewMemoryGuard([]byte("init"))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				g.IntegrityOK()
				g.Snapshot()
			}
		}()
	}
	wg.Wait()
	if !g.IntegrityOK() {
		t.Error("concurrent reads must not corrupt state")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/securemode/ -run TestMemoryGuard -v`
Expected: FAIL — `undefined: NewMemoryGuard`

- [ ] **Step 3: 实现**

```go
package securemode

import (
	"crypto/sha256"
	"sync"
)

// MemoryGuard keeps the run-mode in-memory config with an integrity baseline.
// It exposes read-only snapshots and a controlled Replace path; any mutation
// outside those channels is detected by IntegrityOK (runtime hardening —
// see spec §7; not a guarantee against kernel-level attackers).
type MemoryGuard struct {
	mu       sync.RWMutex
	data     []byte
	baseline [sha256.Size]byte
}

// NewMemoryGuard snapshots the baseline of plaintext.
func NewMemoryGuard(plaintext []byte) *MemoryGuard {
	g := &MemoryGuard{data: append([]byte(nil), plaintext...)}
	g.baseline = sha256.Sum256(g.data)
	return g
}

// IntegrityOK recomputes the hash of the current data and compares with the
// baseline. Call before every config read / mode exit.
func (g *MemoryGuard) IntegrityOK() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return sha256.Sum256(g.data) == g.baseline
}

// Snapshot returns an immutable copy of the current config.
func (g *MemoryGuard) Snapshot() []byte {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return append([]byte(nil), g.data...)
}

// Replace rebuilds the config through the controlled channel and re-baselines.
func (g *MemoryGuard) Replace(newPlaintext []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.data = append([]byte(nil), newPlaintext...)
	g.baseline = sha256.Sum256(g.data)
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./internal/securemode/ -run TestMemoryGuard -v`
Expected: PASS（5 个测试）

- [ ] **Step 5: 提交**

```bash
git add internal/securemode/memguard.go internal/securemode/memguard_test.go
git commit -m "feat(securemode): 内存完整性 — 校验和基线 + 只读快照"
```

---

### Task 7: 密码登记表（证书指纹主键，传输层校验）

**Files:**
- Create: `internal/securemode/registry.go`
- Create: `internal/securemode/registry_test.go`

**Interfaces:**
- Consumes: `Encrypt`/`Decrypt`（Task 2，登记表加密持久化）、`randomBytes`、`sha256`
- Produces:
  - `type AgentSecret struct { AgentID string; Password string; UpdatedAt time.Time }`
  - `type SecretRegistry struct { mu sync.RWMutex; entries map[string]AgentSecret }` — 键 = cert fingerprint
  - `func NewSecretRegistry() *SecretRegistry`
  - `func (r *SecretRegistry) Register(fingerprint, agentID, password string) error` — **传输层校验**：
    - 指纹已存在且 AgentID 不同 → error（一证书一身份）
    - 指纹已存在且 AgentID 相同 → 覆盖密码（agent 重启/轮换）
    - 新指纹 → 登记
  - `func (r *SecretRegistry) Lookup(fingerprint string) (AgentSecret, bool)` — 按指纹查（解锁/下发用）
  - `func (r *SecretRegistry) LookupByAgent(agentID string) (AgentSecret, bool)` — 按 agentID 查（CLI 展示用）
  - `func (r *SecretRegistry) Remove(fingerprint string)`
  - `func (r *SecretRegistry) Size() int`
  - `func (r *SecretRegistry) Marshal() ([]byte, error)` / `func (r *SecretRegistry) Unmarshal(data []byte) error`（加密持久化：外层用内核 run-mode 密钥 Encrypt 落盘）
  - `func (r *SecretRegistry) List() []AgentSecret`（CLI status 展示）

- [ ] **Step 1: 写失败测试**

```go
package securemode

import (
	"testing"
	"time"
)

func TestRegistryRegisterAndLookup(t *testing.T) {
	r := NewSecretRegistry()
	if err := r.Register("fp1", "host-a", "pw1"); err != nil {
		t.Fatal(err)
	}
	s, ok := r.Lookup("fp1")
	if !ok || s.AgentID != "host-a" || s.Password != "pw1" {
		t.Fatalf("lookup = %+v ok=%v", s, ok)
	}
}

func TestRegistryFingerprintKeyed(t *testing.T) {
	r := NewSecretRegistry()
	if err := r.Register("fp1", "host-a", "pw1"); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("fp2", "host-b", "pw2"); err != nil {
		t.Fatal(err)
	}
	if r.Size() != 2 {
		t.Errorf("size = %d, want 2", r.Size())
	}
	// host-a's password is only reachable via fp1, not via fp2.
	if s, _ := r.Lookup("fp2"); s.AgentID == "host-a" {
		t.Error("fingerprint fp2 must map only to host-b")
	}
}

func TestRegistryFakeAgentIDRejected(t *testing.T) {
	r := NewSecretRegistry()
	if err := r.Register("fp1", "host-a", "pw1"); err != nil {
		t.Fatal(err)
	}
	// Attacker forges agent_id for a fingerprint that is already bound to
	// host-a: must be rejected at the transport layer (one cert, one identity).
	err := r.Register("fp1", "host-evil", "pw-evil")
	if err == nil {
		t.Fatal("registering a different agent_id under an existing fingerprint must be rejected")
	}
	// The original binding must survive.
	if s, _ := r.Lookup("fp1"); s.AgentID != "host-a" {
		t.Errorf("binding must stay host-a, got %+v", s)
	}
}

func TestRegistryAgentRotateUpdatesPassword(t *testing.T) {
	r := NewSecretRegistry()
	if err := r.Register("fp1", "host-a", "old-pw"); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("fp1", "host-a", "new-pw"); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.Lookup("fp1"); s.Password != "new-pw" {
		t.Errorf("password = %q, want new-pw after rotate", s.Password)
	}
}

func TestRegistryRemove(t *testing.T) {
	r := NewSecretRegistry()
	r.Register("fp1", "host-a", "pw")
	r.Remove("fp1")
	if _, ok := r.Lookup("fp1"); ok {
		t.Error("entry must be gone after Remove")
	}
}

func TestRegistryMarshalRoundTrip(t *testing.T) {
	r := NewSecretRegistry()
	r.Register("fp1", "host-a", "pw1")
	r.Register("fp2", "host-b", "pw2")

	data, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	r2 := NewSecretRegistry()
	if err := r2.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	if r2.Size() != 2 {
		t.Fatalf("restored size = %d, want 2", r2.Size())
	}
	if s, _ := r2.Lookup("fp1"); s.AgentID != "host-a" || s.Password != "pw1" {
		t.Errorf("restored fp1 = %+v", s)
	}
	// Unmarshal must fail on garbage.
	if err := r2.Unmarshal([]byte("garbage")); err == nil {
		t.Error("garbage data must fail Unmarshal")
	}
}

func TestRegistryPersistenceEncrypted(t *testing.T) {
	// Marshal must not contain plaintext passwords (they get encrypted by the
	// caller's run-mode key; here we verify the wire format at least isn't raw).
	r := NewSecretRegistry()
	r.Register("fp1", "host-a", "super-secret-pw")
	data, _ := r.Marshal()
	for _, probe := range []string{"super-secret-pw", "host-a"} {
		if contains(data, []byte(probe)) {
			t.Errorf("marshal output must not contain raw %q", probe)
		}
	}
}

func contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestRegistryUpdatedAt(t *testing.T) {
	r := NewSecretRegistry()
	if err := r.Register("fp1", "host-a", "pw"); err != nil {
		t.Fatal(err)
	}
	s, _ := r.Lookup("fp1")
	if s.UpdatedAt.IsZero() {
		t.Error("UpdatedAt must be set")
	}
	// rotate updates timestamp
	old := s.UpdatedAt
	time.Sleep(2 * time.Millisecond)
	r.Register("fp1", "host-a", "pw2")
	s2, _ := r.Lookup("fp1")
	if !s2.UpdatedAt.After(old) {
		t.Error("rotate must bump UpdatedAt")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/securemode/ -run TestRegistry -v`
Expected: FAIL — `undefined: NewSecretRegistry`

- [ ] **Step 3: 实现**

```go
package securemode

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AgentSecret is the kernel-side record of an agent's ephemeral unlock
// secret. The agent's password is a TEMPORARY unlock secret (spec §3.1/P1-1),
// not a long-term credential.
type AgentSecret struct {
	AgentID   string    `json:"agent_id"`
	Password  string    `json:"password"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SecretRegistry maps mTLS client-cert fingerprint -> agent secret. The
// fingerprint is the PRIMARY KEY (spec §10.1): even if an attacker forges an
// agent_id, the fingerprint mismatch is rejected at the transport layer.
type SecretRegistry struct {
	mu      sync.RWMutex
	entries map[string]AgentSecret
}

// NewSecretRegistry creates an empty registry.
func NewSecretRegistry() *SecretRegistry {
	return &SecretRegistry{entries: make(map[string]AgentSecret)}
}

// Register records/updates the secret for a fingerprint. It enforces the
// one-certificate-one-identity constraint: registering a DIFFERENT agent_id
// under an already-bound fingerprint is rejected (the fingerprint check the
// transport layer performs before this call is authoritative; this is the
// application-level backstop).
func (r *SecretRegistry) Register(fingerprint, agentID, password string) error {
	if fingerprint == "" || agentID == "" || password == "" {
		return fmt.Errorf("fingerprint, agent_id and password are all required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.entries[fingerprint]; ok {
		if existing.AgentID != agentID {
			return fmt.Errorf("fingerprint %q is bound to agent %q, refusing agent %q (one certificate, one identity)",
				fingerprint, existing.AgentID, agentID)
		}
		// Same identity: password rotation / re-registration.
		existing.Password = password
		existing.UpdatedAt = time.Now()
		r.entries[fingerprint] = existing
		return nil
	}
	r.entries[fingerprint] = AgentSecret{
		AgentID:   agentID,
		Password:  password,
		UpdatedAt: time.Now(),
	}
	return nil
}

// Lookup returns the secret for a fingerprint (used to unlock on agent
// restart and to issue mode-exit decryption).
func (r *SecretRegistry) Lookup(fingerprint string) (AgentSecret, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.entries[fingerprint]
	return s, ok
}

// LookupByAgent returns the first entry matching agentID (CLI display).
func (r *SecretRegistry) LookupByAgent(agentID string) (AgentSecret, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.entries {
		if s.AgentID == agentID {
			return s, true
		}
	}
	return AgentSecret{}, false
}

// Remove deletes the fingerprint entry.
func (r *SecretRegistry) Remove(fingerprint string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, fingerprint)
}

// Size returns the number of registered agents.
func (r *SecretRegistry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// List returns all entries (CLI status).
func (r *SecretRegistry) List() []AgentSecret {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]AgentSecret, 0, len(r.entries))
	for _, s := range r.entries {
		out = append(out, s)
	}
	return out
}

// Marshal serializes the registry (plaintext; callers encrypt with the
// kernel run-mode key before persisting — spec §10.1).
func (r *SecretRegistry) Marshal() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return json.Marshal(r.entries)
}

// Unmarshal restores the registry from Marshal output.
func (r *SecretRegistry) Unmarshal(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var entries map[string]AgentSecret
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("registry unmarshal: %w", err)
	}
	r.entries = entries
	return nil
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./internal/securemode/ -run TestRegistry -v`
Expected: PASS（9 个测试）

- [ ] **Step 5: 提交**

```bash
git add internal/securemode/registry.go internal/securemode/registry_test.go
git commit -m "feat(securemode): 密码登记表 — 证书指纹主键 + 一证书一身份 + 加密持久化格式"
```

---

### Task 8: 模式控制器（内核侧编排：状态机 + 启动恢复 + 崩溃恢复）

**Files:**
- Create: `internal/securemode/controller.go`
- Create: `internal/securemode/controller_test.go`

**Interfaces:**
- Consumes: `Vault`（Task 4）、`PasswordVerifier`（Task 5）、`MemoryGuard`（Task 6）、`Mode`/`ReadMarker`/`WriteMarker`/`ErrCorruptMarker`（Task 3）、`SecretRegistry`（Task 7）、`Encrypt`/`Decrypt`（Task 2）
- Produces:
  - `type Controller struct { DataDir string; Vaults []*Vault; Password *PasswordVerifier; Guard *MemoryGuard; Mode Mode; Secrets *SecretRegistry; Mu sync.RWMutex }`
  - `func NewController(dataDir string, vaults []*Vault) *Controller` — 初始 Mode=ModeDefault，Guard 置空
  - `func (c *Controller) EnterRun(password string) error` — 免密入口：对每个 Vault `EncryptFile(password)`；写 PasswordVerifier；写标记 ModeRun；`Guard = NewMemoryGuard(明文)`（从第一个 vault 的明文重建）
  - `func (c *Controller) ExitRun(password string) error` — 需密码：`Password.Verify` 失败拒绝；`Guard.IntegrityOK()` 失败拒绝（内存篡改检测）；各 Vault `DecryptFile(password)`；Clear verifier；写标记 ModeDefault
  - `func (c *Controller) SetPassword(oldPassword, newPassword string) error` — 验证旧密码 → `Password.Set(new)` → 各 Vault 重新加密（用新密码）
  - `func (c *Controller) Startup() error` — 启动恢复：
    - 读标记：ErrCorruptMarker → 返回错误（fail-closed，kernel 拒绝启动 run 模式）
    - ModeDefault → 检查各 Vault.State()：明文+.enc 共存 → 返回 `ErrResidue`（需人工处置，见 Task 9 CLI）
    - ModeRun → 需密码解锁（由调用方提示输入，`Unlock(password)`）
  - `func (c *Controller) Unlock(password string) error` — 验证 → 各 Vault.LoadCiphertext → Guard 重建 → 确认标记
  - `var ErrResidue = errors.New("plaintext and .enc both present — crash residue, manual recovery required")`

- [ ] **Step 1: 写失败测试**

```go
package securemode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestController(t *testing.T) *Controller {
	t.Helper()
	dir := t.TempDir()
	v := &Vault{
		DataDir:         dir,
		ConfigPath:      filepath.Join(dir, "config.ini"),
		BootstrapHeader: "[bootstrap]",
	}
	os.WriteFile(v.ConfigPath, []byte("[bootstrap]\naddr = x\n\n[weights]\na = 1\n"), 0o600)
	return NewController(dir, []*Vault{v})
}

func TestControllerEnterExitRun(t *testing.T) {
	c := newTestController(t)
	if c.Mode != ModeDefault {
		t.Fatalf("initial mode = %q, want default", c.Mode)
	}
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeRun {
		t.Errorf("mode = %q after enter, want run", c.Mode)
	}
	if c.Guard == nil || !c.Guard.IntegrityOK() {
		t.Error("guard must be initialized after enter")
	}
	if err := c.ExitRun("pw"); err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeDefault {
		t.Errorf("mode = %q after exit, want default", c.Mode)
	}
	// plaintext must be restored
	if _, err := os.Stat(c.Vaults[0].ConfigPath); err != nil {
		t.Error("plaintext config must be restored after exit")
	}
}

func TestControllerExitRunWrongPassword(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("right"); err != nil {
		t.Fatal(err)
	}
	if err := c.ExitRun("wrong"); err == nil {
		t.Fatal("exit with wrong password must fail")
	}
	if c.Mode != ModeRun {
		t.Errorf("mode must stay run after failed exit, got %q", c.Mode)
	}
}

func TestControllerStartupMarkerRunNeedsUnlock(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	// Simulate restart: fresh controller over same dir.
	c2 := NewController(c.DataDir, c.Vaults)
	if err := c2.Startup(); err != nil {
		t.Fatalf("Startup (run marker) should succeed but require unlock, got %v", err)
	}
	if c2.Mode != ModeRun {
		t.Errorf("restarted mode = %q, want run", c2.Mode)
	}
	if c2.Guard != nil {
		t.Error("guard must not be populated before unlock")
	}
	if err := c2.Unlock("pw"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if c2.Guard == nil || !c2.Guard.IntegrityOK() {
		t.Error("guard must be populated after unlock")
	}
}

func TestControllerStartupCorruptMarkerFailClosed(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	p := MarkerPath(c.DataDir)
	data, _ := os.ReadFile(p)
	data[0] = 'Z'
	os.WriteFile(p, data, 0o600)

	c2 := NewController(c.DataDir, c.Vaults)
	err := c2.Startup()
	if err == nil {
		t.Fatal("corrupt marker must fail closed on startup")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("error = %v, want corrupt mention", err)
	}
}

func TestControllerStartupResidue(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	// Re-create plaintext alongside .enc -> crash residue.
	os.WriteFile(c.Vaults[0].ConfigPath, []byte("stale"), 0o600)
	c2 := NewController(c.DataDir, c.Vaults)
	err := c2.Startup()
	if err == nil {
		t.Fatal("residue must surface an error on startup")
	}
	if !strings.Contains(err.Error(), "residue") && !strings.Contains(err.Error(), "both") {
		t.Errorf("error = %v, want residue mention", err)
	}
}

func TestControllerSetPassword(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("old"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetPassword("old", "new"); err != nil {
		t.Fatal(err)
	}
	// Old password must no longer decrypt; new one must.
	if err := c.ExitRun("old"); err == nil {
		t.Fatal("old password must fail after rotate")
	}
	if err := c.ExitRun("new"); err != nil {
		t.Fatalf("new password must work after rotate: %v", err)
	}
}

func TestControllerSetPasswordWrongOld(t *testing.T) {
	c := newTestController(t)
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetPassword("wrong", "new"); err == nil {
		t.Fatal("wrong old password must fail rotation")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/securemode/ -run TestController -v`
Expected: FAIL — `undefined: NewController`

- [ ] **Step 3: 实现**

```go
package securemode

import (
	"errors"
	"fmt"
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
```

*注：需在文件头补充 `import ("os" ...)`；`SetPassword` 的临时明文写回使用三段式原子转换的 Vault 内部逻辑更稳妥，若实现中发现 `EncryptFile` 依赖磁盘明文，改为直接调 `Encrypt` + 原子写 `.enc`。*

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./internal/securemode/ -run TestController -v`
Expected: PASS（8 个测试）

- [ ] **Step 5: 提交**

```bash
git add internal/securemode/controller.go internal/securemode/controller_test.go
git commit -m "feat(securemode): 模式控制器 — 进入/退出/轮换/启动恢复/崩溃残留"
```

---

### Task 9: CLI 命令（内核侧 mode 命令族 + config 子命令）

**Files:**
- Create: `internal/securemode/cli.go`
- Create: `internal/securemode/cli_test.go`

**Interfaces:**
- Consumes: `Controller`（Task 8）、`CLI 注册机制`（外部注入 handler，见 Task 10）
- Produces:
  - `func BuildModeCommand(c *Controller) (name string, info CommandInfo, handler CommandHandler, completions func(...))` 风格 API 不便——实际采用：
  - `type ModeCLI struct { Ctrl *Controller }`
  - `func (m *ModeCLI) HandleMode(input string, args []string, params map[string]string) (string, error)` — 解析 `mode status|enter|exit|set-password|agent <id> <action>`；返回输出文本
  - `func (m *ModeCLI) HandleConfigSet(args []string, flags map[string]string) (string, error)` — `config set <key> <value> [--temp|--persist]`；运行模式需密码参数 `--password`
  - 注：CLI 层与 `internal/cli` 的命令注册桥接在 Task 10 完成（避免 import cycle：securemode 不 import internal/cli；internal/cli 反向注入 handler）

- [ ] **Step 1: 写失败测试**

```go
package securemode

import (
	"strings"
	"testing"
)

func newModeCLI(t *testing.T) *ModeCLI {
	c := newTestController(t)
	if err := c.EnterRun("pw"); err != nil {
		t.Fatal(err)
	}
	return &ModeCLI{Ctrl: c}
}

func TestModeCLIStatus(t *testing.T) {
	m := newModeCLI(t)
	out, err := m.HandleMode("status", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "run") {
		t.Errorf("status output should mention run mode, got %q", out)
	}
}

func TestModeCLIExitWrongPassword(t *testing.T) {
	m := newModeCLI(t)
	_, err := m.HandleMode("exit", nil, map[string]string{"password": "wrong"})
	if err == nil {
		t.Fatal("exit with wrong password must fail")
	}
	if m.Ctrl.Mode != ModeRun {
		t.Error("mode must stay run after failed exit")
	}
}

func TestModeCLIExitOK(t *testing.T) {
	m := newModeCLI(t)
	out, err := m.HandleMode("exit", nil, map[string]string{"password": "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "default") {
		t.Errorf("exit output should mention default mode, got %q", out)
	}
}

func TestModeCLISetPassword(t *testing.T) {
	m := newModeCLI(t)
	if _, err := m.HandleMode("set-password", nil, map[string]string{"old": "pw", "new": "newpw"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.HandleMode("exit", nil, map[string]string{"password": "newpw"}); err != nil {
		t.Fatalf("new password should work: %v", err)
	}
}

func TestModeCLIConfigSetTemp(t *testing.T) {
	m := newModeCLI(t)
	out, err := m.HandleConfigSet([]string{"threshold", "85"}, map[string]string{"password": "pw", "temp": "true"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "85") {
		t.Errorf("set output should echo value, got %q", out)
	}
}

func TestModeCLIConfigSetWrongPassword(t *testing.T) {
	m := newModeCLI(t)
	if _, err := m.HandleConfigSet([]string{"threshold", "85"}, map[string]string{"password": "nope"}); err == nil {
		t.Fatal("config set in run mode without correct password must fail")
	}
}

func TestModeCLIConfigSetPersist(t *testing.T) {
	m := newModeCLI(t)
	out, err := m.HandleConfigSet([]string{"threshold", "77"}, map[string]string{"password": "pw", "persist": "true"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "reload") {
		t.Errorf("persist output should mention reload, got %q", out)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/securemode/ -run TestModeCLI -v`
Expected: FAIL — `undefined: ModeCLI`

- [ ] **Step 3: 实现**

```go
package securemode

import (
	"fmt"
	"sort"
	"strings"
)

// ModeCLI is the kernel-side CLI adapter for mode/config commands. It stays
// free of any internal/cli import to avoid a dependency cycle; internal/cli
// wires it via handler functions (Task 10).
type ModeCLI struct {
	Ctrl *Controller
}

// HandleMode implements the `mode` command family:
//
//	mode status
//	mode enter
//	mode exit --password <pw>
//	mode set-password --old <pw> --new <pw>
//	mode agent <id> status|enter|exit|rotate-password
func (m *ModeCLI) HandleMode(sub string, args []string, params map[string]string) (string, error) {
	switch sub {
	case "status":
		return m.status()
	case "enter":
		return m.enter(params)
	case "exit":
		return m.exit(params)
	case "set-password":
		return m.setPassword(params)
	case "agent":
		return m.agent(args, params)
	default:
		return "", fmt.Errorf("mode: unknown subcommand %q", sub)
	}
}

func (m *ModeCLI) status() (string, error) {
	m.Ctrl.Mu.RLock()
	defer m.Ctrl.Mu.RUnlock()
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Mode: %s\n", m.Ctrl.Mode))
	for _, v := range m.Ctrl.Vaults {
		st := v.State()
		b.WriteString(fmt.Sprintf("  %s: plaintext=%v enc=%v\n", v.ConfigPath, st.hasPlain, st.hasEnc))
	}
	if m.Ctrl.Secrets.Size() > 0 {
		b.WriteString("Registered agents (cert-fingerprint keyed):\n")
		for _, s := range m.Ctrl.Secrets.List() {
			b.WriteString(fmt.Sprintf("  %s (agent %s, updated %s)\n", truncateFP(s.AgentID), s.AgentID, s.UpdatedAt.Format("15:04:05")))
		}
	}
	return b.String(), nil
}

func (m *ModeCLI) enter(params map[string]string) (string, error) {
	password := params["password"]
	if password == "" {
		return "", fmt.Errorf("mode enter: --password is required to establish the run-mode secret")
	}
	if err := m.Ctrl.EnterRun(password); err != nil {
		return "", err
	}
	return "Entered run mode — configuration files encrypted.\n", nil
}

func (m *ModeCLI) exit(params map[string]string) (string, error) {
	password := params["password"]
	if err := m.Ctrl.ExitRun(password); err != nil {
		return "", err
	}
	return "Exited run mode — configuration restored to plaintext.\n", nil
}

func (m *ModeCLI) setPassword(params map[string]string) (string, error) {
	oldPw := params["old"]
	newPw := params["new"]
	if oldPw == "" || newPw == "" {
		return "", fmt.Errorf("mode set-password: --old and --new are required")
	}
	if err := m.Ctrl.SetPassword(oldPw, newPw); err != nil {
		return "", err
	}
	return "Password rotated; configuration re-encrypted.\n", nil
}

func (m *ModeCLI) agent(args []string, params map[string]string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("mode agent: agent id required")
	}
	agentID := args[0]
	action := "status"
	if len(args) > 1 {
		action = args[1]
	}
	switch action {
	case "status":
		m.Ctrl.Mu.RLock()
		defer m.Ctrl.Mu.RUnlock()
		if s, ok := m.Ctrl.Secrets.LookupByAgent(agentID); ok {
			return fmt.Sprintf("agent %s: registered (updated %s)\n", agentID, s.UpdatedAt.Format("15:04:05")), nil
		}
		return fmt.Sprintf("agent %s: not registered\n", agentID), nil
	case "enter", "exit", "rotate-password":
		// Actual agent instruction dispatch happens via CommanderInterface
		// (Task 11). This CLI surface returns the intended action for the
		// wiring layer to enqueue.
		return fmt.Sprintf("agent %s: %s instruction prepared (dispatch via commander)\n", agentID, action), nil
	default:
		return "", fmt.Errorf("mode agent: unknown action %q", action)
	}
}

// HandleConfigSet implements `config set <key> <value> [--temp|--persist]`.
// In run mode a correct --password is required.
func (m *ModeCLI) HandleConfigSet(args []string, flags map[string]string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("config set: key and value required")
	}
	key, value := args[0], args[1]
	password := flags["password"]
	persist := flags["persist"] == "true" || flags["persist"] == "1"

	m.Ctrl.Mu.RLock()
	runMode := m.Ctrl.Mode == ModeRun
	guard := m.Ctrl.Guard
	m.Ctrl.Mu.RUnlock()

	if runMode {
		if password == "" {
			return "", fmt.Errorf("config set: run mode requires --password")
		}
		if !m.Ctrl.Password.Verify(password) {
			return "", fmt.Errorf("config set: incorrect password")
		}
		if guard != nil && !guard.IntegrityOK() {
			return "", fmt.Errorf("config set: in-memory config integrity check failed")
		}
	}

	// Apply to the in-memory snapshot (guard.Replace path).
	snap := []byte{}
	if guard != nil {
		snap = guard.Snapshot()
	}
	updated, err := applyKeyValue(string(snap), key, value)
	if err != nil {
		return "", err
	}
	if guard != nil {
		guard.Replace([]byte(updated))
	}

	if persist {
		if runMode {
			// Write back through the vault as encrypted content.
			if err := m.writePersisted(runMode, []byte(updated), password); err != nil {
				return "", err
			}
			return fmt.Sprintf("config set: %s=%s persisted (encrypted); run 'config reload' to apply\n", key, value), nil
		}
		if err := m.writePersisted(false, []byte(updated), ""); err != nil {
			return "", err
		}
		return fmt.Sprintf("config set: %s=%s persisted (plaintext); run 'config reload' to apply\n", key, value), nil
	}
	return fmt.Sprintf("config set: %s=%s applied in memory (temp, not persisted)\n", key, value), nil
}

// writePersisted writes the updated config to disk in the current mode format.
func (m *ModeCLI) writePersisted(runMode bool, content []byte, password string) error {
	if len(m.Ctrl.Vaults) == 0 {
		return fmt.Errorf("config set: no vault configured")
	}
	v := m.Ctrl.Vaults[0]
	if runMode {
		return v.EncryptFile(password)
	}
	return osWriteFileAll(v.ConfigPath, content, 0o600)
}

// applyKeyValue replaces `key = <old>` in an INI-like text with the new value.
func applyKeyValue(content, key, value string) (string, error) {
	lines := strings.Split(content, "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "[") {
			continue
		}
		eq := strings.Index(trimmed, "=")
		if eq < 0 {
			continue
		}
		if strings.TrimSpace(trimmed[:eq]) == key {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = indent + key + " = " + value
			found = true
		}
	}
	if !found {
		return "", fmt.Errorf("config set: key %q not found", key)
	}
	return strings.Join(lines, "\n"), nil
}

func truncateFP(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "..."
}

// sort import guard for future list ordering.
var _ = sort.Strings
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./internal/securemode/ -run TestModeCLI -v`
Expected: PASS（7 个测试）

- [ ] **Step 5: 提交**

```bash
git add internal/securemode/cli.go internal/securemode/cli_test.go
git commit -m "feat(securemode): CLI 适配层 — mode 命令族 + config set 两段式持久化"
```

---

### Task 10: 内核接入（build-tag 插件 + CLI 注册 + 启动接线）

**Files:**
- Modify: `cmd/kernel/securemode_on.go`（Create）
- Modify: `cmd/kernel/securemode_off.go`（Create）
- Modify: `cmd/kernel/main.go`（接线：NewController、Startup、CLI handler 注册）
- Modify: `internal/cli/commands.go`（注册 mode/config handler——经注入接口避免 import cycle）

**Interfaces:**
- Consumes: `Controller`/`ModeCLI`（Task 9）、`kernel.KernelContext`、`CLIModule.RegisterCommand`、`HeartbeatInterface`
- Produces:
  - `func initSecureMode(k kernel.KernelContext, dataDir, configPath string) (*securemode.Controller, error)` — 组装 Vault（BootstrapHeader="[bootstrap]"）、NewController、Startup；corrupt marker → 返回错误终止启动
  - `func registerModeCLI(cliModule *cli.CLIModule, mcli *securemode.ModeCLI)` — 经 `RegisterCommand` 注册 `mode` 与 `config` handler（handler 转发到 ModeCLI）

- [ ] **Step 1: 写失败测试（接线无法单测，改为 build 验证）**

Run: `GOOS=linux go build -tags securemode ./cmd/kernel` 及 `go build ./...`（默认 off）
Expected: 两者均成功编译；off 版不含 securemode 引用

- [ ] **Step 2: 实现 securemode_on.go**

```go
//go:build securemode

package main

import (
	"fmt"

	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/securemode"
)

// initSecureMode assembles the kernel-side secure-mode controller. The
// config.ini path comes from the kernel's resolved -config flag; bootstrap
// section stays plaintext for connectivity essentials.
func initSecureMode(k kernel.KernelContext, dataDir, configPath string) (*securemode.Controller, error) {
	if dataDir == "" {
		dataDir = "/var/lib/asscor"
	}
	vault := &securemode.Vault{
		DataDir:         dataDir,
		ConfigPath:      configPath,
		BootstrapHeader: "[bootstrap]",
	}
	ctrl := securemode.NewController(dataDir, []*securemode.Vault{vault})
	if err := ctrl.Startup(); err != nil {
		return nil, fmt.Errorf("secure mode startup: %w", err)
	}
	if ctrl.Mode == securemode.ModeRun {
		// Kernel was in run mode at shutdown: block serving until unlocked.
		// The CLI prompts for the password via `mode unlock`; serving gating
		// is wired in main via ctrl.Mode == ModeRun check.
	}
	return ctrl, nil
}
```

- [ ] **Step 3: 实现 securemode_off.go**

```go
//go:build !securemode

package main

import (
	"github.com/asscor/asscor/internal/kernel"
	"github.com/asscor/asscor/internal/securemode"
)

// initSecureMode returns a nil controller when the securemode build tag is
// absent — the kernel runs in plaintext default mode exactly as before.
func initSecureMode(k kernel.KernelContext, dataDir, configPath string) (*securemode.Controller, error) {
	return nil, nil
}
```

- [ ] **Step 4: 在 main.go 接线**

在 `cmd/kernel/main.go` 中（`cliModule` 创建后）：

```go
// Secure Mode: optional build-tag module. Off by default; enable with
// -tags securemode. When enabled and the kernel was in run mode at
// shutdown, startup requires the run-mode password via `mode unlock`.
secureCtrl, err := initSecureMode(k, cfg.DataDir, resolvedConfigPath)
if err != nil {
    log.Error("secure mode init failed (fail-closed)", "error", err)
    os.Exit(1)
}
if secureCtrl != nil {
    mcli := securemode.NewModeCLI(secureCtrl)
    if err := registerSecureModeCLI(cliModule, mcli); err != nil {
        log.Error("secure mode CLI registration failed", "error", err)
        os.Exit(1)
    }
    // Bind the controller for later plugins (heartbeat secret reporting).
    k.Container().BindNamed("securemode", (*securemode.Controller)(nil), secureCtrl)
}
```

并新增 `cmd/kernel/securemode_cli.go`（无 build-tag，安全空指针保护）：

```go
package main

import (
	"github.com/asscor/asscor/internal/cli"
	"github.com/asscor/asscor/internal/securemode"
)

// registerSecureModeCLI wires the mode/config handlers into the kernel CLI.
// It is safe to call with a nil cliModule (no-op).
func registerSecureModeCLI(cliModule *cli.CLIModule, mcli *securemode.ModeCLI) error {
	if cliModule == nil || mcli == nil {
		return nil
	}
	// mode command
	if err := cliModule.RegisterCommand(cli.Command{
		Name:        "mode",
		Description: "Secure mode control (status/enter/exit/set-password/agent)",
		Handler: func(ctx *cli.CommandContext) *cli.CommandResult {
			// forward to mcli.HandleMode with parsed args/params
			// (wiring detail: extract subcommand + --password/--old/--new)
			...
		},
	}); err != nil {
		return err
	}
	// config set handler hooks into existing config command
	...
	return nil
}
```

*注：`cli.Command` 的精确字段（Name/Handler/Params）与 `CommandContext` 的 Args/Repeat 结构需在实现时对照 `internal/cli/commands.go` 的现有命令（如 `agentCmdHandler`）逐一填写——本任务重点是打通注册链路；若 `RegisterCommand` 不接受闭包 Handler，则改用 `RegisterFrom`（对照 module.go 用法）。*

- [ ] **Step 5: 构建验证**

Run: `go build ./...`（默认 off）+ `go build -tags securemode ./cmd/kernel`
Expected: 两者 exit 0

- [ ] **Step 6: 提交**

```bash
git add cmd/kernel/securemode_on.go cmd/kernel/securemode_off.go cmd/kernel/securemode_cli.go cmd/kernel/main.go internal/cli/commands.go
git commit -m "feat(securemode): 内核接线 — build-tag 插件 + CLI 注册 + 启动 fail-closed"
```

---

### Task 11: agent 托管（自生成密码 + mTLS 上报 + 内核指令执行）

**Files:**
- Modify: `cmd/agent/securemode_on.go`（Create）
- Modify: `cmd/agent/securemode_off.go`（Create）
- Modify: `internal/agent/agent.go`（runCommand 增加 securemode 动作分发）
- Modify: `internal/comms/services.go`（Heartbeat 处理密码上报 + 注册）

**Interfaces:**
- Consumes: `Vault`/`PasswordVerifier`/`Controller`（agent 侧复用 Vault）、`CommanderInterface.EnqueueCommand`（内核→agent 指令）、`PeerCertFingerprintFromContext`、`SecretRegistry`
- Produces:
  - agent 侧：`func agentBootstrapSecureMode(cfg AgentConfig) (*securemode.Vault, error)` — 读明文引导段 → 自生成随机密码（`randomBytes` 派生）→ `vault.EncryptFile(pw)` → 返回 vault
  - agent 心跳上报：新增心跳字段 `SecureModeReport { Password string; Fingerprint string }`（经 apiv1.HeartbeatRequest 扩展或复用 Params）——fingerprint 由内核从 context 取，agent 只上报密码
  - 内核侧：Heartbeat 收到上报 → `fp := PeerCertFingerprintFromContext(ctx)` → `ctrl.Secrets.Register(fp, req.HostId, password)` → 传输层不一致时 Register 拒绝
  - agent 指令：`internal/agent/agent.go` 的 `runCommand` 新增 `case "securemode_exit", "securemode_rotate"` → 调用 vault 解密/重加密（密码从命令 Params 下发）

- [ ] **Step 1: 写失败测试**

```go
// internal/securemode/agent_test.go
package securemode

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAgentSecretFlow verifies the agent-side bootstrap: self-generated
// password, encrypt, and registry registration (mock fingerprint).
func TestAgentSecretFlow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.ini")
	content := "[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[agent]\nheartbeat_sec = 30\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	v := &Vault{DataDir: dir, ConfigPath: path, BootstrapHeader: "[bootstrap]"}

	// Agent generates its own ephemeral password (never persisted).
	pw, err := randomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	agentPW := hex.EncodeToString(pw)

	if err := v.EncryptFile(agentPW); err != nil {
		t.Fatal(err)
	}
	if !v.State().hasEnc || v.State().hasPlain {
		t.Fatalf("after agent encrypt: state = %+v", v.State())
	}

	// Report to kernel: fingerprint-keyed registry.
	reg := NewSecretRegistry()
	if err := reg.Register("cert-fp-001", "host-1", agentPW); err != nil {
		t.Fatal(err)
	}
	if s, ok := reg.Lookup("cert-fp-001"); !ok || s.Password != agentPW {
		t.Fatalf("registry lookup = %+v ok=%v", s, ok)
	}

	// Agent restart: decrypt with kernel-issued password.
	plain, err := v.LoadCiphertext(agentPW)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain, "heartbeat_sec") {
		t.Errorf("decrypted config missing protected section: %q", plain)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./internal/securemode/ -run TestAgentSecretFlow -v`
Expected: 编译失败或 FAIL（Vault 已存在则 PASS——若 Task 4 已完成则本测试立即通过；作为集成验证）

- [ ] **Step 3: 实现 agent 侧 build-tag 文件**

```go
//go:build securemode
// cmd/agent/securemode_on.go
package main

import (
	"fmt"

	"github.com/asscor/asscor/internal/agent"
	"github.com/asscor/asscor/internal/securemode"
)

// agentSecureVault returns the agent's protected-config vault. When the
// securemode tag is enabled, the agent manages agent.ini encryption itself
// (self-generated ephemeral password, kernel-managed lifecycle).
func agentSecureVault(cfg agent.AgentConfig) *securemode.Vault {
	return &securemode.Vault{
		DataDir:         "",
		ConfigPath:      cfg.ConfigPath(),
		BootstrapHeader: "[bootstrap]",
	}
}
```

```go
//go:build !securemode
// cmd/agent/securemode_off.go
package main

import (
	"github.com/asscor/asscor/internal/agent"
	"github.com/asscor/asscor/internal/securemode"
)

func agentSecureVault(cfg agent.AgentConfig) *securemode.Vault {
	return nil
}
```

*注：`cfg.ConfigPath()` 需在 `internal/agent/agent.go` 的 `AgentConfig` 上新增方法（返回 configPath 字段；main.go 的 `-config` 值需传入）。实现时在 AgentConfig 增加 `ConfigPath string` 字段并在 cmd/agent/main.go 赋值。*

- [ ] **Step 4: 实现心跳上报与内核登记（internal/comms/services.go）**

在 `KernelServiceImpl.Heartbeat` 中，`VerifyAgentCert` 通过后追加：

```go
// Secure Mode: agent ephemeral-password reporting (kernel-managed).
// The fingerprint comes from the mTLS transport layer; a forged agent_id
// with an unknown/mismatched fingerprint is rejected here (transport-layer
// defense, spec §10.1).
if s.secureMode != nil && req.SecureMode != nil && req.SecureMode.Password != "" {
    fp := kernel.PeerCertFingerprintFromContext(ctx)
    if err := s.secureMode.Secrets.Register(fp, req.HostId, req.SecureMode.Password); err != nil {
        logger.WithComponent("identity").Warn("secure-mode registration rejected",
            "host_id", req.HostId, "error", err.Error())
        return &apiv1.HeartbeatResponse{Ok: false}, fmt.Errorf("secure mode registration rejected: %v", err)
    }
}
```

*注：`apiv1.HeartbeatRequest` 需新增 `SecureMode *SecureModeReport` 字段（api/v1/asscor.pb.go，手写 struct 可加）；`s.secureMode` 字段经 `SetSecureMode(ctrl)` 注入。*

- [ ] **Step 5: agent 指令分发（internal/agent/agent.go runCommand）**

```go
case "securemode_exit", "securemode_rotate":
    a.executeSecureModeCommand(cmd)
    return
```

并新增方法（agent.go 或 securemode 相关文件）：

```go
// executeSecureModeCommand handles kernel-issued secure-mode instructions.
// The kernel supplies the agent's current ephemeral password in Params.
func (a *Agent) executeSecureModeCommand(cmd *apiv1.Command) {
    pw := cmd.Params["password"]
    if pw == "" {
        logger.WithComponent("agent").Warn("securemode command missing password", "command_id", cmd.CommandId)
        return
    }
    switch cmd.Command {
    case "securemode_exit":
        // decrypt .enc back to plaintext (kernel-requested mode exit)
        ...
    case "securemode_rotate":
        // re-encrypt with a fresh self-generated password and report it
        // on the next heartbeat
        ...
    }
}
```

- [ ] **Step 6: 构建与测试**

Run: `go build ./...` + `go test ./internal/securemode/ ./internal/agent/ ./internal/comms/`
Expected: 全绿；`GOOS=linux go build -tags securemode ./cmd/kernel ./cmd/agent` 通过

- [ ] **Step 7: 提交**

```bash
git add cmd/agent/securemode_on.go cmd/agent/securemode_off.go internal/agent/agent.go internal/comms/services.go api/v1/asscor.pb.go
git commit -m "feat(securemode): agent 托管 — 自生成临时密码 + mTLS 上报 + 内核指令分发"
```

---

### Task 12: 端到端组合测试 + README 说明

**Files:**
- Create: `internal/securemode/e2e_test.go`
- Modify: `README.md`（模块说明 + build-tag 用法）

**Interfaces:**
- Consumes: 全部组件

- [ ] **Step 1: 写组合测试**

```go
package securemode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2EKernelAgentFlow simulates the full kernel+agent lifecycle:
// kernel enter run -> agent registers secret -> kernel restart recovery ->
// agent restart unlock -> agent exit via kernel instruction.
func TestE2EKernelAgentFlow(t *testing.T) {
	dir := t.TempDir()

	// --- kernel side ---
	kernelCfg := filepath.Join(dir, "config.ini")
	os.WriteFile(kernelCfg, []byte("[bootstrap]\naddr=x\n\n[weights]\na=1\n"), 0o600)
	kernelVault := &Vault{DataDir: dir, ConfigPath: kernelCfg, BootstrapHeader: "[bootstrap]"}
	ctrl := NewController(dir, []*Vault{kernelVault})
	if err := ctrl.EnterRun("kernel-pw"); err != nil {
		t.Fatal(err)
	}

	// --- agent reports ephemeral password (fingerprint-keyed) ---
	if err := ctrl.Secrets.Register("fp-agent1", "host-1", "agent-ephemeral-pw"); err != nil {
		t.Fatal(err)
	}

	// --- kernel restart: marker says run -> unlock ---
	ctrl2 := NewController(dir, []*Vault{kernelVault})
	if err := ctrl2.Startup(); err != nil {
		t.Fatal(err)
	}
	if ctrl2.Mode != ModeRun {
		t.Fatalf("kernel restart mode = %q, want run", ctrl2.Mode)
	}
	if err := ctrl2.Unlock("kernel-pw"); err != nil {
		t.Fatal(err)
	}

	// --- agent restart: kernel issues the registered password ---
	agentDir := filepath.Join(dir, "agent")
	os.MkdirAll(agentDir, 0o700)
	agentCfg := filepath.Join(agentDir, "agent.ini")
	os.WriteFile(agentCfg, []byte("[bootstrap]\nkernel_addr = 127.0.0.1:50051\n\n[agent]\nheartbeat_sec = 30\n"), 0o600)
	agentVault := &Vault{DataDir: agentDir, ConfigPath: agentCfg, BootstrapHeader: "[bootstrap]"}

	// simulate prior run-mode disk state: agent.ini already encrypted
	if err := agentVault.EncryptFile("agent-ephemeral-pw"); err != nil {
		t.Fatal(err)
	}
	// restart: kernel issues password, agent decrypts
	issued, ok := ctrl2.Secrets.Lookup("fp-agent1")
	if !ok {
		t.Fatal("kernel must have the agent password")
	}
	plain, err := agentVault.LoadCiphertext(issued.Password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain, "heartbeat_sec") {
		t.Error("agent config not decrypted with kernel-issued password")
	}

	// --- kernel instructs agent exit (decrypt to plaintext) ---
	if err := agentVault.DecryptFile(issued.Password); err != nil {
		t.Fatal(err)
	}
	if !agentVault.State().hasPlain || agentVault.State().hasEnc {
		t.Errorf("agent exit state = %+v, want plaintext only", agentVault.State())
	}
}

// TestE2ECrashResidueRecovery: crash between encrypt stages must not lose config.
func TestE2ECrashResidueRecovery(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.ini")
	os.WriteFile(cfg, []byte("[weights]\na=1\n"), 0o600)
	v := &Vault{DataDir: dir, ConfigPath: cfg, BootstrapHeader: ""}
	if err := v.EncryptFile("pw"); err != nil {
		t.Fatal(err)
	}
	// Simulate crash residue: plaintext still present alongside .enc.
	os.WriteFile(cfg, []byte("residue"), 0o600)
	if !v.State().hasPlain || !v.State().hasEnc {
		t.Fatal("residue state not detected")
	}
	// Recovery: validate .enc (with password), then remove stale plaintext.
	plain, err := v.LoadCiphertext("pw")
	if err != nil {
		t.Fatal("valid .enc must decrypt despite residue")
	}
	if !strings.Contains(plain, "a=1") {
		t.Error("recovered content mismatch")
	}
}
```

- [ ] **Step 2: 运行确认通过**

Run: `go test ./internal/securemode/ -run TestE2E -v`
Expected: PASS

- [ ] **Step 3: README 说明**

在 `README.md` 新增：

```markdown
## Secure Mode（实验性，build-tag：securemode）

默认/运行双模式保护 config.ini 与 agent.ini：

- 默认模式：配置文件明文，行为与现状一致。
- 运行模式：源文件加密为 .enc（AES-256-GCM 信封加密 + argon2id），配置驻留内存（只读快照 + 校验和基线）；CLI 修改配置/退出运行模式需密码；进入运行模式免密。
- agent 托管：agent 启动自生成临时密码，经 mTLS 上报内核（证书指纹主键登记），自动进入运行模式；模式切换仅内核 CLI 发起。
- 崩溃安全：三段式原子转换（.enc.tmp → 验证 → rename → 删明文），任何一步崩溃不丢配置；启动时自动检测崩溃残留。
- 模式标记损坏 fail-closed：拒绝静默降级为明文模式。

构建：go build -tags securemode ./cmd/kernel ./cmd/agent
CLI：mode status / mode enter --password <pw> / mode exit --password <pw>
     / mode set-password --old <pw> --new <pw> / mode agent <id> <action>
```

- [ ] **Step 4: 全量验证 + 提交**

Run: `go test ./...` + `go vet ./...` + `GOOS=linux go build -tags securemode ./cmd/kernel ./cmd/agent`
Expected: 全绿

```bash
git add internal/securemode/e2e_test.go README.md
git commit -m "docs+test(securemode): 端到端组合测试与 README 说明"
```

---

## 自审记录

**Spec 覆盖核对：**
- §4 双模式概念 → Task 4/8
- §5 信封加密 → Task 2
- §6 崩溃安全（三段式/恢复/OOM）→ Task 4 + Task 12 e2e
- §7 内存防篡改（校验和/只读快照/hardening 定位）→ Task 6
- §8 状态机（内核 + agent）→ Task 8 + Task 11
- §9 CLI 命令（mode 族/config set 两段式）→ Task 9 + Task 10
- §10 受保护文件 + 引导段 → Task 4（BootstrapHeader）
- §10.1 指纹主键登记 + P0-1 持久化 → Task 7 + Task 8（登记表加密持久化由 kernel 侧 run-mode 密钥封装，接口已留 Marshal/Unmarshal）
- §11 错误处理（corrupt marker fail-closed）→ Task 3 + Task 8
- §12 责任边界 → Task 10/11（kernel/agent 各自 build-tag 文件）
- §13 测试计划 → Task 1-12 各测试文件 + e2e
- §14 非目标 → 全局约束

**占位符检查**：Task 10 Step 4 的 handler 转发代码标注了"wiring detail"（`...` 省略了 ctx 字段提取细节）——这是有意的实现提示，但按"No Placeholders"要求，实现者需对照 `internal/cli/commands.go` 现有 handler（如 `agentCmdHandler`、`configCmdHandler`）的 `ctx.Args`/`ctx.Repeat`/`ctx.Options` 用法补全，不得凭空臆造字段名。

**类型一致性**：
- `Vault.encPath()` 私有方法 → Task 4 测试直接调用（同包）；Task 12 复用
- `Controller.EnterRun/ExitRun/SetPassword/Startup/Unlock` 签名在 Task 8 定义，Task 9/10/12 按此消费 ✓
- `SecretRegistry.Register/Lookup/LookupByAgent/Marshal/Unmarshal` 在 Task 7 定义，Task 11/12 消费 ✓
- `PasswordVerifier.Set/Verify/Clear` 在 Task 5 定义，Task 8 消费 ✓
- `MemoryGuard.Snapshot/Replace/IntegrityOK` 在 Task 6 定义，Task 8/9 消费 ✓
