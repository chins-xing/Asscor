# 熵扩展包实现计划 — 里程碑 A（算法内核 + 存储 CIA + 审计）

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现熵扩展包的纯内核部分：行为/网络/基线三维的瞬时偏移算法（ΔH + KL 双读、多尺度）、加密情报存储（独立密钥域、逐帧哈希链、链头签名、原子写与崩溃恢复）、完整审计链（含审计失败时高危操作拒绝），全部可在无系统依赖下单元测试。

**Architecture:** 新增 `internal/entropy` 包（全部文件带 `//go:build entropy`），分成三层：纯函数层（`math.go`/`symbolize.go`/`window.go`/`reading.go`，零 IO，直接用手算向量测试）、存储层（`keys.go`/`store.go`/`frames.go`/`chain.go`/`baseline.go`，复用 `securemode.Encrypt/Decrypt` 做帧加密，自持独立密钥域）、审计层（`audit.go`/`verify.go`，数据链与审计链交叉锚定）。链头签名复用 `internal/integrity` 新增的通用字节签名 API（`NewSigner`/`SignBytes`/`VerifyBytes`）。本里程碑不接 kernel、不采集、不出 CLI 命令——这些是里程碑 B。

**Tech Stack:** Go 1.26、`crypto/hmac`+`crypto/sha256`、`golang.org/x/crypto/argon2`（经 `internal/securemode` 复用）、AES-256-GCM（同）、`encoding/json`、build-tag 模块模式（`entropy` / `integrity`）。

**Spec:** `docs/ENTROPY_EXTENSION_DESIGN_2026-09-08.md`

## Global Constraints

- 分支：`ASSCOR-Research-Core`；提交说明必须**中文**（`feat(entropy): …` 前缀可保留英文分类词，正文中文）。
- `internal/entropy` 内**所有** `.go` 文件（含测试）首行 `//go:build entropy`；测试命令 `go test -tags entropy ./internal/entropy/...`。
- 读数语义：`Ĥ` 归一化到 `[0,1]`（除数 = 配置的**固定符号空间上限** `N`，不随观测抖动）；`ΔH` 无量纲、可负；`KL` 非负。
- 平滑：`ε = 1e-6`；`KL` 用混合平滑 `q' = (1-|S|·ε)·q + ε`（保证 `Σq' = 1` 且 `q' ≥ ε`），杜绝 `log₂(0)`。
- 未标定语义：无基线时 `State = "uncalibrated"`，所有尺度读数为 `nil`，**不得输出 0**；未标定不产生阈值事件。
- 加密：复用 `internal/securemode.Encrypt(plaintext []byte, password string)` / `Decrypt(data []byte, password string)`（argon2id KEK + AES-GCM 信封）；熵包**自持独立密钥域**，不共享 securemode/integrity 密钥。
- 签名：扩展 `internal/integrity`（`NewSigner(keyPath)` / `SignBytes` / `VerifyBytes`），链头 HMAC-SHA256；`integrity` 关闭时 stub 版返回错误/空签名，熵包**不得静默产出无签名链**（里程碑 B 负责启动告警）。
- 权限：目录 `0700`、文件 `0600`，且**写入后显式 `Chmod`**（与 umask 无关，沿 RC-L2 范式）。
- 原子写：`tmp → Chmod → fsync(file) → rename → fsync(dir)`；崩溃残留 tmp 在下次启动清理。
- 时间：帧时间戳 UTC + 单调时钟读数；窗口按时间戳判定；帧按 `(HostID, Seq)` 幂等去重；时钟回拨 > 1s 记审计并标记帧。
- 审计失败 ⇒ 打点/重置/滚动/导出**一律拒绝**（`RequireOperable()` 返回错误）；采集可继续但帧标记 `unaudited`。
- **不提供**单帧删除/修改接口。
- 非 Linux 平台必须可编译（`syscall.Umask` 相关测试限定 `linux`）。
- gofmt 必须干净（提交前对改动文件做 LF 归一的 `gofmt -l` 检查，Windows 本地 CRLF 会假阳性）。

**Scope 说明（拆分为两个计划）**：本计划只覆盖里程碑 A。保留策略滚动（retention）因涉及链分段语义（spec §6.4 与 §6.3 的衔接）延后到里程碑 B 并与作者确认，本里程碑只实现无破坏性的导出。里程碑 B（kernel SPI 契约、`cmd/kernel` on/off 装配、`[entropy]` 配置、agent 侧四面采集器、独立熵帧通道、kernel 汇聚发布、CLI 熵命令、扩展包清单、MODULE_TAGS/agent tags、依赖闭包断言与非回归验收）的任务清单见文末 §里程碑 B，待 A 验收并合并后另写逐步骤计划。

---

## File Structure

| 文件 | 职责 |
|---|---|
| `internal/integrity/signbytes.go` | `integrity` 构建：通用字节签名（`NewSigner`/`SignBytes`/`VerifyBytes`），独立密钥路径 |
| `internal/integrity/signbytes_stub.go` | `!integrity` 构建：同名 API 的降级实现（返回错误/空签名） |
| `internal/integrity/signbytes_test.go` | 往返/篡改/密钥隔离测试（tag `integrity`） |
| `internal/integrity/signbytes_perms_test.go` | umask 0000 下密钥文件仍 0600（tag `integrity && linux`） |
| `internal/entropy/math.go` | 纯函数：`Dist`/`Normalize`/`Entropy`/`NormalizedEntropy`/`DeltaH`/`KLSmooth` |
| `internal/entropy/symbolize.go` | 特征→符号：枚举直通、连续等宽分箱、固定符号空间 `N` |
| `internal/entropy/window.go` | 多尺度窗口选择、去重、斜率、持续时长、完整度 |
| `internal/entropy/reading.go` | `Reading`/`DimReading`/`ScaleReading` 组装与未标定语义 |
| `internal/entropy/keys.go` | 独立密钥域：帧密钥（hex 字符串）+ 链签名密钥（32B） |
| `internal/entropy/store.go` | 目录创建、原子写、权限保持、崩溃残留清理 |
| `internal/entropy/frames.go` | 加密帧日志（append-only、按大小滚动）+ 链索引写入 |
| `internal/entropy/chain.go` | 逐帧哈希链、链头签名、链校验（截断/重排/篡改） |
| `internal/entropy/audit.go` | 审计事件、审计链、`RequireOperable`、交叉锚定 |
| `internal/entropy/baseline.go` | 打点/重置（重置强制原因）、历史归档、`PrevHash` 链接 |
| `internal/entropy/verify.go` | 全链校验报告（数据链 + 审计链 + 链头签名） |

---

### Task 1: integrity 通用字节签名扩展

**Files:**
- Create: `internal/integrity/signbytes.go`
- Create: `internal/integrity/signbytes_stub.go`
- Test: `internal/integrity/signbytes_test.go`
- Test: `internal/integrity/signbytes_perms_test.go`

**Interfaces:**
- Consumes: 既有 `internal/integrity` 的 HMAC-SHA256 范式与密钥文件权限约定。
- Produces:
  - `func NewSigner(keyPath string) (*Signer, error)`
  - `func (s *Signer) SignBytes(payload []byte) string`
  - `func (s *Signer) VerifyBytes(payload []byte, sig string) bool`
  - `!integrity` 版：`NewSigner` 返回错误、`SignBytes` 返回 `""`、`VerifyBytes` 返回 `false`。

- [ ] **Step 1: 写失败测试**

```go
//go:build integrity

package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignBytesRoundTrip(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "entropy-chain.key")
	s, err := NewSigner(keyPath)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	payload := []byte("frame|1|1700000000|deadbeef")
	sig := s.SignBytes(payload)
	if sig == "" {
		t.Fatal("SignBytes returned empty signature")
	}
	if !s.VerifyBytes(payload, sig) {
		t.Error("VerifyBytes must accept its own signature")
	}
}

func TestSignBytesTamperRejected(t *testing.T) {
	s, err := NewSigner(filepath.Join(t.TempDir(), "chain.key"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	sig := s.SignBytes([]byte("original"))
	if s.VerifyBytes([]byte("tampered"), sig) {
		t.Error("VerifyBytes must reject a modified payload")
	}
}

func TestSignBytesIndependentKeys(t *testing.T) {
	dir := t.TempDir()
	a, err := NewSigner(filepath.Join(dir, "a.key"))
	if err != nil {
		t.Fatalf("NewSigner a: %v", err)
	}
	b, err := NewSigner(filepath.Join(dir, "b.key"))
	if err != nil {
		t.Fatalf("NewSigner b: %v", err)
	}
	sig := a.SignBytes([]byte("payload"))
	if b.VerifyBytes([]byte("payload"), sig) {
		t.Error("a signature must not verify under b's key")
	}
}

func TestSignBytesKeyPersisted(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "persist.key")
	first, err := NewSigner(keyPath)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	sig := first.SignBytes([]byte("payload"))
	second, err := NewSigner(keyPath)
	if err != nil {
		t.Fatalf("reload NewSigner: %v", err)
	}
	if !second.VerifyBytes([]byte("payload"), sig) {
		t.Error("key must persist across NewSigner calls on the same path")
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file must exist: %v", err)
	}
}
```

```go
//go:build integrity && linux

package integrity

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSignBytesKeyModeIgnoresPermissiveUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	keyPath := filepath.Join(t.TempDir(), "umask.key")
	if _, err := NewSigner(keyPath); err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key mode = %o, want 600 (umask must not widen it)", perm)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags integrity ./internal/integrity/ -run 'TestSignBytes' -v`
Expected: FAIL —`undefined: NewSigner`（编译失败）

- [ ] **Step 3: 实现（integrity 版）**

```go
//go:build integrity

package integrity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// NewSigner loads (or creates) an independent HMAC-SHA256 key at keyPath and
// returns a Signer bound to it. It is deliberately independent from the
// singleton GetSigner(): callers that need their own key domain (e.g. the
// entropy extension's chain-head signatures) must not share the assessment
// signing key. The key file is written 0600 with an explicit chmod so a
// permissive umask cannot widen it (RC-L2 pattern).
func NewSigner(keyPath string) (*Signer, error) {
	if keyPath == "" {
		return nil, fmt.Errorf("signer key path is required")
	}
	if data, err := os.ReadFile(keyPath); err == nil && len(data) >= 32 {
		return &Signer{key: data}, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	if dir := filepath.Dir(keyPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create key dir: %w", err)
		}
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		return nil, fmt.Errorf("write signing key: %w", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return nil, fmt.Errorf("chmod signing key: %w", err)
	}
	return &Signer{key: key}, nil
}

// SignBytes returns the hex HMAC-SHA256 of payload under this signer's key.
func (s *Signer) SignBytes(payload []byte) string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	key := s.key
	s.mu.RUnlock()
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyBytes reports whether sig is the valid signature of payload.
func (s *Signer) VerifyBytes(payload []byte, sig string) bool {
	if s == nil || sig == "" {
		return false
	}
	provided, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	s.mu.RLock()
	key := s.key
	s.mu.RUnlock()
	if len(key) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return hmac.Equal(provided, mac.Sum(nil))
}
```

```go
//go:build !integrity

package integrity

import "fmt"

// NewSigner always fails when the integrity module is disabled: callers must
// not silently produce unsigned chains (spec §8.5).
func NewSigner(keyPath string) (*Signer, error) {
	return nil, fmt.Errorf("integrity module disabled: cannot create signer")
}

// SignBytes returns an empty signature when the integrity module is disabled.
func (s *Signer) SignBytes(payload []byte) string { return "" }

// VerifyBytes always returns false when the integrity module is disabled.
func (s *Signer) VerifyBytes(payload []byte, sig string) bool { return false }
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags integrity ./internal/integrity/ -v`
Expected: PASS（含既有 integrity 测试）

再验证降级构建：`go build ./internal/integrity/`（无 tag）→ 期望成功（stub 版提供同名方法）。

- [ ] **Step 5: 提交**

```bash
git add internal/integrity/signbytes.go internal/integrity/signbytes_stub.go internal/integrity/signbytes_test.go internal/integrity/signbytes_perms_test.go
git commit -F build/commit-msg.txt
```

提交说明（写入 `build/commit-msg.txt`）：`feat(integrity): 增加通用字节签名 API（独立密钥域）`，正文说明熵扩展包链头签名需要签任意字节、原 Sign() 只接受评分结果、密钥文件 0600 显式 chmod。

---

### Task 2: 熵数学原语（math.go）

**Files:**
- Create: `internal/entropy/math.go`
- Test: `internal/entropy/math_test.go`

**Interfaces:**
- Produces:
  - `type Dist map[string]float64`
  - `func Normalize(counts map[string]float64) Dist`
  - `func Entropy(d Dist) float64`
  - `func NormalizedEntropy(d Dist, symbolSpace int) float64`
  - `func DeltaH(now, base Dist, symbolSpace int) float64`
  - `func KLSmooth(now, base Dist, eps float64) float64`

- [ ] **Step 1: 写失败测试**

```go
//go:build entropy

package entropy

import "math"

func almost(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestEntropyUniform(t *testing.T) {
	d := Normalize(map[string]float64{"a": 1, "b": 1, "c": 1, "d": 1})
	if got := Entropy(d); !almost(got, 2) {
		t.Errorf("Entropy(uniform 4) = %v, want 2", got)
	}
	if got := NormalizedEntropy(d, 4); !almost(got, 1) {
		t.Errorf("NormalizedEntropy(uniform 4, N=4) = %v, want 1", got)
	}
}

func TestEntropyTwoPoint(t *testing.T) {
	d := Normalize(map[string]float64{"a": 1, "b": 1})
	if got := Entropy(d); !almost(got, 1) {
		t.Errorf("Entropy(0.5/0.5) = %v, want 1", got)
	}
}

func TestNormalizeIgnoresNegativesAndEmpty(t *testing.T) {
	d := Normalize(map[string]float64{"a": 3, "b": -1})
	if len(d) != 1 || !almost(d["a"], 1) {
		t.Errorf("Normalize = %v, want only a=1", d)
	}
	if d := Normalize(map[string]float64{}); len(d) != 0 {
		t.Errorf("Normalize(empty) = %v, want empty", d)
	}
}

func TestDeltaHSignConvention(t *testing.T) {
	base := Normalize(map[string]float64{"a": 1, "b": 1})
	more := Normalize(map[string]float64{"a": 1, "b": 1, "c": 1, "d": 1})
	less := Normalize(map[string]float64{"a": 9, "b": 1})
	if got := DeltaH(more, base, 4); got <= 0 {
		t.Errorf("DeltaH(more uniform) = %v, want > 0", got)
	}
	if got := DeltaH(less, base, 4); got >= 0 {
		t.Errorf("DeltaH(less uniform) = %v, want < 0", got)
	}
}

func TestKLSmoothKnownValueAndIdentity(t *testing.T) {
	now := Normalize(map[string]float64{"a": 3, "b": 1})
	base := Normalize(map[string]float64{"a": 1, "b": 1})
	// 0.75*log2(1.5) + 0.25*log2(0.5) = 0.4387 - 0.25 = 0.1887 (smoothed ≈ same)
	if got := KLSmooth(now, base, 1e-6); math.Abs(got-0.1887) > 1e-3 {
		t.Errorf("KLSmooth = %v, want ≈0.1887", got)
	}
	if got := KLSmooth(base, base, 1e-6); math.Abs(got) > 1e-9 {
		t.Errorf("KLSmooth(p,p) = %v, want 0", got)
	}
}

func TestKLSmoothZeroBaseProbability(t *testing.T) {
	now := Normalize(map[string]float64{"a": 1, "b": 1})
	base := Normalize(map[string]float64{"a": 1})
	got := KLSmooth(now, base, 1e-6)
	if math.IsInf(got, 0) || math.IsNaN(got) {
		t.Fatalf("KLSmooth with zero base probability must stay finite, got %v", got)
	}
	if got <= 0 {
		t.Errorf("KLSmooth = %v, want > 0 for a novel symbol", got)
	}
}
```

注：测试文件需 `import "testing"`（上面的 `func almost` 之外）。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags entropy ./internal/entropy/ -run 'TestEntropy|TestDeltaH|TestKLSmooth|TestNormalize' -v`
Expected: FAIL — `undefined: Normalize`

- [ ] **Step 3: 实现**

```go
package entropy

import "math"

// Dist is a normalized probability distribution over discrete symbols.
type Dist map[string]float64

// Normalize converts symbol counts into a probability distribution, ignoring
// non-positive counts. An empty or all-zero input yields an empty Dist.
func Normalize(counts map[string]float64) Dist {
	total := 0.0
	for _, c := range counts {
		if c > 0 {
			total += c
		}
	}
	if total == 0 {
		return Dist{}
	}
	out := make(Dist, len(counts))
	for sym, c := range counts {
		if c > 0 {
			out[sym] = c / total
		}
	}
	return out
}

// Entropy returns the Shannon entropy in bits (-Σ p·log₂p), skipping p ≤ 0.
func Entropy(d Dist) float64 {
	h := 0.0
	for _, p := range d {
		if p > 0 {
			h -= p * math.Log2(p)
		}
	}
	return h
}

// NormalizedEntropy returns H / log₂N so the result lands in [0,1]. N is the
// CONFIGURED fixed symbol-space ceiling — not the observed symbol count — so
// the divisor never jitters with the window contents.
func NormalizedEntropy(d Dist, symbolSpace int) float64 {
	if symbolSpace < 2 {
		return 0
	}
	denom := math.Log2(float64(symbolSpace))
	if denom <= 0 {
		return 0
	}
	return Entropy(d) / denom
}

// DeltaH is the normalized-entropy difference between now and base. It is
// dimensionless and signed: positive means "more disorderly than baseline".
func DeltaH(now, base Dist, symbolSpace int) float64 {
	return NormalizedEntropy(now, symbolSpace) - NormalizedEntropy(base, symbolSpace)
}

// KLSmooth returns D(now‖base) in bits with mixture smoothing
// q' = (1-|S|·eps)·q + eps, which keeps Σq' = 1 and q' ≥ eps, so log₂(0)
// can never occur even when the baseline never observed a symbol.
func KLSmooth(now, base Dist, eps float64) float64 {
	if eps <= 0 {
		eps = 1e-6
	}
	symbols := map[string]struct{}{}
	for s := range now {
		symbols[s] = struct{}{}
	}
	for s := range base {
		symbols[s] = struct{}{}
	}
	if len(symbols) == 0 {
		return 0
	}
	alpha := eps * float64(len(symbols))
	if alpha > 1 {
		alpha = 1
	}
	total := 0.0
	for s := range symbols {
		p := now[s]
		if p <= 0 {
			continue
		}
		q := (1-alpha)*base[s] + eps
		total += p * math.Log2(p/q)
	}
	return total
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags entropy ./internal/entropy/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(entropy): 熵数学原语 — 归一化熵/ΔH/平滑 KL`，正文注明归一化除数用固定符号空间上限、平滑保证 Σq'=1。

---

### Task 3: 特征符号化（symbolize.go）

**Files:**
- Create: `internal/entropy/symbolize.go`
- Test: `internal/entropy/symbolize_test.go`

**Interfaces:**
- Produces:
  - `type BinSpec struct { Min, Max float64; Bins int }`
  - `type Features struct { Enums map[string][]string; Ranges map[string]BinSpec }`
  - `func (f Features) Space(name string) (int, bool)`
  - `func (f Features) SymbolizeNumeric(name string, v float64) (string, error)`
  - `func (f Features) SymbolizeEnum(name string, v string) (string, error)`

- [ ] **Step 1: 写失败测试**

```go
//go:build entropy

package entropy

import "testing"

func testFeatures() Features {
	return Features{
		Enums:  map[string][]string{"proto": {"tcp", "udp", "icmp"}},
		Ranges: map[string]BinSpec{"cpu": {Min: 0, Max: 100, Bins: 8}},
	}
}

func TestSymbolizeNumericBinning(t *testing.T) {
	f := testFeatures()
	cases := []struct{ in float64; want string }{
		{0, "b0"}, {12.5, "b1"}, {99.9, "b7"}, {100, "b7"},
	}
	for _, c := range cases {
		got, err := f.SymbolizeNumeric("cpu", c.in)
		if err != nil {
			t.Fatalf("SymbolizeNumeric(%v): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("SymbolizeNumeric(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSymbolizeNumericClampsOutOfRange(t *testing.T) {
	f := testFeatures()
	if got, _ := f.SymbolizeNumeric("cpu", -50); got != "b0" {
		t.Errorf("below-min = %q, want b0", got)
	}
	if got, _ := f.SymbolizeNumeric("cpu", 500); got != "b7" {
		t.Errorf("above-max = %q, want b7", got)
	}
}

func TestSymbolizeUnknownFeatureIsError(t *testing.T) {
	f := testFeatures()
	if _, err := f.SymbolizeNumeric("disk", 1); err == nil {
		t.Error("unknown numeric feature must be an error")
	}
	if _, err := f.SymbolizeEnum("unregistered", "x"); err == nil {
		t.Error("unknown enum feature must be an error")
	}
}

func TestSymbolizeEnumPassThrough(t *testing.T) {
	f := testFeatures()
	if got, err := f.SymbolizeEnum("proto", "udp"); err != nil || got != "udp" {
		t.Errorf("SymbolizeEnum(udp) = %q,%v; want udp,nil", got, err)
	}
	// A value outside the declared value set is hashed into a catch-all symbol
	// so an unknown protocol still contributes to the distribution.
	if got, err := f.SymbolizeEnum("proto", "sctp"); err != nil || got != "other" {
		t.Errorf("unknown enum value = %q,%v; want other,nil", got, err)
	}
}

func TestSpaceIsFixedCeiling(t *testing.T) {
	f := testFeatures()
	if n, ok := f.Space("cpu"); !ok || n != 8 {
		t.Errorf("Space(cpu) = %d,%v; want 8,true", n, ok)
	}
	// Enum ceiling is the declared set size plus the catch-all symbol.
	if n, ok := f.Space("proto"); !ok || n != 4 {
		t.Errorf("Space(proto) = %d,%v; want 4,true", n, ok)
	}
	if _, ok := f.Space("nope"); ok {
		t.Error("Space(unregistered) must not report ok")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags entropy ./internal/entropy/ -run TestSymbolize -v`
Expected: FAIL — `undefined: Features`

- [ ] **Step 3: 实现**

```go
package entropy

import "fmt"

// BinSpec describes equal-width binning for one continuous feature.
type BinSpec struct {
	Min  float64
	Max  float64
	Bins int
}

// Features declares how raw feature values become discrete symbols. The
// declared ceilings are what Space returns: they are configuration, never
// derived from what a window happened to observe (spec §4.2).
type Features struct {
	Enums  map[string][]string
	Ranges map[string]BinSpec
}

// Space returns the fixed symbol-space ceiling N for a feature.
func (f Features) Space(name string) (int, bool) {
	if spec, ok := f.Ranges[name]; ok {
		if spec.Bins < 2 {
			return 0, false
		}
		return spec.Bins, true
	}
	if vals, ok := f.Enums[name]; ok {
		if len(vals) == 0 {
			return 0, false
		}
		return len(vals) + 1, true // + catch-all "other"
	}
	return 0, false
}

// SymbolizeNumeric maps a continuous value to its bin symbol, clamping
// out-of-range values into the boundary bins.
func (f Features) SymbolizeNumeric(name string, v float64) (string, error) {
	spec, ok := f.Ranges[name]
	if !ok {
		return "", fmt.Errorf("entropy: unregistered numeric feature %q", name)
	}
	if spec.Bins < 2 || spec.Max <= spec.Min {
		return "", fmt.Errorf("entropy: invalid bin spec for %q", name)
	}
	if v <= spec.Min {
		return "b0", nil
	}
	if v >= spec.Max {
		return fmt.Sprintf("b%d", spec.Bins-1), nil
	}
	width := (spec.Max - spec.Min) / float64(spec.Bins)
	idx := int((v - spec.Min) / width)
	if idx < 0 {
		idx = 0
	}
	if idx >= spec.Bins {
		idx = spec.Bins - 1
	}
	return fmt.Sprintf("b%d", idx), nil
}

// SymbolizeEnum passes a declared enum value through unchanged; undeclared
// values collapse into the catch-all "other" symbol so they still count.
func (f Features) SymbolizeEnum(name string, v string) (string, error) {
	vals, ok := f.Enums[name]
	if !ok {
		return "", fmt.Errorf("entropy: unregistered enum feature %q", name)
	}
	for _, allowed := range vals {
		if v == allowed {
			return v, nil
		}
	}
	return "other", nil
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags entropy ./internal/entropy/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(entropy): 特征符号化 — 等宽分箱/枚举直通/固定符号空间上限`。

---

### Task 4: 多尺度窗口与时间量（window.go）

**Files:**
- Create: `internal/entropy/window.go`
- Test: `internal/entropy/window_test.go`

**Interfaces:**
- Produces:
  - `type Sample struct { TS time.Time; Mono int64; HostID string; Seq uint64; Features map[string]float64 }`
  - `type Point struct { TS time.Time; Value float64 }`
  - `func Dedup(in []Sample) []Sample`
  - `func Select(in []Sample, hostID string, end time.Time, d time.Duration) []Sample`
  - `func Slope(pts []Point) float64`
  - `func DurationAbove(pts []Point, threshold float64) time.Duration`
  - `func Completeness(received, expected int) float64`
  - `func ClockSkewExceeded(prev, cur Sample, limit time.Duration) bool`

- [ ] **Step 1: 写失败测试**

```go
//go:build entropy

package entropy

import (
	"math"
	"testing"
	"time"
)

func at(base time.Time, sec int) time.Time { return base.Add(time.Duration(sec) * time.Second) }

func TestDedupKeepsFirstPerHostSeq(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	in := []Sample{
		{TS: at(base, 0), HostID: "h1", Seq: 1},
		{TS: at(base, 1), HostID: "h1", Seq: 1}, // duplicate
		{TS: at(base, 2), HostID: "h2", Seq: 1}, // different host, same seq
	}
	out := Dedup(in)
	if len(out) != 2 {
		t.Fatalf("Dedup len = %d, want 2", len(out))
	}
	if !out[0].TS.Equal(at(base, 0)) {
		t.Error("Dedup must keep the first occurrence")
	}
}

func TestSelectWindowByTimestampIgnoresArrivalOrder(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	in := []Sample{
		{TS: at(base, 300), HostID: "h1", Seq: 3},
		{TS: at(base, 30), HostID: "h1", Seq: 1},  // arrived out of order
		{TS: at(base, 120), HostID: "h1", Seq: 2},
		{TS: at(base, 1200), HostID: "h1", Seq: 9}, // outside window
		{TS: at(base, 100), HostID: "h2", Seq: 1},  // other host
	}
	got := Select(in, "h1", at(base, 300), 5*time.Minute)
	if len(got) != 3 {
		t.Fatalf("Select len = %d, want 3 (got %+v)", len(got), got)
	}
	for _, s := range got {
		if s.Seq == 9 || s.HostID != "h1" {
			t.Errorf("Select leaked an out-of-window/other-host sample: %+v", s)
		}
	}
}

func TestSlopeLinearSeries(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	pts := []Point{
		{TS: at(base, 0), Value: 1.0},
		{TS: at(base, 60), Value: 2.0},
		{TS: at(base, 120), Value: 3.0},
	}
	if got := Slope(pts); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("Slope = %v, want 1.0 per minute", got)
	}
	if got := Slope([]Point{{TS: base, Value: 5}}); got != 0 {
		t.Errorf("Slope(single point) = %v, want 0", got)
	}
}

func TestDurationAboveTakesLongestStretch(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	pts := []Point{
		{TS: at(base, 0), Value: 0.0},
		{TS: at(base, 60), Value: 0.5},
		{TS: at(base, 120), Value: 0.6},
		{TS: at(base, 180), Value: 0.7},
		{TS: at(base, 240), Value: 0.8},
		{TS: at(base, 300), Value: 0.9},
		{TS: at(base, 360), Value: 0.0},
		{TS: at(base, 420), Value: 0.5},
		{TS: at(base, 480), Value: 0.0},
	}
	if got := DurationAbove(pts, 0.4); got != 5*time.Minute {
		t.Errorf("DurationAbove = %v, want 5m (longest stretch)", got)
	}
}

func TestCompleteness(t *testing.T) {
	if got := Completeness(90, 100); math.Abs(got-0.9) > 1e-9 {
		t.Errorf("Completeness = %v, want 0.9", got)
	}
	if got := Completeness(5, 0); got != 0 {
		t.Errorf("Completeness with unknown expectation = %v, want 0", got)
	}
	if got := Completeness(150, 100); got != 1 {
		t.Errorf("Completeness must clamp to 1, got %v", got)
	}
}

func TestClockSkewExceededUsesMonoDelta(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	prev := Sample{TS: at(base, 0), Mono: 1000}
	ok := Sample{TS: at(base, 10), Mono: 11000}       // wall +10s, mono +10s
	skewed := Sample{TS: at(base, -30), Mono: 11000}  // wall went backwards
	if ClockSkewExceeded(prev, ok, time.Second) {
		t.Error("consistent clock must not be flagged")
	}
	if !ClockSkewExceeded(prev, skewed, time.Second) {
		t.Error("backwards wall clock must be flagged")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags entropy ./internal/entropy/ -run 'TestDedup|TestSelect|TestSlope|TestDurationAbove|TestCompleteness|TestClockSkew' -v`
Expected: FAIL — `undefined: Dedup`

- [ ] **Step 3: 实现**

```go
package entropy

import (
	"math"
	"time"
)

// Sample is one collected entropy frame at one instant.
type Sample struct {
	TS     time.Time
	Mono   int64 // monotonic clock reading (ns) captured with TS
	HostID string
	Seq    uint64
	// Features carries numeric feature values (cpu, port number, scores…).
	Features map[string]float64
	// Symbols carries enum-valued features (protocol, event type, source…);
	// numeric values live in Features and the two never overlap.
	Symbols map[string]string
}

// Point is a scalar time series entry (a per-window ΔH or KL reading).
type Point struct {
	TS    time.Time
	Value float64
}

// Dedup removes duplicate (HostID, Seq) frames, keeping the first occurrence,
// so retransmits are idempotent (spec §4.4).
func Dedup(in []Sample) []Sample {
	seen := make(map[string]struct{}, len(in))
	out := make([]Sample, 0, len(in))
	for _, s := range in {
		key := s.HostID + "\x00" + itoa(s.Seq)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	return out
}

// Select returns samples for hostID whose timestamp falls in [end-d, end],
// independent of arrival order.
func Select(in []Sample, hostID string, end time.Time, d time.Duration) []Sample {
	start := end.Add(-d)
	out := make([]Sample, 0, len(in))
	for _, s := range in {
		if s.HostID != hostID {
			continue
		}
		if s.TS.Before(start) || s.TS.After(end) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Slope is the least-squares slope of the series in value-per-minute; it
// returns 0 for fewer than two points or a degenerate time axis.
func Slope(pts []Point) float64 {
	if len(pts) < 2 {
		return 0
	}
	var sumX, sumY, sumXY, sumXX float64
	n := float64(len(pts))
	t0 := pts[0].TS
	for _, p := range pts {
		x := p.TS.Sub(t0).Minutes()
		sumX += x
		sumY += p.Value
		sumXY += x * p.Value
		sumXX += x * x
	}
	denom := n*sumXX - sumX*sumX
	if math.Abs(denom) < 1e-12 {
		return 0
	}
	return (n*sumXY - sumX*sumY) / denom
}

// DurationAbove returns the LONGEST continuous stretch whose value exceeds
// threshold — "sustained drift" rather than "sum of all excursions".
func DurationAbove(pts []Point, threshold float64) time.Duration {
	var longest, current time.Duration
	var prevTS time.Time
	started := false
	for _, p := range pts {
		if p.Value > threshold {
			if !started || p.TS.Sub(prevTS) > 2*time.Minute {
				current = 0
			}
			started = true
			if !prevTS.IsZero() {
				current += p.TS.Sub(prevTS)
			}
			prevTS = p.TS
			if current > longest {
				longest = current
			}
			continue
		}
		started = false
		prevTS = time.Time{}
		current = 0
	}
	return longest
}

// Completeness is received/expected clamped to [0,1]; an unknown expectation
// (expected ≤ 0) reports 0 rather than a misleading 1.
func Completeness(received, expected int) float64 {
	if expected <= 0 {
		return 0
	}
	v := float64(received) / float64(expected)
	if v > 1 {
		return 1
	}
	if v < 0 {
		return 0
	}
	return v
}

// ClockSkewExceeded reports whether the wall clock jumped backwards relative
// to the monotonic clock by more than limit (spec §4.4).
func ClockSkewExceeded(prev, cur Sample, limit time.Duration) bool {
	if prev.Mono == 0 || cur.Mono == 0 {
		return false
	}
	wall := cur.TS.Sub(prev.TS)
	mono := time.Duration(cur.Mono - prev.Mono)
	if wall < 0 && -wall > limit {
		return true
	}
	return math.Abs(float64(wall-mono)) > float64(limit)
}

// itoa is a tiny dependency-free uint64 formatter for map keys.
func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags entropy ./internal/entropy/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(entropy): 多尺度窗口与时间量 — 幂等去重/按时间戳选窗/斜率/持续时长/时钟回拨`。

---

### Task 5: 读数模型与未标定语义（reading.go）

**Files:**
- Create: `internal/entropy/reading.go`
- Test: `internal/entropy/reading_test.go`

**Interfaces:**
- Consumes: Task 2 `Dist`/`NormalizedEntropy`/`DeltaH`/`KLSmooth`。
- Produces:
  - `type Dim string`（`DimBehavior`/`DimNetwork`/`DimBaseline`）
  - `type Scale string`（`ScaleShort`/`ScaleMid`/`ScaleLong`）
  - `type ScaleSpec struct { Name Scale; Dur time.Duration }`
  - `func DefaultScales() []ScaleSpec`
  - `type ScaleReading struct { HNow, HBase, DeltaH, KL float64 }`
  - `type DimReading struct { Scales map[Scale]*ScaleReading }`
  - `type ChainRef struct { Seq uint64; Hash string; HeadSigOK bool }`
  - `type Reading struct { TS time.Time; HostID string; State string; Dims map[Dim]DimReading; Rates map[string]float64; Durations map[string]time.Duration; BaselineAge time.Duration; Completeness float64; ChainRef ChainRef }`
  - `const (StateCalibrated = "calibrated"; StateUncalibrated = "uncalibrated")`
  - `func BuildReading(hostID string, ts time.Time, spaces map[Dim]int, dists, base map[Dim]map[Scale]Dist, baselineTS time.Time) Reading`
  - `func ApplySeries(r *Reading, rates map[string][]Point, durations map[string][]Point, thresholds map[string]float64)`

- [ ] **Step 1: 写失败测试**

```go
//go:build entropy

package entropy

import (
	"testing"
	"time"
)

func testDists() (map[Dim]map[Scale]Dist, map[Dim]map[Scale]Dist) {
	now := map[Dim]map[Scale]Dist{
		DimBehavior: {ScaleShort: Normalize(map[string]float64{"a": 1, "b": 1, "c": 1, "d": 1})},
	}
	base := map[Dim]map[Scale]Dist{
		DimBehavior: {ScaleShort: Normalize(map[string]float64{"a": 1, "b": 1})},
	}
	return now, base
}

func TestBuildReadingUncalibratedOutputsNoNumbers(t *testing.T) {
	now, _ := testDists()
	spaces := map[Dim]int{DimBehavior: 4}
	r := BuildReading("h1", time.Unix(1700000000, 0).UTC(), spaces, now, nil, time.Time{})
	if r.State != StateUncalibrated {
		t.Fatalf("State = %q, want %q", r.State, StateUncalibrated)
	}
	if len(r.Dims) != 3 {
		t.Fatalf("Dims must list all three dimensions, got %d", len(r.Dims))
	}
	for dim, dr := range r.Dims {
		for scale, sr := range dr.Scales {
			if sr != nil {
				t.Errorf("uncalibrated %s/%s must be nil, got %+v", dim, scale, sr)
			}
		}
	}
}

func TestBuildReadingCalibratedComputesFourQuantities(t *testing.T) {
	now, base := testDists()
	spaces := map[Dim]int{DimBehavior: 4}
	bt := time.Unix(1700000000, 0).UTC()
	r := BuildReading("h1", bt.Add(time.Hour), spaces, now, base, bt)
	if r.State != StateCalibrated {
		t.Fatalf("State = %q, want calibrated", r.State)
	}
	sr := r.Dims[DimBehavior].Scales[ScaleShort]
	if sr == nil {
		t.Fatal("short-scale reading is nil")
	}
	// now uniform over 4 → Ĥ=1 ; base uniform over 2 → Ĥ=1 at N=4 → ΔH=0
	if sr.HNow != 1 || sr.HBase != 1 || sr.DeltaH != 0 {
		t.Errorf("unexpected four quantities: %+v", sr)
	}
	if sr.KL <= 0 {
		t.Errorf("KL = %v, want > 0 (now is broader than base)", sr.KL)
	}
	if r.BaselineAge != time.Hour {
		t.Errorf("BaselineAge = %v, want 1h", r.BaselineAge)
	}
}

func TestBuildReadingMissingScaleOnOneDimStaysNil(t *testing.T) {
	now, base := testDists()
	spaces := map[Dim]int{DimBehavior: 4}
	r := BuildReading("h1", time.Unix(1700000000, 0).UTC(), spaces, now, base, time.Unix(1700000000, 0).UTC())
	if r.Dims[DimBehavior].Scales[ScaleMid] != nil {
		t.Error("a scale absent from the inputs must be nil, not zero")
	}
}

func TestApplySeriesComputesRateAndDuration(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	now, baseD := testDists()
	spaces := map[Dim]int{DimBehavior: 4}
	r := BuildReading("h1", base.Add(time.Hour), spaces, now, baseD, base)

	series := []Point{
		{TS: base.Add(0 * time.Minute), Value: 0.0},
		{TS: base.Add(1 * time.Minute), Value: 0.5},
		{TS: base.Add(2 * time.Minute), Value: 0.6},
	}
	ApplySeries(&r,
		map[string][]Point{"behavior_short_delta_h": series},
		map[string][]Point{"behavior_short_delta_h": series},
		map[string]float64{"behavior_short_delta_h": 0.4},
	)
	if got := r.Rates["behavior_short_delta_h"]; got <= 0 {
		t.Errorf("rate = %v, want > 0", got)
	}
	if got := r.Durations["behavior_short_delta_h"]; got != time.Minute {
		t.Errorf("duration = %v, want 1m", got)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags entropy ./internal/entropy/ -run 'TestBuildReading|TestApplySeries' -v`
Expected: FAIL — `undefined: BuildReading`

- [ ] **Step 3: 实现**

```go
package entropy

import "time"

// Dim identifies one entropy dimension (spec §4.1).
type Dim string

const (
	DimBehavior Dim = "behavior"
	DimNetwork  Dim = "network"
	DimBaseline Dim = "baseline"
)

// AllDims is the fixed dimension order used for output.
func AllDims() []Dim { return []Dim{DimBehavior, DimNetwork, DimBaseline} }

// Scale identifies one time-scale layer (spec §4.3).
type Scale string

const (
	ScaleShort Scale = "short"
	ScaleMid   Scale = "mid"
	ScaleLong  Scale = "long"
)

// ScaleSpec binds a scale name to its window duration.
type ScaleSpec struct {
	Name Scale
	Dur  time.Duration
}

// DefaultScales is 5m / 1h / 24h (spec §4.3, appendix).
func DefaultScales() []ScaleSpec {
	return []ScaleSpec{
		{Name: ScaleShort, Dur: 5 * time.Minute},
		{Name: ScaleMid, Dur: time.Hour},
		{Name: ScaleLong, Dur: 24 * time.Hour},
	}
}

// ScaleReading holds the four published quantities of one dimension/scale.
type ScaleReading struct {
	HNow   float64
	HBase  float64
	DeltaH float64
	KL     float64
}

// DimReading holds one dimension across scales; a nil *ScaleReading means
// "no reading for this scale" (either uncalibrated, or that scale was not
// computed) — never a misleading zero.
type DimReading struct {
	Scales map[Scale]*ScaleReading
}

// ChainRef ties a reading back to the stored frame chain.
type ChainRef struct {
	Seq       uint64
	Hash      string
	HeadSigOK bool
}

// Reading is the published result structure (spec §9.1).
type Reading struct {
	TS           time.Time
	HostID       string
	State        string
	Dims         map[Dim]DimReading
	Rates        map[string]float64
	Durations    map[string]time.Duration
	BaselineAge  time.Duration
	Completeness float64
	ChainRef     ChainRef
}

// State values (spec §9.1).
const (
	StateCalibrated   = "calibrated"
	StateUncalibrated = "uncalibrated"
)

// BuildReading assembles a reading. base == nil (no baseline snapshot yet)
// yields the uncalibrated state with every scale nil. baselineTS zero also
// means uncalibrated.
func BuildReading(
	hostID string,
	ts time.Time,
	spaces map[Dim]int,
	dists map[Dim]map[Scale]Dist,
	base map[Dim]map[Scale]Dist,
	baselineTS time.Time,
) Reading {
	r := Reading{
		TS:     ts,
		HostID: hostID,
		State:  StateUncalibrated,
		Dims:   make(map[Dim]DimReading, len(AllDims())),
		Rates:  map[string]float64{},
		Durations: map[string]time.Duration{},
	}
	for _, dim := range AllDims() {
		dr := DimReading{Scales: map[Scale]*ScaleReading{}}
		for _, spec := range DefaultScales() {
			dr.Scales[spec.Name] = nil
		}
		r.Dims[dim] = dr
	}
	if base == nil || baselineTS.IsZero() {
		return r
	}
	r.State = StateCalibrated
	r.BaselineAge = ts.Sub(baselineTS)
	for _, dim := range AllDims() {
		dr := r.Dims[dim]
		for _, spec := range DefaultScales() {
			nowD, okNow := dists[dim][spec.Name]
			baseD, okBase := base[dim][spec.Name]
			if !okNow || !okBase {
				continue
			}
			dr.Scales[spec.Name] = &ScaleReading{
				HNow:   NormalizedEntropy(nowD, spaces[dim]),
				HBase:  NormalizedEntropy(baseD, spaces[dim]),
				DeltaH: DeltaH(nowD, baseD, spaces[dim]),
				KL:     KLSmooth(nowD, baseD, 1e-6),
			}
		}
		r.Dims[dim] = dr
	}
	return r
}

// ApplySeries fills the derived time quantities: the least-squares rate and
// the longest above-threshold stretch per series key. Series absent from
// durations/thresholds keep only their rate (or nothing) — absence is not
// fabricated into a zero duration.
func ApplySeries(r *Reading, rates, durations map[string][]Point, thresholds map[string]float64) {
	if r == nil {
		return
	}
	for key, pts := range rates {
		r.Rates[key] = Slope(pts)
	}
	for key, pts := range durations {
		th, ok := thresholds[key]
		if !ok {
			continue
		}
		r.Durations[key] = DurationAbove(pts, th)
	}
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags entropy ./internal/entropy/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(entropy): 读数模型 — 四量组装/未标定输出 nil/派生时间量`。

---

### Task 5B: 维度分布聚合（aggregate.go）

> **执行顺序：** 紧随 Task 5 执行（编号 5B 表示插入在 Task 5 与 Task 6 之间）。

**Files:**
- Create: `internal/entropy/aggregate.go`
- Test: `internal/entropy/aggregate_test.go`

**Interfaces:**
- Consumes: Task 3 `Features`/`SymbolizeNumeric`/`SymbolizeEnum`；Task 4 `Sample`/`Select`；Task 5 `Dim`/`ScaleSpec`。
- Produces:
  - `type DimFeatures map[Dim]map[string]bool`
  - `func DefaultDimFeatures() DimFeatures`
  - `func Aggregate(f Features, dims DimFeatures, hostID string, samples []Sample, spec ScaleSpec, end time.Time) (map[Dim]Dist, error)`

- [ ] **Step 1: 写失败测试**

```go
//go:build entropy

package entropy

import (
	"testing"
	"time"
)

func aggFeatures() Features {
	return Features{
		Enums:  map[string][]string{"conn_proto": {"tcp", "udp"}},
		Ranges: map[string]BinSpec{"cpu": {Min: 0, Max: 100, Bins: 8}},
	}
}

func aggSamples(base time.Time) []Sample {
	return []Sample{
		{TS: base.Add(0), HostID: "h1", Seq: 1,
			Features: map[string]float64{"cpu": 5},
			Symbols:  map[string]string{"conn_proto": "tcp"}},
		{TS: base.Add(30 * time.Second), HostID: "h1", Seq: 2,
			Features: map[string]float64{"cpu": 10},
			Symbols:  map[string]string{"conn_proto": "tcp"}},
		{TS: base.Add(time.Minute), HostID: "h1", Seq: 3,
			Features: map[string]float64{"cpu": 20},
			Symbols:  map[string]string{"conn_proto": "udp"}},
	}
}

func TestAggregateCountsSymbolsPerDimension(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	dims := DimFeatures{
		DimNetwork:  {"conn_proto": true},
		DimBaseline: {"cpu": true},
	}
	got, err := Aggregate(aggFeatures(), dims, "h1", aggSamples(base), ScaleSpec{Name: ScaleShort, Dur: 5 * time.Minute}, base.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	net := got[DimNetwork]
	if net["tcp"] != 2.0/3.0 || net["udp"] != 1.0/3.0 {
		t.Errorf("network dist = %v, want tcp=2/3 udp=1/3", net)
	}
	// cpu 5 and 10 both land in bin b0, 20 lands in b1 (width 12.5) → 2/3 : 1/3
	base0 := got[DimBaseline]
	if base0["b0"] != 2.0/3.0 || base0["b1"] != 1.0/3.0 {
		t.Errorf("baseline dist = %v, want b0=2/3 b1=1/3", base0)
	}
}

func TestAggregateExcludesOutOfWindowSamples(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	samples := aggSamples(base)
	samples = append(samples, Sample{TS: base.Add(time.Hour), HostID: "h1", Seq: 9,
		Symbols: map[string]string{"conn_proto": "udp"}})
	got, err := Aggregate(aggFeatures(), DimFeatures{DimNetwork: {"conn_proto": true}}, "h1", samples,
		ScaleSpec{Name: ScaleShort, Dur: 5 * time.Minute}, base.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if _, ok := got[DimNetwork]["udp"]; !ok || got[DimNetwork]["udp"] == 1.0 {
		t.Errorf("out-of-window sample leaked into the distribution: %v", got[DimNetwork])
	}
}

func TestAggregateRejectsUnknownFeatureName(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	_, err := Aggregate(aggFeatures(), DimFeatures{DimNetwork: {"nope": true}}, "h1", aggSamples(base),
		ScaleSpec{Name: ScaleShort, Dur: time.Minute}, base)
	if err == nil {
		t.Fatal("an unregistered feature name must be an error, not a silent skip")
	}
}

func TestDefaultDimFeaturesCoversSpecGroups(t *testing.T) {
	dims := DefaultDimFeatures()
	for _, dim := range AllDims() {
		if len(dims[dim]) == 0 {
			t.Errorf("dimension %s has no features mapped", dim)
		}
	}
	if !dims[DimNetwork]["conn_proto"] {
		t.Error("network dimension must include conn_proto")
	}
	if !dims[DimBaseline]["ssam_score"] || !dims[DimBaseline]["srd_score"] {
		t.Error("baseline dimension must include the SSAM/SRD score features")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags entropy ./internal/entropy/ -run TestAggregate -v`
Expected: FAIL — `undefined: Aggregate`

- [ ] **Step 3: 实现**

```go
package entropy

import (
	"fmt"
	"time"
)

// DimFeatures maps each dimension to the feature names that feed it. The
// groups follow spec §4.1 and are configuration, not runtime discovery.
type DimFeatures map[Dim]map[string]bool

// DefaultDimFeatures returns the spec §4.1 feature groups. Baseline is the
// catch-all dimension: resource pressure plus the pre-existing intelligence
// links (SSAM/SRD scores, CTI sources, topology events).
func DefaultDimFeatures() DimFeatures {
	return DimFeatures{
		DimBehavior: {
			"proc_start": true, "proc_stop": true,
			"login": true, "logout": true,
			"file_change": true, "log_event_type": true,
		},
		DimNetwork: {
			"conn_proto": true, "conn_port": true, "listen_port": true,
		},
		DimBaseline: {
			"cpu": true, "mem": true, "io": true, "load": true,
			"ssam_score": true, "srd_score": true,
			"cti_source": true, "topo_event": true,
		},
	}
}

// Aggregate builds one probability distribution per dimension from the
// samples inside the scale window. Enum features are read from Sample.Symbols
// and binned features from Sample.Features; a feature name registered in
// neither is an error rather than a silent omission.
func Aggregate(f Features, dims DimFeatures, hostID string, samples []Sample, spec ScaleSpec, end time.Time) (map[Dim]Dist, error) {
	out := make(map[Dim]Dist, len(dims))
	window := Select(samples, hostID, end, spec.Dur)
	for dim, feats := range dims {
		counts := map[string]float64{}
		for _, s := range window {
			for name := range feats {
				if _, ok := f.Enums[name]; ok {
					sym, err := f.SymbolizeEnum(name, s.Symbols[name])
					if err != nil {
						return nil, err
					}
					counts[sym]++
					continue
				}
				if _, ok := f.Ranges[name]; ok {
					v, ok := s.Features[name]
					if !ok {
						continue
					}
					sym, err := f.SymbolizeNumeric(name, v)
					if err != nil {
						return nil, err
					}
					counts[sym]++
					continue
				}
				return nil, fmt.Errorf("entropy: feature %q is mapped to dimension %s but symbolization is not configured", name, dim)
			}
		}
		out[dim] = Normalize(counts)
	}
	return out, nil
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags entropy ./internal/entropy/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(entropy): 维度分布聚合 — 特征分组/枚举与分箱符号化/越窗样本排除`。

---

### Task 6: 存储基座与独立密钥域（store.go / keys.go）

**Files:**
- Create: `internal/entropy/store.go`
- Create: `internal/entropy/keys.go`
- Test: `internal/entropy/store_test.go`
- Test: `internal/entropy/keys_perms_test.go`

**Interfaces:**
- Produces:
  - `func EnsureDir(path string) error`
  - `func WriteFileAtomic(path string, data []byte, mode os.FileMode) error`
  - `func CleanupTempFiles(dir string) error`
  - `type KeySet struct { FrameKey string; ChainKey []byte; ChainKeyPath string }`
  - `func LoadOrCreateKeys(dir string) (KeySet, bool, error)`
  - `const (keyFrameFile = "entropy-frame.key"; keyChainFile = "entropy-chain.key"; keysSubdir = "keys")`

- [ ] **Step 1: 写失败测试**

```go
//go:build entropy

package entropy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicLeavesNoTempAndWritesContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit", "audit.jsonl")
	if err := WriteFileAtomic(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("content = %q, want hello", got)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if len(e.Name()) > 4 && e.Name()[len(e.Name())-4:] == ".tmp" {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestWriteFileAtomicOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := WriteFileAtomic(path, []byte("v1"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteFileAtomic(path, []byte("v2-longer"), 0o600); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "v2-longer" {
		t.Errorf("content = %q, want v2-longer", got)
	}
}

func TestCleanupTempFiles(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "frames.log.1234.tmp")
	if err := os.WriteFile(stale, []byte("partial"), 0o600); err != nil {
		t.Fatalf("seed stale tmp: %v", err)
	}
	if err := CleanupTempFiles(dir); err != nil {
		t.Fatalf("CleanupTempFiles: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("stale temp file must be removed")
	}
}

func TestLoadOrCreateKeysCreatesThenReuses(t *testing.T) {
	dir := t.TempDir()
	first, created, err := LoadOrCreateKeys(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKeys: %v", err)
	}
	if !created {
		t.Error("first call must report created=true")
	}
	if len(first.FrameKey) < 32 || len(first.ChainKey) != 32 {
		t.Errorf("unexpected key shapes: frame=%d bytes chain=%d bytes", len(first.FrameKey), len(first.ChainKey))
	}
	second, created2, err := LoadOrCreateKeys(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreateKeys: %v", err)
	}
	if created2 {
		t.Error("second call must report created=false")
	}
	if second.FrameKey != first.FrameKey || string(second.ChainKey) != string(first.ChainKey) {
		t.Error("keys must persist across calls")
	}
}

func TestKeysAreDistinctFromEachOther(t *testing.T) {
	dir := t.TempDir()
	ks, _, err := LoadOrCreateKeys(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKeys: %v", err)
	}
	if string(ks.ChainKey) == ks.FrameKey {
		t.Error("frame key and chain key must be independent")
	}
}
```

```go
//go:build entropy && linux

package entropy

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestKeyAndDirModesIgnorePermissiveUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := t.TempDir()
	if _, _, err := LoadOrCreateKeys(dir); err != nil {
		t.Fatalf("LoadOrCreateKeys: %v", err)
	}
	keysDir := filepath.Join(dir, keysSubdir)
	info, err := os.Stat(keysDir)
	if err != nil {
		t.Fatalf("stat keys dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("keys dir mode = %o, want 700", perm)
	}
	for _, name := range []string{keyFrameFile, keyChainFile} {
		fi, err := os.Stat(filepath.Join(keysDir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, perm)
		}
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags entropy ./internal/entropy/ -run 'TestWriteFileAtomic|TestCleanupTempFiles|TestLoadOrCreateKeys|TestKeysAreDistinct' -v`
Expected: FAIL — `undefined: WriteFileAtomic`

- [ ] **Step 3: 实现**

```go
package entropy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// dirMode / fileMode are the fixed permissions of the entropy data area
// (spec §6.1). They are applied with an explicit chmod so a permissive umask
// cannot widen them (RC-L2 pattern).
const (
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
	tmpSuffix            = ".tmp"
)

// EnsureDir creates dir (and parents) with 0700 and re-asserts the mode.
func EnsureDir(path string) error {
	if path == "" {
		return fmt.Errorf("entropy: empty directory path")
	}
	if err := os.MkdirAll(path, dirMode); err != nil {
		return fmt.Errorf("entropy: create %s: %w", path, err)
	}
	if err := os.Chmod(path, dirMode); err != nil {
		return fmt.Errorf("entropy: chmod %s: %w", path, err)
	}
	return nil
}

// WriteFileAtomic writes data via tmp → chmod → fsync(file) → rename →
// fsync(dir), so a crash never leaves a half-written authoritative file.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := EnsureDir(dir); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d%s", path, os.Getpid(), tmpSuffix)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("entropy: create temp %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("entropy: write temp %s: %w", tmp, err)
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("entropy: chmod temp %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("entropy: fsync temp %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("entropy: close temp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("entropy: rename %s: %w", path, err)
	}
	return syncDir(dir)
}

// CleanupTempFiles removes stale atomic-write leftovers under dir.
func CleanupTempFiles(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, tmpSuffix) {
			if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
				return fmt.Errorf("entropy: remove stale temp %s: %w", path, rmErr)
			}
		}
		return nil
	})
}

// syncDir fsyncs a directory so a rename survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("entropy: open dir %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		// Directory fsync is unsupported on some platforms/filesystems; the
		// rename itself already landed, so this is not fatal.
		return nil
	}
	return nil
}
```

```go
package entropy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// Key file names inside <dir>/keys (spec §6.1).
const (
	keysSubdir   = "keys"
	keyFrameFile = "entropy-frame.key"
	keyChainFile = "entropy-chain.key"
)

// KeySet is the entropy pack's INDEPENDENT key domain: it is never shared
// with securemode or integrity keys (spec §6.2).
type KeySet struct {
	// FrameKey is the hex-encoded 32-byte key used as the Encrypt password.
	FrameKey string
	// ChainKey is the raw 32-byte HMAC key used for chain-head signatures.
	ChainKey []byte
	// ChainKeyPath is where ChainKey lives, for integrity.NewSigner.
	ChainKeyPath string
}

// LoadOrCreateKeys loads the entropy key domain, generating it on first use.
// created reports whether this call generated new keys (callers must audit
// that as key.init).
func LoadOrCreateKeys(dir string) (KeySet, bool, error) {
	keysDir := filepath.Join(dir, keysSubdir)
	if err := EnsureDir(keysDir); err != nil {
		return KeySet{}, false, err
	}
	framePath := filepath.Join(keysDir, keyFrameFile)
	chainPath := filepath.Join(keysDir, keyChainFile)

	created := false
	frameRaw, err := loadOrCreateRaw(framePath, 32)
	if err != nil {
		return KeySet{}, false, err
	}
	if frameRaw == nil {
		created = true
		frameRaw, err = readKey(framePath)
		if err != nil {
			return KeySet{}, false, err
		}
	}
	chainRaw, err := loadOrCreateRaw(chainPath, 32)
	if err != nil {
		return KeySet{}, false, err
	}
	if chainRaw == nil {
		created = true
		chainRaw, err = readKey(chainPath)
		if err != nil {
			return KeySet{}, false, err
		}
	}
	return KeySet{
		FrameKey:     hex.EncodeToString(frameRaw),
		ChainKey:     chainRaw,
		ChainKeyPath: chainPath,
	}, created, nil
}

// loadOrCreateRaw returns (nil, nil) when the key already existed, the new key
// bytes when it generated one, and an error otherwise.
func loadOrCreateRaw(path string, size int) ([]byte, error) {
	if data, err := readKey(path); err == nil && len(data) >= size {
		return nil, nil
	}
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("entropy: generate key: %w", err)
	}
	if err := WriteFileAtomic(path, key, fileMode); err != nil {
		return nil, err
	}
	return key, nil
}

func readKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("entropy: read key %s: %w", path, err)
	}
	return data, nil
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags entropy ./internal/entropy/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(entropy): 存储基座与独立密钥域 — 原子写/权限显式 chmod/tmp 清理`。

---

### Task 7: 加密帧日志（frames.go）

> **执行顺序：** 先完成 Task 8（`chain.go` 的 `ChainEntry`/`FrameHash`），再执行本任务——本任务依赖它们的类型与函数；任务编号按文件分组，不代表执行次序。

**Files:**
- Create: `internal/entropy/frames.go`
- Test: `internal/entropy/frames_test.go`

**Interfaces:**
- Consumes: Task 6 `KeySet`/`WriteFileAtomic`/`EnsureDir`；Task 8 的 `ChainEntry`/`FrameHash`（本任务先按接口签名实现，Task 8 补齐 `VerifyChain`）。
- Produces:
  - `type Frame struct { Seq uint64; TS time.Time; HostID string; Payload []byte }`
  - `type FrameStore struct { Dir string; Key string; MaxBytes int64; signer *integrity.Signer }`
  - `func OpenFrameStore(dir, frameKey, chainKeyPath string, maxBytes int64) (*FrameStore, error)`
  - `func (s *FrameStore) Append(f Frame) (ChainEntry, error)`
  - `func (s *FrameStore) ReadAll() ([]Frame, error)`
  - `func (s *FrameStore) Entries() ([]ChainEntry, error)`

- [ ] **Step 1: 写失败测试**

```go
//go:build entropy

package entropy

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *FrameStore {
	t.Helper()
	dir := t.TempDir()
	ks, _, err := LoadOrCreateKeys(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKeys: %v", err)
	}
	st, err := OpenFrameStore(dir, ks.FrameKey, ks.ChainKeyPath, 1<<20)
	if err != nil {
		t.Fatalf("OpenFrameStore: %v", err)
	}
	return st
}

func TestFrameAppendReadRoundTrip(t *testing.T) {
	st := newTestStore(t)
	ts := time.Unix(1700000000, 0).UTC()
	payload := []byte(`{"cpu":12.5,"proto":"tcp"}`)
	entry, err := st.Append(Frame{Seq: 1, TS: ts, HostID: "h1", Payload: payload})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if entry.Seq != 1 || entry.Hash == "" || entry.PrevHash != "" {
		t.Errorf("unexpected first chain entry: %+v", entry)
	}
	frames, err := st.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(frames) != 1 || !bytes.Equal(frames[0].Payload, payload) {
		t.Fatalf("round trip mismatch: %+v", frames)
	}
	if !frames[0].TS.Equal(ts) || frames[0].HostID != "h1" {
		t.Errorf("metadata lost: %+v", frames[0])
	}
}

func TestFramePayloadIsEncryptedAtRest(t *testing.T) {
	st := newTestStore(t)
	secret := []byte("UNIQUE-PLAINTEXT-MARKER-9f3a")
	if _, err := st.Append(Frame{Seq: 1, TS: time.Unix(1700000000, 0).UTC(), HostID: "h1", Payload: secret}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(st.Dir, "frames", "*.log"))
	if len(files) == 0 {
		t.Fatal("no frame log written")
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read frame log: %v", err)
	}
	if bytes.Contains(raw, secret) {
		t.Error("plaintext payload found on disk — frames must be encrypted at rest")
	}
}

func TestFrameChainLinksSequentially(t *testing.T) {
	st := newTestStore(t)
	for i := uint64(1); i <= 3; i++ {
		if _, err := st.Append(Frame{Seq: i, TS: time.Unix(1700000000+int64(i), 0).UTC(), HostID: "h1", Payload: []byte("x")}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	entries, err := st.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].PrevHash != entries[i-1].Hash {
			t.Errorf("entry %d PrevHash = %q, want %q", i, entries[i].PrevHash, entries[i-1].Hash)
		}
	}
}

func TestFrameRollsOverAtMaxBytes(t *testing.T) {
	dir := t.TempDir()
	ks, _, err := LoadOrCreateKeys(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKeys: %v", err)
	}
	st, err := OpenFrameStore(dir, ks.FrameKey, ks.ChainKeyPath, 512)
	if err != nil {
		t.Fatalf("OpenFrameStore: %v", err)
	}
	for i := uint64(1); i <= 12; i++ {
		if _, err := st.Append(Frame{Seq: i, TS: time.Unix(1700000000+int64(i), 0).UTC(), HostID: "h1", Payload: bytes.Repeat([]byte("p"), 64)}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(st.Dir, "frames", "*.log"))
	if len(files) < 2 {
		t.Errorf("expected rollover into a second file, got %v", files)
	}
	frames, err := st.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(frames) != 12 {
		t.Errorf("ReadAll across rolled files = %d, want 12", len(frames))
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags entropy ./internal/entropy/ -run 'TestFrame' -v`
Expected: FAIL — `undefined: OpenFrameStore`

- [ ] **Step 3: 实现**

```go
package entropy

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/chins-xing/asscor/internal/integrity"
	"github.com/chins-xing/asscor/internal/securemode"
)

const (
	framesSubdir = "frames"
	chainSubdir  = "chain"
	indexFile    = "index.jsonl"
	headFile     = "head.json"
)

// Frame is one collected observation batch (encrypted at rest).
type Frame struct {
	Seq     uint64
	TS      time.Time
	HostID  string
	Payload []byte
}

// FrameStore is the append-only encrypted frame log plus its hash-chain index.
type FrameStore struct {
	Dir       string
	Key       string
	MaxBytes  int64
	// HeadPath is where the signed chain head is written.
	HeadPath  string
	// Auditor, when set, receives chain.head.signed events.
	Auditor   *Auditor
	entries   []ChainEntry
	curFile   *os.File
	curSize   int64
	curIndex int
	// unsigFrames / lastSign drive chain-head signing (spec §6.3).
	unsigFrames int
	lastSign    time.Time
	signer      *integrity.Signer
	mu          sync.Mutex
}

// Chain-head signing thresholds (spec §6.3, appendix): every 256 frames or
// every 5 minutes, whichever comes first.
const (
	headSignFrames   = 256
	headSignInterval = 5 * time.Minute
)

// OpenFrameStore opens (creating if needed) the frame area, cleans stale
// temporaries, and replays the chain index into memory so appends continue
// the existing chain.
func OpenFrameStore(dir, frameKey, chainKeyPath string, maxBytes int64) (*FrameStore, error) {
	if err := EnsureDir(filepath.Join(dir, framesSubdir)); err != nil {
		return nil, err
	}
	if err := EnsureDir(filepath.Join(dir, chainSubdir)); err != nil {
		return nil, err
	}
	if err := CleanupTempFiles(dir); err != nil {
		return nil, err
	}
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	signer, err := integrity.NewSigner(chainKeyPath)
	if err != nil {
		return nil, fmt.Errorf("entropy: create chain signer: %w", err)
	}
	s := &FrameStore{
		Dir:      dir,
		Key:      frameKey,
		MaxBytes: maxBytes,
		HeadPath: filepath.Join(dir, chainSubdir, headFile),
		curIndex: 1,
		signer:   signer,
	}
	entries, err := s.loadEntries()
	if err != nil {
		return nil, err
	}
	s.entries = entries
	if n := len(entries); n > 0 {
		s.lastSign = entries[n-1].TS
	}
	files, _ := filepath.Glob(filepath.Join(dir, framesSubdir, "*.log"))
	sort.Strings(files)
	if len(files) > 0 {
		last := files[len(files)-1]
		s.curIndex = parseFrameIndex(last)
		fi, statErr := os.Stat(last)
		if statErr == nil {
			s.curSize = fi.Size()
		}
	}
	f, err := os.OpenFile(s.filePath(s.curIndex), os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		return nil, fmt.Errorf("entropy: open frame log: %w", err)
	}
	if err := f.Chmod(fileMode); err != nil {
		f.Close()
		return nil, fmt.Errorf("entropy: chmod frame log: %w", err)
	}
	s.curFile = f
	return s, nil
}

func (s *FrameStore) filePath(idx int) string {
	return filepath.Join(s.Dir, framesSubdir, fmt.Sprintf("%06d.log", idx))
}

func parseFrameIndex(path string) int {
	name := filepath.Base(path)
	var idx int
	if _, err := fmt.Sscanf(name, "%06d.log", &idx); err != nil || idx <= 0 {
		return 1
	}
	return idx
}

// Append encrypts the frame, links it into the hash chain, persists both the
// ciphertext line and the index entry, and rotates the log when it grows past
// MaxBytes. It returns the new chain entry.
func (s *FrameStore) Append(f Frame) (ChainEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ciphertext, err := securemode.Encrypt(f.Payload, s.Key)
	if err != nil {
		return ChainEntry{}, fmt.Errorf("entropy: encrypt frame: %w", err)
	}
	prev := ""
	if n := len(s.entries); n > 0 {
		prev = s.entries[n-1].Hash
	}
	hash := FrameHash(prev, f.Seq, f.TS, ciphertext)
	entry := ChainEntry{Seq: f.Seq, TS: f.TS, Hash: hash, PrevHash: prev}

	line, err := json.Marshal(map[string]interface{}{
		"seq":  f.Seq,
		"ts":   f.TS.UTC().Format(time.RFC3339Nano),
		"host": f.HostID,
		"ct":   base64.StdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return ChainEntry{}, fmt.Errorf("entropy: marshal frame: %w", err)
	}
	line = append(line, '\n')

	if s.curSize+int64(len(line)) > s.MaxBytes {
		if err := s.rotateLocked(); err != nil {
			return ChainEntry{}, err
		}
	}
	if _, err := s.curFile.Write(line); err != nil {
		return ChainEntry{}, fmt.Errorf("entropy: write frame: %w", err)
	}
	if err := s.curFile.Sync(); err != nil {
		return ChainEntry{}, fmt.Errorf("entropy: fsync frame: %w", err)
	}
	s.curSize += int64(len(line))

	s.entries = append(s.entries, entry)
	if err := s.appendIndexLocked(entry); err != nil {
		return ChainEntry{}, err
	}
	if err := s.maybeSignHeadLocked(); err != nil {
		return ChainEntry{}, err
	}
	return entry, nil
}

// maybeSignHeadLocked signs the chain head when the frame-count or time
// threshold is reached and audits the signature. A signing failure is
// returned rather than swallowed: an unsigned chain must never look signed.
// The first frame always signs, giving the chain an initial head.
func (s *FrameStore) maybeSignHeadLocked() error {
	s.unsigFrames++
	due := s.unsigFrames >= headSignFrames ||
		s.lastSign.IsZero() ||
		time.Since(s.lastSign) >= headSignInterval
	if !due {
		return nil
	}
	sig, err := SignHead(s.entries, s.signer)
	if err != nil {
		return err
	}
	if err := WriteHead(s.HeadPath, sig); err != nil {
		return err
	}
	s.lastSign = time.Now().UTC()
	s.unsigFrames = 0
	if s.Auditor != nil {
		if err := s.Auditor.Append(AuditEvent{
			Type:   EvChainHeadSigned,
			Actor:  "kernel",
			Object: "chain",
			Result: "ok",
			Details: map[string]string{
				"from_seq": itoa(sig.FromSeq),
				"to_seq":   itoa(sig.ToSeq),
				"head":     sig.HeadHash,
			},
		}); err != nil {
			return fmt.Errorf("entropy: chain head signed but audit failed: %w", err)
		}
	}
	return nil
}

func (s *FrameStore) rotateLocked() error {
	if s.curFile != nil {
		if err := s.curFile.Close(); err != nil {
			return fmt.Errorf("entropy: close frame log: %w", err)
		}
	}
	s.curIndex++
	s.curSize = 0
	f, err := os.OpenFile(s.filePath(s.curIndex), os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		return fmt.Errorf("entropy: create frame log: %w", err)
	}
	if err := f.Chmod(fileMode); err != nil {
		f.Close()
		return fmt.Errorf("entropy: chmod frame log: %w", err)
	}
	s.curFile = f
	return nil
}

func (s *FrameStore) indexPath() string {
	return filepath.Join(s.Dir, chainSubdir, indexFile)
}

func (s *FrameStore) appendIndexLocked(e ChainEntry) error {
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("entropy: marshal chain entry: %w", err)
	}
	ciphertext, err := securemode.Encrypt(payload, s.Key)
	if err != nil {
		return fmt.Errorf("entropy: encrypt chain entry: %w", err)
	}
	line := append([]byte(base64.StdEncoding.EncodeToString(ciphertext)), '\n')

	f, err := os.OpenFile(s.indexPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		return fmt.Errorf("entropy: open chain index: %w", err)
	}
	defer f.Close()
	if err := f.Chmod(fileMode); err != nil {
		return fmt.Errorf("entropy: chmod chain index: %w", err)
	}
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("entropy: write chain index: %w", err)
	}
	return f.Sync()
}

func (s *FrameStore) loadEntries() ([]ChainEntry, error) {
	f, err := os.Open(s.indexPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("entropy: open chain index: %w", err)
	}
	defer f.Close()

	var entries []ChainEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		ciphertext, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil {
			return nil, fmt.Errorf("entropy: decode chain entry: %w", err)
		}
		payload, err := securemode.Decrypt(ciphertext, s.Key)
		if err != nil {
			return nil, fmt.Errorf("entropy: decrypt chain entry: %w", err)
		}
		var e ChainEntry
		if err := json.Unmarshal(payload, &e); err != nil {
			return nil, fmt.Errorf("entropy: unmarshal chain entry: %w", err)
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("entropy: scan chain index: %w", err)
	}
	return entries, nil
}

// Entries returns a copy of the in-memory chain index.
func (s *FrameStore) Entries() ([]ChainEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ChainEntry, len(s.entries))
	copy(out, s.entries)
	return out, nil
}

// ReadAll decrypts every stored frame in chain order.
func (s *FrameStore) ReadAll() ([]Frame, error) {
	files, _ := filepath.Glob(filepath.Join(s.Dir, framesSubdir, "*.log"))
	sort.Strings(files)
	var frames []Frame
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("entropy: open frame log %s: %w", path, err)
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
		for scanner.Scan() {
			raw := scanner.Bytes()
			if len(raw) == 0 {
				continue
			}
			var rec struct {
				Seq  uint64 `json:"seq"`
				TS   string `json:"ts"`
				Host string `json:"host"`
				CT   string `json:"ct"`
			}
			if err := json.Unmarshal(raw, &rec); err != nil {
				f.Close()
				return nil, fmt.Errorf("entropy: unmarshal frame: %w", err)
			}
			ciphertext, err := base64.StdEncoding.DecodeString(rec.CT)
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("entropy: decode frame: %w", err)
			}
			payload, err := securemode.Decrypt(ciphertext, s.Key)
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("entropy: decrypt frame: %w", err)
			}
			ts, _ := time.Parse(time.RFC3339Nano, rec.TS)
			frames = append(frames, Frame{Seq: rec.Seq, TS: ts, HostID: rec.Host, Payload: payload})
		}
		if err := scanner.Err(); err != nil {
			f.Close()
			return nil, fmt.Errorf("entropy: scan frame log %s: %w", path, err)
		}
		f.Close()
	}
	return frames, nil
}

// Close releases the active frame log handle.
func (s *FrameStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.curFile == nil {
		return nil
	}
	err := s.curFile.Close()
	s.curFile = nil
	return err
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags entropy ./internal/entropy/ -v`
Expected: PASS（本任务需要 Task 8 的 `ChainEntry` 与 `FrameHash` 已存在；若按顺序执行请先做 Task 8 的类型定义，或把 Task 8 的类型与 `FrameHash` 一并落地后再跑本任务测试）

- [ ] **Step 5: 提交**

提交说明：`feat(entropy): 加密帧日志 — 落盘即加密/按大小滚动/链索引持久化`。

---

### Task 8: 逐帧哈希链与链头签名（chain.go）

**Files:**
- Create: `internal/entropy/chain.go`
- Test: `internal/entropy/chain_test.go`

**Interfaces:**
- Consumes: Task 1 `integrity.NewSigner`/`SignBytes`/`VerifyBytes`。
- Produces:
  - `type ChainEntry struct { Seq uint64; TS time.Time; Hash string; PrevHash string }`
  - `func FrameHash(prevHash string, seq uint64, ts time.Time, ciphertext []byte) string`
  - `type HeadSig struct { FromSeq, ToSeq uint64; TS time.Time; HeadHash string; Sig string }`
  - `func SignHead(entries []ChainEntry, signer *integrity.Signer) (HeadSig, error)`
  - `func VerifyChain(entries []ChainEntry, sig *HeadSig, signer *integrity.Signer) error`
  - `func WriteHead(path string, sig HeadSig) error`
  - `func ReadHead(path string) (*HeadSig, error)`

- [ ] **Step 1: 写失败测试**

```go
//go:build entropy

package entropy

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/chins-xing/asscor/internal/integrity"
)

func testEntry(seq uint64, prev string) ChainEntry {
	ts := time.Unix(1700000000+int64(seq), 0).UTC()
	ct := []byte{byte(seq)}
	return ChainEntry{Seq: seq, TS: ts, Hash: FrameHash(prev, seq, ts, ct), PrevHash: prev}
}

func testChain(n int) []ChainEntry {
	entries := make([]ChainEntry, 0, n)
	prev := ""
	for i := 1; i <= n; i++ {
		e := testEntry(uint64(i), prev)
		entries = append(entries, e)
		prev = e.Hash
	}
	return entries
}

func testSigner(t *testing.T) *integrity.Signer {
	t.Helper()
	s, err := integrity.NewSigner(filepath.Join(t.TempDir(), "chain.key"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestVerifyChainAcceptsIntactChain(t *testing.T) {
	entries := testChain(5)
	signer := testSigner(t)
	sig, err := SignHead(entries, signer)
	if err != nil {
		t.Fatalf("SignHead: %v", err)
	}
	if err := VerifyChain(entries, &sig, signer); err != nil {
		t.Fatalf("VerifyChain on intact chain: %v", err)
	}
}

func TestVerifyChainDetectsTampering(t *testing.T) {
	entries := testChain(5)
	signer := testSigner(t)
	sig, _ := SignHead(entries, signer)

	entries[2].Hash = "deadbeef"
	err := VerifyChain(entries, &sig, signer)
	if err == nil {
		t.Fatal("tampered chain must fail verification")
	}
}

func TestVerifyChainDetectsReorder(t *testing.T) {
	entries := testChain(5)
	signer := testSigner(t)
	sig, _ := SignHead(entries, signer)

	entries[1], entries[3] = entries[3], entries[1]
	if err := VerifyChain(entries, &sig, signer); err == nil {
		t.Fatal("reordered chain must fail verification")
	}
}

func TestVerifyChainDetectsTruncation(t *testing.T) {
	entries := testChain(5)
	signer := testSigner(t)
	sig, _ := SignHead(entries, signer)

	truncated := entries[:3]
	if err := VerifyChain(truncated, &sig, signer); err == nil {
		t.Fatal("truncated chain must fail verification against the signed head")
	}
}

func TestVerifyChainRejectsForeignSigner(t *testing.T) {
	entries := testChain(3)
	sig, _ := SignHead(entries, testSigner(t))
	if err := VerifyChain(entries, &sig, testSigner(t)); err == nil {
		t.Fatal("a signature from a different key domain must not verify")
	}
}

func TestHeadRoundTrip(t *testing.T) {
	entries := testChain(3)
	signer := testSigner(t)
	sig, _ := SignHead(entries, signer)
	path := filepath.Join(t.TempDir(), "chain", "head.json")
	if err := WriteHead(path, sig); err != nil {
		t.Fatalf("WriteHead: %v", err)
	}
	got, err := ReadHead(path)
	if err != nil {
		t.Fatalf("ReadHead: %v", err)
	}
	if got == nil || got.ToSeq != sig.ToSeq || got.Sig != sig.Sig {
		t.Errorf("head round trip mismatch: %+v vs %+v", got, sig)
	}
	if err := ReadHeadMissing(filepath.Join(t.TempDir(), "nope.json")); err != nil {
		t.Errorf("missing head must be reported as absence, got %v", err)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags entropy,integrity ./internal/entropy/ -run 'TestVerifyChain|TestHead' -v`
Expected: FAIL — `undefined: FrameHash`

- [ ] **Step 3: 实现**

```go
package entropy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/chins-xing/asscor/internal/integrity"
)

// ChainEntry is one link of the frame hash chain.
type ChainEntry struct {
	Seq      uint64    `json:"seq"`
	TS       time.Time `json:"ts"`
	Hash     string    `json:"hash"`
	PrevHash string    `json:"prev_hash"`
}

// HeadSig is the periodically signed chain head (spec §6.3).
type HeadSig struct {
	FromSeq  uint64    `json:"from_seq"`
	ToSeq    uint64    `json:"to_seq"`
	TS       time.Time `json:"ts"`
	HeadHash string    `json:"head_hash"`
	Sig      string    `json:"sig"`
}

// FrameHash links a frame's ciphertext into the chain: any insertion,
// deletion or reorder breaks it.
func FrameHash(prevHash string, seq uint64, ts time.Time, ciphertext []byte) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte{0})
	h.Write([]byte(itoa(seq)))
	h.Write([]byte{0})
	h.Write([]byte(ts.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte{0})
	h.Write(ciphertext)
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalHead renders the signed head payload deterministically.
func canonicalHead(from, to uint64, ts time.Time, headHash string) []byte {
	return []byte(fmt.Sprintf("v1|%d|%d|%s|%s", from, to, ts.UTC().Format(time.RFC3339Nano), headHash))
}

// SignHead signs the current chain head with an independent key domain.
// An empty chain yields an error: there is nothing to sign, and a caller must
// not mistake that for a valid empty head.
func SignHead(entries []ChainEntry, signer *integrity.Signer) (HeadSig, error) {
	if len(entries) == 0 {
		return HeadSig{}, fmt.Errorf("entropy: refusing to sign an empty chain")
	}
	if signer == nil {
		return HeadSig{}, fmt.Errorf("entropy: no signer available (integrity module disabled?)")
	}
	head := entries[len(entries)-1]
	sig := HeadSig{
		FromSeq:  entries[0].Seq,
		ToSeq:    head.Seq,
		TS:       time.Now().UTC(),
		HeadHash: head.Hash,
	}
	signature := signer.SignBytes(canonicalHead(sig.FromSeq, sig.ToSeq, sig.TS, sig.HeadHash))
	if signature == "" {
		return HeadSig{}, fmt.Errorf("entropy: signer returned an empty signature")
	}
	sig.Sig = signature
	return sig, nil
}

// VerifyChain checks link continuity, then the signed head. It reports the
// first broken link position.
func VerifyChain(entries []ChainEntry, sig *HeadSig, signer *integrity.Signer) error {
	prev := ""
	for i, e := range entries {
		if e.PrevHash != prev {
			return fmt.Errorf("entropy: chain broken at entry index %d (seq %d): prev_hash mismatch", i, e.Seq)
		}
		if e.Hash == "" {
			return fmt.Errorf("entropy: chain entry %d (seq %d) has empty hash", i, e.Seq)
		}
		prev = e.Hash
	}
	if signer == nil {
		return fmt.Errorf("entropy: cannot verify chain head: no signer available")
	}
	if sig == nil {
		return fmt.Errorf("entropy: chain head signature missing")
	}
	if len(entries) > 0 && sig.ToSeq != entries[len(entries)-1].Seq {
		return fmt.Errorf("entropy: chain truncated/rotated after signing: head seq %d, last entry seq %d", sig.ToSeq, entries[len(entries)-1].Seq)
	}
	expected := canonicalHead(sig.FromSeq, sig.ToSeq, sig.TS, sig.HeadHash)
	if !signer.VerifyBytes(expected, sig.Sig) {
		return fmt.Errorf("entropy: chain head signature invalid")
	}
	return nil
}

// WriteHead persists the signed head atomically.
func WriteHead(path string, sig HeadSig) error {
	payload, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return fmt.Errorf("entropy: marshal head: %w", err)
	}
	return WriteFileAtomic(path, payload, fileMode)
}

// ReadHead loads the signed head; a missing file returns (nil, nil).
func ReadHead(path string) (*HeadSig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("entropy: read head: %w", err)
	}
	var sig HeadSig
	if err := json.Unmarshal(data, &sig); err != nil {
		return nil, fmt.Errorf("entropy: unmarshal head: %w", err)
	}
	return &sig, nil
}

// ReadHeadMissing is a tiny helper used by tests to assert "absent head is not
// an error"; it returns nil only when the file does not exist.
func ReadHeadMissing(path string) error {
	sig, err := ReadHead(path)
	if err != nil {
		return err
	}
	if sig != nil {
		return fmt.Errorf("entropy: expected head to be absent at %s", path)
	}
	return nil
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags entropy,integrity ./internal/entropy/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(entropy): 逐帧哈希链与链头签名 — 篡改/重排/截断检知`。

---

### Task 9: 审计链与降级策略（audit.go）

**Files:**
- Create: `internal/entropy/audit.go`
- Test: `internal/entropy/audit_test.go`

**Interfaces:**
- Consumes: Task 6 `WriteFileAtomic`、`KeySet`；`securemode.Encrypt/Decrypt`。
- Produces:
  - `type AuditEvent struct { Seq uint64; TS time.Time; Type string; Actor string; Object string; Result string; Details map[string]string; PrevHash string }`
  - 事件类型常量：`EvBaselineSnapshot`、`EvBaselineReset`、`EvKeyInit`、`EvFrameGap`、`EvClockSkew`、`EvChainHeadSigned`、`EvRetentionRoll`、`EvIntegrityCheck`、`EvExport`、`EvAccessDenied`、`EvConfigChange`、`EvAuditDegraded`、`EvAuditRecovered`、`EvDataHeadAnchor`
  - `type Auditor struct { Dir string; Key string }`
  - `func OpenAuditor(dir, frameKey string) (*Auditor, error)`
  - `func (a *Auditor) Append(ev AuditEvent) error`
  - `func (a *Auditor) RequireOperable() error`
  - `func (a *Auditor) Degraded() bool`
  - `func (a *Auditor) CrossAnchor(dataHeadHash string) error`
  - `func (a *Auditor) Entries() ([]AuditEvent, error)`
  - `func AuditHash(prevHash string, ev AuditEvent) string`

- [ ] **Step 1: 写失败测试**

```go
//go:build entropy

package entropy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestAuditor(t *testing.T) *Auditor {
	t.Helper()
	dir := t.TempDir()
	ks, _, err := LoadOrCreateKeys(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKeys: %v", err)
	}
	a, err := OpenAuditor(dir, ks.FrameKey)
	if err != nil {
		t.Fatalf("OpenAuditor: %v", err)
	}
	return a
}

func TestAuditorAppendChainsEvents(t *testing.T) {
	a := newTestAuditor(t)
	for i, evType := range []string{EvKeyInit, EvBaselineSnapshot} {
		ev := AuditEvent{TS: time.Unix(1700000000+int64(i), 0).UTC(), Type: evType, Actor: "uid=0", Object: "baseline", Result: "ok"}
		if err := a.Append(ev); err != nil {
			t.Fatalf("Append %s: %v", evType, err)
		}
	}
	entries, err := a.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[0].Seq != 1 || entries[1].Seq != 2 {
		t.Errorf("seq assignment wrong: %+v", entries)
	}
	if entries[1].PrevHash != AuditHash(entries[0].PrevHash, entries[0]) {
		t.Errorf("prev_hash chain broken: %+v", entries[1])
	}
}

func TestAuditorDegradesOnWriteFailureAndBlocksOperations(t *testing.T) {
	a := newTestAuditor(t)
	if err := a.RequireOperable(); err != nil {
		t.Fatalf("fresh auditor must be operable: %v", err)
	}
	// Make the audit path unwritable by replacing it with a directory.
	auditPath := filepath.Join(a.Dir, auditSubdir)
	if err := os.RemoveAll(auditPath); err != nil {
		t.Fatalf("cleanup audit dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(auditPath, auditFile), 0o700); err != nil {
		t.Fatalf("block audit file: %v", err)
	}
	if err := a.Append(AuditEvent{TS: time.Now().UTC(), Type: EvBaselineSnapshot, Actor: "uid=0"}); err == nil {
		t.Fatal("Append onto a blocked path must fail")
	}
	if !a.Degraded() {
		t.Error("auditor must report degraded after a write failure")
	}
	if err := a.RequireOperable(); err == nil {
		t.Error("RequireOperable must fail while degraded (high-risk ops are refused)")
	}
}

func TestAuditorCrossAnchorRecordsDataHead(t *testing.T) {
	a := newTestAuditor(t)
	if err := a.CrossAnchor("data-head-hash"); err != nil {
		t.Fatalf("CrossAnchor: %v", err)
	}
	entries, _ := a.Entries()
	if len(entries) != 1 || entries[0].Type != EvDataHeadAnchor {
		t.Fatalf("cross anchor not recorded: %+v", entries)
	}
	if entries[0].Details["data_head_hash"] != "data-head-hash" {
		t.Errorf("anchor payload = %+v", entries[0].Details)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags entropy ./internal/entropy/ -run TestAuditor -v`
Expected: FAIL — `undefined: OpenAuditor`

- [ ] **Step 3: 实现**

```go
package entropy

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chins-xing/asscor/internal/securemode"
)

const (
	auditSubdir = "audit"
	auditFile   = "audit.jsonl"
)

// Audit event types (spec §7.1).
const (
	EvBaselineSnapshot = "baseline.snapshot"
	EvBaselineReset    = "baseline.reset"
	EvKeyInit          = "key.init"
	EvFrameGap         = "frame.gap"
	EvClockSkew        = "clock.skew"
	EvChainHeadSigned  = "chain.head.signed"
	EvRetentionRoll    = "retention.roll"
	EvIntegrityCheck   = "integrity.check"
	EvExport           = "export"
	EvAccessDenied     = "access.denied"
	EvConfigChange     = "config.change"
	EvAuditDegraded    = "audit.degraded"
	EvAuditRecovered   = "audit.recovered"
	EvDataHeadAnchor   = "chain.data_head.anchor"
)

// AuditEvent is one append-only audit record (spec §7.2).
type AuditEvent struct {
	Seq      uint64            `json:"seq"`
	TS       time.Time         `json:"ts"`
	Type     string            `json:"type"`
	Actor    string            `json:"actor"`
	Object   string            `json:"object"`
	Result   string            `json:"result"`
	Details  map[string]string `json:"details,omitempty"`
	PrevHash string            `json:"prev_hash"`
}

// Auditor appends encrypted audit events and tracks degradation.
type Auditor struct {
	Dir      string
	Key      string
	events   []AuditEvent
	degraded bool
}

// OpenAuditor prepares the audit area and replays existing events.
func OpenAuditor(dir, frameKey string) (*Auditor, error) {
	if err := EnsureDir(filepath.Join(dir, auditSubdir)); err != nil {
		return nil, err
	}
	a := &Auditor{Dir: dir, Key: frameKey}
	events, err := a.load()
	if err != nil {
		return nil, err
	}
	a.events = events
	return a, nil
}

func (a *Auditor) path() string {
	return filepath.Join(a.Dir, auditSubdir, auditFile)
}

// AuditHash chains audit events so removing one breaks the chain.
func AuditHash(prevHash string, ev AuditEvent) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte{0})
	h.Write([]byte(itoa(ev.Seq)))
	h.Write([]byte{0})
	h.Write([]byte(ev.TS.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte{0})
	h.Write([]byte(ev.Type))
	h.Write([]byte{0})
	h.Write([]byte(ev.Actor))
	return hex.EncodeToString(h.Sum(nil))
}

// Append writes one audit event. On failure the auditor latches into the
// degraded state: high-risk operations are then refused via RequireOperable,
// and the failure itself is reported to the caller.
func (a *Auditor) Append(ev AuditEvent) error {
	ev.Seq = uint64(len(a.events) + 1)
	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	}
	if n := len(a.events); n > 0 {
		ev.PrevHash = AuditHash(a.events[n-1].PrevHash, a.events[n-1])
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		a.degraded = true
		return fmt.Errorf("entropy: marshal audit event: %w", err)
	}
	ciphertext, err := securemode.Encrypt(payload, a.Key)
	if err != nil {
		a.degraded = true
		return fmt.Errorf("entropy: encrypt audit event: %w", err)
	}
	line := append([]byte(base64.StdEncoding.EncodeToString(ciphertext)), '\n')

	f, err := os.OpenFile(a.path(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		a.degraded = true
		return fmt.Errorf("entropy: open audit log: %w", err)
	}
	defer f.Close()
	if err := f.Chmod(fileMode); err != nil {
		a.degraded = true
		return fmt.Errorf("entropy: chmod audit log: %w", err)
	}
	if _, err := f.Write(line); err != nil {
		a.degraded = true
		return fmt.Errorf("entropy: write audit event: %w", err)
	}
	if err := f.Sync(); err != nil {
		a.degraded = true
		return fmt.Errorf("entropy: fsync audit event: %w", err)
	}
	a.events = append(a.events, ev)
	return nil
}

// RequireOperable is the gate every high-risk operation must pass: while the
// audit chain cannot be written, baseline set/reset, retention roll and export
// are all refused (spec §7.3).
func (a *Auditor) RequireOperable() error {
	if a == nil {
		return fmt.Errorf("entropy: auditor unavailable")
	}
	if a.degraded {
		return fmt.Errorf("entropy: audit chain degraded — refusing high-risk operation")
	}
	return nil
}

// Degraded reports whether audit writes are currently failing.
func (a *Auditor) Degraded() bool { return a != nil && a.degraded }

// CrossAnchor records the data chain head inside the audit chain, so neither
// chain can be trimmed without detection (spec §6.3).
func (a *Auditor) CrossAnchor(dataHeadHash string) error {
	return a.Append(AuditEvent{
		Type:    EvDataHeadAnchor,
		Actor:   "kernel",
		Object:  "chain",
		Result:  "ok",
		Details: map[string]string{"data_head_hash": dataHeadHash},
	})
}

func (a *Auditor) load() ([]AuditEvent, error) {
	f, err := os.Open(a.path())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("entropy: open audit log: %w", err)
	}
	defer f.Close()

	var events []AuditEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		ciphertext, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil {
			return nil, fmt.Errorf("entropy: decode audit event: %w", err)
		}
		payload, err := securemode.Decrypt(ciphertext, a.Key)
		if err != nil {
			return nil, fmt.Errorf("entropy: decrypt audit event: %w", err)
		}
		var ev AuditEvent
		if err := json.Unmarshal(payload, &ev); err != nil {
			return nil, fmt.Errorf("entropy: unmarshal audit event: %w", err)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("entropy: scan audit log: %w", err)
	}
	return events, nil
}

// Entries returns the replayed audit events.
func (a *Auditor) Entries() ([]AuditEvent, error) {
	out := make([]AuditEvent, len(a.events))
	copy(out, a.events)
	return out, nil
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags entropy ./internal/entropy/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(entropy): 审计链与降级策略 — 高危操作在审计失败时拒绝/交叉锚定`。

---

### Task 10: 基线打点与重置（baseline.go）

**Files:**
- Create: `internal/entropy/baseline.go`
- Test: `internal/entropy/baseline_test.go`

**Interfaces:**
- Consumes: Task 6 `WriteFileAtomic`/`EnsureDir`；Task 9 `Auditor`/`RequireOperable`/`EvBaselineSnapshot`/`EvBaselineReset`。
- Produces:
  - `type Baseline struct { TS time.Time; SnapshotHash string; PrevHash string; Dists map[Dim]map[Scale]Dist; Meta map[string]string }`
  - `type BaselineStore struct { Dir string; Key string; Auditor *Auditor }`
  - `func OpenBaselineStore(dir, frameKey string, auditor *Auditor) (*BaselineStore, error)`
  - `func (s *BaselineStore) Set(b Baseline, actor string) (Baseline, error)`
  - `func (s *BaselineStore) Reset(b Baseline, actor, reason string) (Baseline, error)`
  - `func (s *BaselineStore) Current() (*Baseline, error)`
  - `func (s *BaselineStore) History() ([]Baseline, error)`

- [ ] **Step 1: 写失败测试**

```go
//go:build entropy

package entropy

import (
	"encoding/json"
	"testing"
	"time"
)

func newTestBaselineStore(t *testing.T) *BaselineStore {
	t.Helper()
	dir := t.TempDir()
	ks, _, err := LoadOrCreateKeys(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKeys: %v", err)
	}
	aud, err := OpenAuditor(dir, ks.FrameKey)
	if err != nil {
		t.Fatalf("OpenAuditor: %v", err)
	}
	st, err := OpenBaselineStore(dir, ks.FrameKey, aud)
	if err != nil {
		t.Fatalf("OpenBaselineStore: %v", err)
	}
	return st
}

func sampleBaseline(ts time.Time) Baseline {
	return Baseline{
		TS: ts,
		Dists: map[Dim]map[Scale]Dist{
			DimBehavior: {ScaleShort: Normalize(map[string]float64{"a": 1, "b": 1})},
		},
		Meta: map[string]string{"source": "cli"},
	}
}

func TestBaselineSetThenCurrent(t *testing.T) {
	st := newTestBaselineStore(t)
	ts := time.Unix(1700000000, 0).UTC()
	saved, err := st.Set(sampleBaseline(ts), "uid=1000")
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if saved.SnapshotHash == "" {
		t.Error("SnapshotHash must be computed")
	}
	cur, err := st.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if cur == nil || cur.SnapshotHash != saved.SnapshotHash {
		t.Fatalf("current baseline mismatch: %+v", cur)
	}
}

func TestBaselineSetLinksPrevHash(t *testing.T) {
	st := newTestBaselineStore(t)
	first, err := st.Set(sampleBaseline(time.Unix(1700000000, 0).UTC()), "uid=1000")
	if err != nil {
		t.Fatalf("Set first: %v", err)
	}
	second, err := st.Set(sampleBaseline(time.Unix(1700003600, 0).UTC()), "uid=1000")
	if err != nil {
		t.Fatalf("Set second: %v", err)
	}
	if second.PrevHash != first.SnapshotHash {
		t.Errorf("PrevHash = %q, want %q", second.PrevHash, first.SnapshotHash)
	}
	hist, err := st.History()
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 2 {
		t.Errorf("history length = %d, want 2 (baselines are archived forever)", len(hist))
	}
}

func TestBaselineResetRequiresReason(t *testing.T) {
	st := newTestBaselineStore(t)
	if _, err := st.Set(sampleBaseline(time.Unix(1700000000, 0).UTC()), "uid=1000"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := st.Reset(sampleBaseline(time.Unix(1700003600, 0).UTC()), "uid=1000", ""); err == nil {
		t.Fatal("Reset without a reason must be refused")
	}
	cur, _ := st.Current()
	if cur.TS.Unix() != 1700000000 {
		t.Error("a refused reset must not change the current baseline")
	}
	if _, err := st.Reset(sampleBaseline(time.Unix(1700003600, 0).UTC()), "uid=1000", "post-deploy re-baseline"); err != nil {
		t.Fatalf("Reset with reason: %v", err)
	}
	cur2, _ := st.Current()
	if cur2.TS.Unix() != 1700003600 {
		t.Error("reset must install the new baseline")
	}
}

func TestBaselineWritesAuditEvents(t *testing.T) {
	st := newTestBaselineStore(t)
	if _, err := st.Set(sampleBaseline(time.Unix(1700000000, 0).UTC()), "uid=1000"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := st.Reset(sampleBaseline(time.Unix(1700003600, 0).UTC()), "uid=1000", "reason"); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	events, _ := st.Auditor.Entries()
	var sawSet, sawReset bool
	for _, e := range events {
		switch e.Type {
		case EvBaselineSnapshot:
			sawSet = true
		case EvBaselineReset:
			sawReset = true
			if e.Details["reason"] != "reason" {
				t.Errorf("reset audit lacks reason: %+v", e.Details)
			}
		}
	}
	if !sawSet || !sawReset {
		t.Errorf("audit events missing: set=%v reset=%v (%+v)", sawSet, sawReset, events)
	}
}

func TestBaselineRefusedWhileAuditDegraded(t *testing.T) {
	st := newTestBaselineStore(t)
	st.Auditor.degraded = true
	if _, err := st.Set(sampleBaseline(time.Unix(1700000000, 0).UTC()), "uid=1000"); err == nil {
		t.Fatal("Set must be refused while the audit chain is degraded")
	}
	if _, err := st.Reset(sampleBaseline(time.Unix(1700000000, 0).UTC()), "uid=1000", "r"); err == nil {
		t.Fatal("Reset must be refused while the audit chain is degraded")
	}
}

func TestBaselineSnapshotHashIsCanonical(t *testing.T) {
	b := sampleBaseline(time.Unix(1700000000, 0).UTC())
	h1, err := snapshotHash(b)
	if err != nil {
		t.Fatalf("snapshotHash: %v", err)
	}
	// Re-marshalling the same baseline must be stable.
	raw, _ := json.Marshal(b)
	var round Baseline
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	h2, err := snapshotHash(round)
	if err != nil {
		t.Fatalf("snapshotHash round trip: %v", err)
	}
	if h1 != h2 {
		t.Errorf("snapshot hash not stable: %q vs %q", h1, h2)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags entropy ./internal/entropy/ -run TestBaseline -v`
Expected: FAIL — `undefined: OpenBaselineStore`

- [ ] **Step 3: 实现**

```go
package entropy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/chins-xing/asscor/internal/securemode"
)

const (
	baselineSubdir  = "baseline"
	currentFile     = "current.json"
	historySubdir   = "history"
	baselineFileExt = ".json"
)

// Baseline is the frozen reference snapshot — simultaneously the zero point
// of every offset (spec §二.5, spec §六.1).
type Baseline struct {
	TS           time.Time              `json:"ts"`
	SnapshotHash string                 `json:"snapshot_hash"`
	PrevHash     string                 `json:"prev_hash"`
	Dists        map[Dim]map[Scale]Dist `json:"dists"`
	Meta         map[string]string      `json:"meta,omitempty"`
}

// BaselineStore persists the current baseline and archives every predecessor.
type BaselineStore struct {
	Dir     string
	Key     string
	Auditor *Auditor
}

// OpenBaselineStore prepares the baseline area.
func OpenBaselineStore(dir, frameKey string, auditor *Auditor) (*BaselineStore, error) {
	if err := EnsureDir(filepath.Join(dir, baselineSubdir, historySubdir)); err != nil {
		return nil, err
	}
	return &BaselineStore{Dir: dir, Key: frameKey, Auditor: auditor}, nil
}

func (s *BaselineStore) currentPath() string {
	return filepath.Join(s.Dir, baselineSubdir, currentFile)
}

// snapshotHash is the canonical hash of a baseline's CONTENT (excluding its
// own hash/prev fields), so the audit record can pin exactly what was frozen.
func snapshotHash(b Baseline) (string, error) {
	content := struct {
		TS    time.Time              `json:"ts"`
		Dists map[Dim]map[Scale]Dist `json:"dists"`
		Meta  map[string]string      `json:"meta,omitempty"`
	}{TS: b.TS.UTC(), Dists: b.Dists, Meta: b.Meta}
	raw, err := json.Marshal(content)
	if err != nil {
		return "", fmt.Errorf("entropy: marshal baseline content: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Set installs a baseline (first snapshot or an updated one) and audits it.
func (s *BaselineStore) Set(b Baseline, actor string) (Baseline, error) {
	return s.install(b, actor, "", EvBaselineSnapshot)
}

// Reset installs a baseline as a RESET: the reason is mandatory and the event
// is audited as baseline.reset, so a re-baseline is never silent (spec §9.2).
func (s *BaselineStore) Reset(b Baseline, actor, reason string) (Baseline, error) {
	if reason == "" {
		return Baseline{}, fmt.Errorf("entropy: reset refused: a reason is required")
	}
	return s.install(b, actor, reason, EvBaselineReset)
}

func (s *BaselineStore) install(b Baseline, actor, reason, evType string) (Baseline, error) {
	if s.Auditor != nil {
		if err := s.Auditor.RequireOperable(); err != nil {
			return Baseline{}, err
		}
	}
	if b.TS.IsZero() {
		b.TS = time.Now().UTC()
	}
	hash, err := snapshotHash(b)
	if err != nil {
		return Baseline{}, err
	}
	b.SnapshotHash = hash

	if prev, err := s.Current(); err == nil && prev != nil {
		b.PrevHash = prev.SnapshotHash
		if err := s.archive(*prev); err != nil {
			return Baseline{}, err
		}
	}
	if err := s.writeCurrent(b); err != nil {
		return Baseline{}, err
	}
	if s.Auditor != nil {
		details := map[string]string{"snapshot_hash": b.SnapshotHash, "prev_hash": b.PrevHash}
		if reason != "" {
			details["reason"] = reason
		}
		if err := s.Auditor.Append(AuditEvent{
			Type:    evType,
			Actor:   actor,
			Object:  "baseline",
			Result:  "ok",
			Details: details,
		}); err != nil {
			return Baseline{}, fmt.Errorf("entropy: baseline installed but audit failed: %w", err)
		}
	}
	return b, nil
}

func (s *BaselineStore) writeCurrent(b Baseline) error {
	payload, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("entropy: marshal baseline: %w", err)
	}
	ciphertext, err := securemode.Encrypt(payload, s.Key)
	if err != nil {
		return fmt.Errorf("entropy: encrypt baseline: %w", err)
	}
	return WriteFileAtomic(s.currentPath(), ciphertext, fileMode)
}

func (s *BaselineStore) archive(b Baseline) error {
	name := fmt.Sprintf("%d%s", b.TS.UTC().UnixNano(), baselineFileExt)
	path := filepath.Join(s.Dir, baselineSubdir, historySubdir, name)
	payload, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("entropy: marshal archived baseline: %w", err)
	}
	ciphertext, err := securemode.Encrypt(payload, s.Key)
	if err != nil {
		return fmt.Errorf("entropy: encrypt archived baseline: %w", err)
	}
	return WriteFileAtomic(path, ciphertext, fileMode)
}

// Current returns the installed baseline, or (nil, nil) when none exists.
func (s *BaselineStore) Current() (*Baseline, error) {
	ciphertext, err := os.ReadFile(s.currentPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("entropy: read baseline: %w", err)
	}
	payload, err := securemode.Decrypt(ciphertext, s.Key)
	if err != nil {
		return nil, fmt.Errorf("entropy: decrypt baseline: %w", err)
	}
	var b Baseline
	if err := json.Unmarshal(payload, &b); err != nil {
		return nil, fmt.Errorf("entropy: unmarshal baseline: %w", err)
	}
	return &b, nil
}

// History returns archived baselines, oldest first.
func (s *BaselineStore) History() ([]Baseline, error) {
	dir := filepath.Join(s.Dir, baselineSubdir, historySubdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("entropy: read baseline history: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == baselineFileExt {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	out := make([]Baseline, 0, len(names))
	for _, name := range names {
		ciphertext, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("entropy: read archived baseline %s: %w", name, err)
		}
		payload, err := securemode.Decrypt(ciphertext, s.Key)
		if err != nil {
			return nil, fmt.Errorf("entropy: decrypt archived baseline %s: %w", name, err)
		}
		var b Baseline
		if err := json.Unmarshal(payload, &b); err != nil {
			return nil, fmt.Errorf("entropy: unmarshal archived baseline %s: %w", name, err)
		}
		out = append(out, b)
	}
	return out, nil
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags entropy ./internal/entropy/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(entropy): 基线打点与重置 — 重置强制原因/历史永久归档/审计降级时拒绝`。

---

### Task 11: 全链校验（verify.go）

**Files:**
- Create: `internal/entropy/verify.go`
- Test: `internal/entropy/verify_test.go`

**Interfaces:**
- Consumes: Task 7 `FrameStore`、Task 8 `VerifyChain`/`ReadHead`/`WriteHead`、Task 9 `Auditor`、Task 1 `integrity.NewSigner`。
- Produces:
  - `type VerifyReport struct { Frames uint64; BrokenAt *uint64; HeadSigOK bool; AuditEvents uint64; AuditCrossOK bool; Err string }`
  - `func Verify(dir, frameKey, chainKeyPath string) (VerifyReport, error)`

- [ ] **Step 1: 写失败测试**

```go
//go:build entropy

package entropy

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/chins-xing/asscor/internal/integrity"
)

func seedSignedChain(t *testing.T, dir string) {
	t.Helper()
	ks, _, err := LoadOrCreateKeys(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKeys: %v", err)
	}
	st, err := OpenFrameStore(dir, ks.FrameKey, ks.ChainKeyPath, 1<<20)
	if err != nil {
		t.Fatalf("OpenFrameStore: %v", err)
	}
	for i := uint64(1); i <= 4; i++ {
		if _, err := st.Append(Frame{Seq: i, TS: time.Unix(1700000000+int64(i), 0).UTC(), HostID: "h1", Payload: []byte("p")}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	entries, _ := st.Entries()
	signer, err := integrity.NewSigner(ks.ChainKeyPath)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	sig, err := SignHead(entries, signer)
	if err != nil {
		t.Fatalf("SignHead: %v", err)
	}
	if err := WriteHead(filepath.Join(dir, chainSubdir, headFile), sig); err != nil {
		t.Fatalf("WriteHead: %v", err)
	}
	aud, err := OpenAuditor(dir, ks.FrameKey)
	if err != nil {
		t.Fatalf("OpenAuditor: %v", err)
	}
	if err := aud.CrossAnchor(sig.HeadHash); err != nil {
		t.Fatalf("CrossAnchor: %v", err)
	}
}

func TestVerifyReportsIntactChain(t *testing.T) {
	dir := t.TempDir()
	seedSignedChain(t, dir)
	ks, _, _ := LoadOrCreateKeys(dir)
	rep, err := Verify(dir, ks.FrameKey, ks.ChainKeyPath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Frames != 4 {
		t.Errorf("Frames = %d, want 4", rep.Frames)
	}
	if !rep.HeadSigOK {
		t.Errorf("HeadSigOK = false on an intact chain (%s)", rep.Err)
	}
	if !rep.AuditCrossOK {
		t.Errorf("AuditCrossOK = false on an intact chain (%s)", rep.Err)
	}
	if rep.BrokenAt != nil {
		t.Errorf("BrokenAt = %d, want nil", *rep.BrokenAt)
	}
}

func TestVerifyDetectsTamperedFrameFile(t *testing.T) {
	dir := t.TempDir()
	seedSignedChain(t, dir)
	ks, _, _ := LoadOrCreateKeys(dir)

	files, _ := filepath.Glob(filepath.Join(dir, framesSubdir, "*.log"))
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read frame log: %v", err)
	}
	var rec map[string]interface{}
	if err := json.Unmarshal(raw[:len(raw)-1], &rec); err != nil {
		t.Fatalf("parse first line: %v", err)
	}
	rec["ct"] = base64.StdEncoding.EncodeToString([]byte("forged-ciphertext-XXXXXXXXXXXX"))
	forged, _ := json.Marshal(rec)
	if err := os.WriteFile(files[0], append(forged, '\n'), 0o600); err != nil {
		t.Fatalf("write forged log: %v", err)
	}

	rep, err := Verify(dir, ks.FrameKey, ks.ChainKeyPath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.BrokenAt == nil {
		t.Error("tampering with a frame must be detected")
	}
	if rep.Frames < 1 && rep.BrokenAt == nil {
		t.Error("verify must report either frames or a break")
	}
}

func TestVerifyDetectsMissingHead(t *testing.T) {
	dir := t.TempDir()
	seedSignedChain(t, dir)
	if err := os.Remove(filepath.Join(dir, chainSubdir, headFile)); err != nil {
		t.Fatalf("remove head: %v", err)
	}
	ks, _, _ := LoadOrCreateKeys(dir)
	rep, err := Verify(dir, ks.FrameKey, ks.ChainKeyPath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.HeadSigOK {
		t.Error("a missing chain head must not report HeadSigOK")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags entropy,integrity ./internal/entropy/ -run TestVerify -v`
Expected: FAIL — `undefined: Verify`

- [ ] **Step 3: 实现**

```go
package entropy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chins-xing/asscor/internal/integrity"
	"github.com/chins-xing/asscor/internal/securemode"
)

// VerifyReport summarises a full-chain verification (spec §6.3, §9.2).
type VerifyReport struct {
	Frames      uint64 `json:"frames"`
	BrokenAt    *uint64 `json:"broken_at,omitempty"`
	HeadSigOK   bool   `json:"head_sig_ok"`
	AuditEvents uint64 `json:"audit_events"`
	AuditCrossOK bool  `json:"audit_cross_ok"`
	Err         string `json:"err,omitempty"`
}

// Verify re-derives every frame hash from the stored ciphertext, checks the
// hash chain against the signed head, and checks that the audit chain anchors
// the same head. A structural problem yields a report (not an error); an
// unrecoverable read/decrypt failure yields an error.
func Verify(dir, frameKey, chainKeyPath string) (VerifyReport, error) {
	var rep VerifyReport

	index, err := loadIndex(filepath.Join(dir, chainSubdir, indexFile), frameKey)
	if err != nil {
		return rep, err
	}

	files, _ := filepath.Glob(filepath.Join(dir, framesSubdir, "*.log"))
	entries := make([]ChainEntry, 0, 64)
	prev := ""
	var seq uint64
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return rep, fmt.Errorf("entropy: read frame log %s: %w", path, err)
		}
		for _, line := range splitLines(raw) {
			var rec struct {
				Seq uint64 `json:"seq"`
				TS  string `json:"ts"`
				CT  string `json:"ct"`
			}
			if err := json.Unmarshal(line, &rec); err != nil {
				return rep, fmt.Errorf("entropy: unmarshal frame in %s: %w", path, err)
			}
			ciphertext, err := base64.StdEncoding.DecodeString(rec.CT)
			if err != nil {
				return rep, fmt.Errorf("entropy: decode frame in %s: %w", path, err)
			}
			ts, err := time.Parse(time.RFC3339Nano, rec.TS)
			if err != nil {
				return rep, fmt.Errorf("entropy: parse frame ts in %s: %w", path, err)
			}
			hash := FrameHash(prev, rec.Seq, ts, ciphertext)
			entry := ChainEntry{Seq: rec.Seq, TS: ts, Hash: hash, PrevHash: prev}
			seq++
			if idxEntry, ok := index[rec.Seq]; !ok {
				if rep.BrokenAt == nil {
					broken := rec.Seq
					rep.BrokenAt = &broken
					rep.Err = fmt.Sprintf("frame %d has no matching chain index entry", rec.Seq)
				}
			} else if idxEntry.Hash != hash {
				if rep.BrokenAt == nil {
					broken := rec.Seq
					rep.BrokenAt = &broken
					rep.Err = fmt.Sprintf("frame %d content hash %s does not match chain index %s", rec.Seq, hash, idxEntry.Hash)
				}
			}
			entries = append(entries, entry)
			prev = hash
		}
	}
	rep.Frames = seq

	signer, err := integrity.NewSigner(chainKeyPath)
	if err != nil {
		rep.Err = fmt.Sprintf("signer unavailable: %v", err)
	} else {
		head, err := ReadHead(filepath.Join(dir, chainSubdir, headFile))
		if err != nil {
			return rep, err
		}
		if head == nil {
			rep.Err = "chain head missing"
		} else if err := VerifyChain(entries, head, signer); err != nil {
			rep.Err = err.Error()
		} else {
			rep.HeadSigOK = true
		}
	}

	aud, err := OpenAuditor(dir, frameKey)
	if err != nil {
		return rep, err
	}
	events, err := aud.Entries()
	if err != nil {
		return rep, err
	}
	rep.AuditEvents = uint64(len(events))
	if rep.HeadSigOK && len(entries) > 0 {
		for _, ev := range events {
			if ev.Type == EvDataHeadAnchor && ev.Details["data_head_hash"] == entries[len(entries)-1].Hash {
				rep.AuditCrossOK = true
			}
		}
	}
	// Record the verification outcome in the audit chain (spec §7.1). A failed
	// audit write does not invalidate the verification result itself; it is
	// surfaced in the report instead.
	result := "ok"
	if !rep.HeadSigOK || rep.BrokenAt != nil {
		result = "failed"
	}
	details := map[string]string{
		"frames":      itoa(rep.Frames),
		"head_sig_ok": boolStr(rep.HeadSigOK),
	}
	if rep.BrokenAt != nil {
		details["broken_at"] = itoa(*rep.BrokenAt)
	}
	if err := aud.Append(AuditEvent{Type: EvIntegrityCheck, Actor: "cli", Object: "chain", Result: result, Details: details}); err != nil {
		rep.Err = strings.TrimSpace(rep.Err + " (audit write failed: " + err.Error() + ")")
	}
	return rep, nil
}

// boolStr renders a bool into an audit detail without importing strconv.
func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// loadIndex reads the whole chain index once, keyed by sequence number, so
// verification stays linear instead of re-reading the file per frame.
func loadIndex(path, frameKey string) (map[uint64]ChainEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[uint64]ChainEntry{}, nil
		}
		return nil, fmt.Errorf("entropy: read chain index: %w", err)
	}
	out := make(map[uint64]ChainEntry, 64)
	for _, line := range splitLines(raw) {
		ciphertext, err := base64.StdEncoding.DecodeString(string(line))
		if err != nil {
			return nil, fmt.Errorf("entropy: decode chain index entry: %w", err)
		}
		payload, err := securemode.Decrypt(ciphertext, frameKey)
		if err != nil {
			return nil, fmt.Errorf("entropy: decrypt chain index entry: %w", err)
		}
		var e ChainEntry
		if err := json.Unmarshal(payload, &e); err != nil {
			return nil, fmt.Errorf("entropy: unmarshal chain index entry: %w", err)
		}
		out[e.Seq] = e
	}
	return out, nil
}

// splitLines returns the non-empty lines of raw without copying semantics
// surprises (blank and whitespace-only lines are skipped).
func splitLines(raw []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\n' {
			line := raw[start:i]
			if len(line) > 0 {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	if start < len(raw) {
		out = append(out, raw[start:])
	}
	return out
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags entropy,integrity ./internal/entropy/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(entropy): 全链校验 — 帧哈希重算/链头签名/审计交叉锚定校验`。

---

### Task 12: 离线导出包（export.go）

**Files:**
- Create: `internal/entropy/export.go`
- Test: `internal/entropy/export_test.go`

**Interfaces:**
- Consumes: Task 7 `FrameStore`；Task 8 `ReadHead`；Task 9 `Auditor`/`EvExport`；Task 11 `Verify`/`VerifyReport`。
- Produces:
  - `type ExportBundle struct { GeneratedAt time.Time; FromSeq, ToSeq uint64; Frames []ExportFrame }`
  - `type ExportFrame struct { Seq uint64; TS time.Time; Hash string }`
  - `type ExportManifest struct { GeneratedAt time.Time; FromSeq, ToSeq uint64; Frames int; ChainHead string; HeadSig string; ContentSHA256 string; Verify VerifyReport }`
  - `func Export(dir, frameKey, chainKeyPath, outPath string, fromSeq, toSeq uint64, actor string) (ExportManifest, error)`

导出包只含**帧哈希与链头签名信息**（不含解密后的原始载荷），因此交给第三方只能核验哈希链自洽与存在性，符合 D12（第一版 HMAC）。

- [ ] **Step 1: 写失败测试**

```go
//go:build entropy

package entropy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExportWritesBundleWithHeadAndVerifies(t *testing.T) {
	dir := t.TempDir()
	seedSignedChain(t, dir)
	ks, _, _ := LoadOrCreateKeys(dir)
	aud, err := OpenAuditor(dir, ks.FrameKey)
	if err != nil {
		t.Fatalf("OpenAuditor: %v", err)
	}
	outPath := filepath.Join(t.TempDir(), "export", "bundle.json")

	man, err := Export(dir, ks.FrameKey, ks.ChainKeyPath, outPath, 1, 4, "uid=1000")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if man.Frames != 4 || man.ChainHead == "" || man.HeadSig == "" {
		t.Fatalf("manifest incomplete: %+v", man)
	}
	if !man.Verify.HeadSigOK {
		t.Errorf("export verify must report HeadSigOK: %+v", man.Verify)
	}
	if man.ContentSHA256 == "" {
		t.Error("export must record the content hash")
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	var bundle ExportBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	if len(bundle.Frames) != 4 || bundle.Frames[0].Seq != 1 || bundle.Frames[3].Seq != 4 {
		t.Errorf("export frame range wrong: %+v", bundle.Frames)
	}
	if bundle.Frames[0].Hash == "" {
		t.Error("export frames must carry their chain hashes")
	}
	// The bundle is hash-only: no decrypted payload may be present.
	if bytesContains(raw, []byte("\"payload\"")) {
		t.Error("export bundle must not carry decrypted payloads")
	}

	events, _ := aud.Entries()
	var sawExport bool
	for _, ev := range events {
		if ev.Type == EvExport {
			sawExport = true
			if ev.Details["from_seq"] != "1" || ev.Details["to_seq"] != "4" {
				t.Errorf("export audit range wrong: %+v", ev.Details)
			}
		}
	}
	if !sawExport {
		t.Error("export must be audited (spec §7.1)")
	}
}

// bytesContains is a local helper so the test does not import bytes twice.
func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test -tags entropy,integrity ./internal/entropy/ -run TestExport -v`
Expected: FAIL — `undefined: Export`

- [ ] **Step 3: 实现**

```go
package entropy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
)

// ExportBundle is the offline, hash-only view of a frame range (spec §6.4):
// it carries chain hashes, never decrypted payloads.
type ExportBundle struct {
	GeneratedAt time.Time     `json:"generated_at"`
	FromSeq     uint64        `json:"from_seq"`
	ToSeq       uint64        `json:"to_seq"`
	Frames      []ExportFrame `json:"frames"`
}

// ExportFrame is one chain link as exported.
type ExportFrame struct {
	Seq  uint64    `json:"seq"`
	TS   time.Time `json:"ts"`
	Hash string    `json:"hash"`
}

// ExportManifest summarises an export and is returned to the caller.
type ExportManifest struct {
	GeneratedAt   time.Time    `json:"generated_at"`
	FromSeq       uint64       `json:"from_seq"`
	ToSeq         uint64       `json:"to_seq"`
	Frames        int          `json:"frames"`
	ChainHead     string       `json:"chain_head"`
	HeadSig       string       `json:"head_signature"`
	ContentSHA256 string       `json:"content_sha256"`
	Verify        VerifyReport `json:"verify"`
}

// Export writes an offline bundle for [fromSeq, toSeq] and audits the request.
// Exporting is a high-risk operation: it is refused while the audit chain is
// degraded (spec §7.3).
func Export(dir, frameKey, chainKeyPath, outPath string, fromSeq, toSeq uint64, actor string) (ExportManifest, error) {
	aud, err := OpenAuditor(dir, frameKey)
	if err != nil {
		return ExportManifest{}, err
	}
	if err := aud.RequireOperable(); err != nil {
		return ExportManifest{}, err
	}

	st, err := OpenFrameStore(dir, frameKey, chainKeyPath, 1<<20)
	if err != nil {
		return ExportManifest{}, err
	}
	defer st.Close()
	entries, err := st.Entries()
	if err != nil {
		return ExportManifest{}, err
	}

	bundle := ExportBundle{GeneratedAt: time.Now().UTC(), FromSeq: fromSeq, ToSeq: toSeq}
	for _, e := range entries {
		if e.Seq < fromSeq || e.Seq > toSeq {
			continue
		}
		bundle.Frames = append(bundle.Frames, ExportFrame{Seq: e.Seq, TS: e.TS, Hash: e.Hash})
	}
	if len(bundle.Frames) == 0 {
		return ExportManifest{}, fmt.Errorf("entropy: export refused: no frames in range [%d,%d]", fromSeq, toSeq)
	}

	head, err := ReadHead(filepath.Join(dir, chainSubdir, headFile))
	if err != nil {
		return ExportManifest{}, err
	}
	payload, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return ExportManifest{}, fmt.Errorf("entropy: marshal export bundle: %w", err)
	}
	sum := sha256.Sum256(payload)

	rep, err := Verify(dir, frameKey, chainKeyPath)
	if err != nil {
		return ExportManifest{}, err
	}
	man := ExportManifest{
		GeneratedAt:   bundle.GeneratedAt,
		FromSeq:       fromSeq,
		ToSeq:         toSeq,
		Frames:        len(bundle.Frames),
		ContentSHA256: hex.EncodeToString(sum[:]),
		Verify:        rep,
	}
	if head != nil {
		man.ChainHead = head.HeadHash
		man.HeadSig = head.Sig
	}
	if err := WriteFileAtomic(outPath, payload, fileMode); err != nil {
		return ExportManifest{}, err
	}
	if err := aud.Append(AuditEvent{
		Type:   EvExport,
		Actor:  actor,
		Object: "chain",
		Result: "ok",
		Details: map[string]string{
			"from_seq": itoa(fromSeq),
			"to_seq":   itoa(toSeq),
			"frames":   itoa(uint64(man.Frames)),
			"sha256":   man.ContentSHA256,
			"target":   outPath,
		},
	}); err != nil {
		return ExportManifest{}, fmt.Errorf("entropy: export written but audit failed: %w", err)
	}
	return man, nil
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test -tags entropy,integrity ./internal/entropy/ -v`
Expected: PASS

- [ ] **Step 5: 提交**

提交说明：`feat(entropy): 离线导出包 — 仅含链哈希与链头签名/导出操作入审计/审计降级时拒绝`。

---

## 里程碑 A 验收门禁

- [ ] `go test -tags entropy,integrity ./internal/entropy/... ./internal/integrity/...` 全绿
- [ ] `go build ./...`（无 tag）通过 —— 证明 `!integrity` stub 分支可编译
- [ ] `go vet ./internal/entropy/... ./internal/integrity/...`（带 tag 与不带 tag）通过
- [ ] LF 归一的 `gofmt -l` 对全部新增文件无输出
- [ ] 端到端冒烟（临时 main 或测试）：生成密钥域 → 追加 3 帧 → 打点 → 读读数（三尺度四量）→ `Verify` 报告 `HeadSigOK/AuditCrossOK` → 篡改一帧后 `Verify` 报破点 → 重置（带原因）后读数归零、`BaselineAge` 归零
- [ ] 非回归：本里程碑未触碰评分链（`go list -deps ./internal/entropy/...` 不含 engine/assessor/predictor）

## 里程碑 B（后续计划，本次不展开步骤）

1. **kernel SPI 契约**：`internal/kernel/entropy_interface.go`（只读评分/情报读取面 + 查询接口）。
2. **模块与装配**：`internal/entropy/module.go`（实现 kernel 模块生命周期）、`cmd/kernel/entropy_on.go`/`entropy_off.go`。
3. **配置**：`config.ini [entropy]` 段 + `internal/config` 解析与范围校验（保持纯解析）。
4. **agent 侧采集器**：四面采集（Linux `/proc` 实现 + stub）、隐私最小化哈希化、采集节拍。
5. **独立熵帧通道**：传输、接收、背压、`frame.gap` 记录、时钟回拨检测接线。
6. **kernel 侧汇聚与发布**：多 agent 汇聚、三维多尺度读数生成、阈值熵事件 hook。
7. **保留策略滚动（retention）**：spec §6.4 要求原始帧滚动保留（默认 30 天），但删除最旧帧会让哈希链失去起点——实现前需与作者确认**分段链语义**（每段独立链头、段头签名留存于审计链、校验以当前段起点为基准），本文档不擅自确定该设计。
8. **CLI 与分发**：`entropy status/show/history/export/verify` + `baseline set` / `reset` 高危入口（不含 CLI 结构重构，后者属方向④）、`optional/algorithms/packages/entropy-pack/` 清单、`MODULE_TAGS` 增 `entropy`、agent 构建 tags 增 `entropy`、`entropy→integrity` 半启用告警登记、依赖闭包断言测试。
