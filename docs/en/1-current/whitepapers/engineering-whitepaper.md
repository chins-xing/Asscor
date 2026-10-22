# SSAM 2.0 Engineering Implementation Whitepaper (ASSCOR Project)

**Version:** 2.0 | **ASSCOR version:** v0.2.3
**Date:** 2026-08-12
**Status:** Published
**Companion documents:** SSAM 2.0 Whitepaper (Volume I), MLPS check-item mapping manual (Volume II), Oversight Committee Charter (Volume III)

## Abstract

This document is the ASSCOR project engineering implementation specification for SSAM 2.0 (System Security Acceptability Model). It describes in detail the distributed assessment system's technology selection, architecture design, module breakdown, communication protocols, data models, security mechanisms, build & deployment, and extension strategy. The system uses a Go microkernel + Agent architecture, with self-developed JSONRPC and mTLS for high-performance, secure bidirectional communication. All designs follow the principles of low coupling, extensibility, and zero external dependencies (in the core), easing community contribution and cross-platform deployment.

### SSAM V2.0 Project Split

Since SSAM V2.0, the core scoring algorithm has been fully extracted from the ASSCOR framework into a pure functional library, [github.com/chins-xing/ssam](https://github.com/chins-xing/ssam) (located in `ssam-lib/`). ssam-lib is a pure Go library with zero external dependencies — no goroutines, no locks, no I/O, no RPC, no plugins. The ASSCOR platform delegates to ssam-lib through the thin adapter layer `internal/engine/ssam/`; the two sides collaborate loosely coupled through standardized interfaces:

```
ASSCOR Platform (plugin-based distributed platform)
    │
    ├── internal/engine/ssam/    (thin adapter layer: adapter.go + defaults.go)
    │       │
    │       └── delegates to → ssam-lib/  (github.com/chins-xing/ssam)
    │                        ├── ssam.go         — Engine core, hooks, validation
    │                        ├── types.go        — V1.x DTO (backward compatible)
    │                        ├── types_v2.go     — V2.0 three-layer model types
    │                        ├── formulas.go     — V1.x formulas (ssam_v1.2)
    │                        ├── formulas_v2.go  — SSAMV20Formula
    │                        ├── ir.go           — SSAM IR export
    │                        ├── ast.go          — Formula DSL / AST
    │                        └── formulas_ast.go — AST formula implementation
    │
    └── internal/kernel/  (plugin bus, gRPC, DI, SPC, ATT&CK...)
```

### Prism (SRD) Project Split

Prism is the engineering implementation of the SRD (Systemic Risk Dynamics) theory — a risk dynamics engine — extracted into the standalone Go module [github.com/chins-xing/prism](https://github.com/chins-xing/prism) (located in `prism-lib/`) with zero external dependencies. The ASSCOR platform delegates to it through the thin adapter layer `internal/engine/prism/` and the `internal/engine/srd/` data-flow pipeline:

```
ASSCOR Platform
    │
    ├── internal/engine/prism/  (thread-safe adapter layer: engine.go)
    │       │
    │       └── delegates to → prism-lib/  (github.com/chins-xing/prism)
    │                        ├── types.go      — data model (NodeState, PrismConfig, AssetRiskResult)
    │                        ├── config.go     — default parameters (DebtAlpha, PropCap, ScoreFloor...)
    │                        ├── core.go       — Core Layer deterministic numeric evaluation
    │                        ├── semantic.go   — Semantic Layer four-state fuzzy membership
    │                        ├── inference.go  — Inference Layer Markov-chain prediction
    │                        └── paths.go      — risk propagation path search
    │
    └── internal/engine/srd/   (SRD data-flow pipeline)
         ├── manager.go    — risk state manager
         ├── pipeline.go   — data processing pipeline
         ├── adapter.go    — external tool data adaptation
         ├── lynis.go      — Lynis audit data adapter
         ├── openscap.go   — OpenSCAP compliance data adapter
         ├── generic.go    — generic data adapter
         ├── atomicred.go  — Atomic Red Team attack simulation adapter
         └── atomicred_test.go — Atomic Red Team adapter tests
```

**Prism three-layer architecture:**

| Layer | File | Responsibility | Key Function | Key Output |
|:---|:---|:---|:---|:---|
| **Core Layer** | `core.go` | Deterministic numeric evaluation | `ComputeDynamicScore` | `PrismScore` (0–100) |
| **Semantic Layer** | `semantic.go` | Four-state fuzzy membership mapping | `ComputeStateMembership` | `[μ_Stable, μ_Degraded, μ_Untrusted, μ_Collapse]` |
| **Inference Layer** | `inference.go` | Markov-chain state prediction | `PredictFuture` | Future state distribution, trend (improving/stable/degrading/collapsing) |

ASSCOR is an acronym of Argus — the hundred-eyed giant of Greek mythology — all-seeing, vigilant, never closing its eyes. The name is itself the project's metaphor: continuously monitoring the security state of every host and missing no weakness. The eye is the project's soul element and its most central image.

## 1. Technology Selection

| Layer | Technology | Rationale |
|------|----------|----------|
| Programming language | Go 1.21+ | Static compilation, zero-dependency distribution, native concurrency, cross-platform support |
| Communication protocol | JSONRPC (self-developed compatible layer) + gRPC (native) | Dual protocol stack: JSONRPC has zero external dependencies; native gRPC supports high-performance scenarios; both support mTLS |
| Transport security | mTLS (mutual authentication) | Ensures identity authentication and encryption between kernel and Agent, preventing man-in-the-middle attacks |
| Configuration format | INI (custom parser) | Simple and human-readable; administrators can edit directly without special tools |
| Concurrency control | Goroutine + Channel + Semaphore | Go-native concurrency for parallel check execution; semaphores limit concurrency |
| Data storage | In-memory cache + JSONL persistence + SPC disk cache | Assessment results computed in real time, cached 5 minutes; SPC CVE cache loaded at startup/saved on exit; historical data rotated daily as JSONL |
| Frontend dashboard | TBD (suggested React/Vue + Go API gateway) | CLI output and JSON reports initially; Web UI offered as a community-contributed module |
| Containerization | Docker + Kubernetes (optional) | Kernel can be containerized; Agent is recommended to run directly on the host |

## 2. Overall Architecture

The system adopts a microkernel + Agent distributed architecture: the kernel acts as the central security brain, while Agents act as execution probes distributed on business hosts.

### 2.1 Kernel Node (single instance or multi-instance federation)

```
Kernel Node (single instance or multi-instance federation)
│
├── JSONRPC Server (self-developed compatible layer, listening on 0.0.0.0:50051)
│   ├── KernelService   (Agent registration, heartbeat)
│   └── AgentService    (pull snapshot, dispatch commands, log stream)
│
├── gRPC Server (native protocol, listening on 0.0.0.0:50052, optional)
│   ├── KernelService   (GetSnapshot, Register, Heartbeat)
│   └── AgentService    (ExecuteCommand, StreamLogs)
│
├── Internal components (communicate over the message bus)
│   ├── Assessment Engine (Assessor)
│   ├── Policy Manager
│   ├── Security Posture Calculator (SPC, with disk cache persistence)
│   ├── Threat Intelligence Manager (CTI Manager)
│   ├── Risk Dynamics Engine (Prism/SRD, three layers)
│   ├── Commander
│   ├── Log Collector
│   ├── Heartbeat Monitor
│   ├── Adapter Integration (periodically runs external adapters)
│   ├── Config Watcher (weight hot-reload + SIGHUP)
│   └── Concurrency Controller (semaphore + health check)
│
└── Data store
    ├── Host asset inventory (memory + JSONL persistence)
    ├── Assessment result cache (with TTL)
    ├── SPC CVE cache (memory + disk JSON, loaded at startup/saved on exit)
    └── Audit log (daily JSONL rotation, file permission 0600)
```

### 2.2 Agent (one per business host)

```
Agent (one per business host)
├── gRPC Client (mTLS connection to kernel)
├── State Collector (runs local checks)
├── Command Executor (invokes system commands/APIs)
└── File Monitor (optional)
```

## 3. Module Detailed Design

### 3.1 Kernel Modules

#### 3.1.1 Assessment Engine

- **Responsibilities:** Load checks, execute assessments concurrently, compute core-domain scores, apply edge factors, threat coefficients and SPC corrections, and produce the final SSAM score.
- **Key interface:** `Evaluate(hostID) -> AssessmentResult`
- **Concurrency model:** Goroutine pool with a maximum of 10 concurrent workers, governed by a channel-based semaphore.
- **Caching:** Results cached for 5 minutes, protected by a read/write lock.
- **Built-in SSAM 2.0 conflict detection:** During bootstrap, after all checks are loaded, the engine runs exclusivity conflict detection — it indexes checks by check ID and core-domain membership and scans for atomic checks assigned to more than one core domain. If a conflict is detected (e.g. SYN Cookie appearing in both the edge factors and the Resilience domain), the engine refuses to start and prints the conflict details (conflicting check IDs and the list of involved domains), forcing a fix before it will continue. This enforces the §2.1 exclusivity statement at the engineering level.

#### 3.1.2 Prism/SRD Risk Dynamics Engine

Prism is the engineering implementation of the SRD (Systemic Risk Dynamics) theory. It uses a three-layer architecture (Core → Semantic → Inference) and, via the pure functional core `prism-lib`, stands independent of the ASSCOR framework with zero external dependencies. ASSCOR integrates it through `internal/engine/prism/engine.go` (thread-safe wrapper) and `internal/engine/srd/` (data-flow pipeline).

```
┌──────────────────────────────────────────────────────┐
│                        Prism Engine                   │
├───────────────┬───────────────────┬──────────────────┤
│   Core Layer  │  Semantic Layer   │ Inference Layer  │
│  (determin.   │  (fuzzy semantic   │  (state inference│
│   evaluation) │   mapping)         │   prediction)    │
│               │                   │                  │
│  external risk│  trapezoidUp/     │  Markov chain 4×4 │
│  E(v)         │  trapezoidDown/   │  state transition│
│  propagation  │  triangular       │  matrix          │
│  risk R       │  → four-state     │  N-step prediction│
│  security debt│  membership       │  → trend judgment │
│  D            │  [μ_S, μ_D, μ_U,  │  collapsing       │
│  orthogonal   │   μ_C]            │  detection       │
│  score        │                   │                  │
│  PrismScore   │                   │                  │
│   (0-100)     │                   │                  │
└───────────────┴───────────────────┴──────────────────┘
```

**Layer details:**

- **Core Layer (`prism-lib/core.go`):** Computes external risk E(v) = (100−S_ssam)/100, propagation risk R_prop = √Σ spillover², and security debt D = |Δ|×(t/86400)^α, finally producing the orthogonalized dynamic score PrismScore = max(S_ssam×0.40, S_ssam×(1−min(0.25, R_prop))×(1−min(0.30, ΣD/1500))). CollapseModifier triggers only when failed checks ≥ 2.
- **Semantic Layer (`prism-lib/semantic.go`):** Uses trapezoidal/triangular membership functions to map PrismScore to a four-state membership vector. Thresholds are configurable via PrismConfig (defaults: Stable ≥ 80, Degraded ≥ 60, Untrusted ≥ 40, Collapse < 40); a state may belong to multiple states simultaneously.
- **Inference Layer (`prism-lib/inference.go`):** Based on an expert-prior 4×4 Markov transition matrix, supporting future-state prediction over 30 days (default) or a custom number of steps. Trend judgment gives priority to the collapse probability — if current > 0.3 and future > 0.3, or future − current > 0.1, it is judged collapsing; improving/degrading/stable are then evaluated in order.
- **Path search (`prism-lib/paths.go`):** DFS-based propagation path search, maximum depth 5, hop-decay γⁿ, paths sorted by descending risk contribution.

#### 3.1.3 Policy Manager

- **Responsibilities:** Read configured thresholds and generate automated actions from score ranges.
- **State machine:** OK (≥ threshold) → Warning (≥ threshold−10) → Critical (≥ threshold−30) → Isolated (< threshold−30)
- **Action mapping:** notify_admin, increase_assessment, block_ip, disable_service, isolate_host.
- **v1.5 fix:** The original implementation used nested switches, which caused threshold ranges to overlap (an outer branch set `HostIsolated` and an inner branch then overwrote it to `HostWarning`). It is now a single mutually exclusive switch evaluated from high to low scores, so each score hits exactly one state.

#### 3.1.4 Security Posture Calculator (SPC)

- **Responsibilities:** Pull vulnerability intelligence from NVD, EPSS and CISA KEV, correlate it against the local asset inventory, and output $P_{score}$, $P_{weight}$, $P_{action}$.
- **Data sources:** REST API or local mirror, refreshed periodically (1h).
- **Localization factors:** MatchType, ExposureLevel, ControlFactor.
- **SPC 1.3 stacking attenuation:** Multi-CVE penalty stacking uses the square root of the sum of squares ($\sqrt{\sum Penalty^2}$) instead of linear summation. This prevents large numbers of low-severity CVEs from prematurely bottoming $P_{score}$ out at 0.60, keeps the weight of high-impact CVEs more prominent, and preserves discrimination among high-risk scores. In the implementation, the Calculator engine accumulates the square of each Penalty while iterating over matched_cves and finally executes `math.Sqrt(sumOfSquares)` to obtain the stacked penalty.
- **Assessment method statement (known limitation):** SPC's matching logic is based on CPE string matching — it cross-references installed software package names/versions against the affected-product versions in the CVE database. It does **not** perform exploit verification, runtime reachability analysis, binary analysis, or verification of compensating mitigations. Matches may produce false positives (vulnerabilities mitigated by a WAF/virtual patch but with an un-updated version string) and false negatives (version string matches but a customized variant is in use). SPC is positioned as a "vulnerability intelligence aggregation and version-comparison engine", not an "exploit verifier"; there is currently no plan to add deep verification capability.
- **v1.5 fixes:**
  - **CVE matching logic:** The original implementation matched package names by CVE ID (e.g. `CVE-2023-1234`), which caused numeric substring false matches (e.g. the "2023" package); short package names (< 2 characters) were also prone to false matches. The CVE-ID matching path is now removed; only Description text matching is used, and package names shorter than 2 characters are filtered out.
  - **EPSS scaling:** The original EPSS factor used linear scaling (`EPSS*10`), which could not reflect order-of-magnitude differences in exploit probability. It now uses logarithmic scaling, `-log(1-EPSS)/5`, making penalties for high EPSS values more pronounced and the impact of low EPSS values gentler.

#### 3.1.5 Threat Intelligence Manager

- **Responsibilities:** Integrate intelligence sources such as OTX and MISP, and compute the global threat coefficient μ.
- **Interface:** `GetThreatCoefficient() -> float64`
- **v1.5 fix:** The original `ReportThreat` method only incremented the `activeThreats` counter without distinguishing threat severity. A `severityWeight` function now weights the computation by threat level (critical=4, high=3, medium=2, low=1), so the threat coefficient more accurately reflects the actual risk level.

#### 3.1.6 Commander

- **Responsibilities:** Translate the actions produced by the Policy Manager into commands executable by Agents, dispatch them via gRPC, and manage retries and timeouts.
- **Signing:** Commands signed with HMAC-SHA256; Agents verify the signature.
- **v1.5 fix:** The original HMAC signature covered only `cmdID` and `action` but not `params`, leaving parameters open to tampering. The `sign` method now appends all parameter values sorted by key, and the Agent-side verification logic was updated in step, ensuring command integrity.
- **HMAC key management:** Key metadata includes creation time, expiry time and a SHA-256 hash; automatic rotation every 90 days; key file permission `0600`; if an Agent starts without a configured HMAC key it emits a SECURITY ALERT and rejects all remote commands at runtime.

#### 3.1.7 Log Collector

- **Responsibilities:** Receive log streams pushed by Agents and write them to local or remote log storage.
- **Storage:** Append-only files, or forwarding to a SIEM.
- **v1.5 fixes:**
  - **Log injection protection:** A newline in the original `entry.Message` could inject forged log entries. A `sanitizeLogField` function now replaces `\n` and `\r` with spaces so that every log entry occupies exactly one line.
  - **Durability guarantee:** The original code did not call `Sync()` after writing, so a process crash could lose the most recent data. `m.writer.Sync()` is now called immediately after each successful write to guarantee the data is flushed to disk.

#### 3.1.8 Heartbeat Monitor

- **Responsibilities:** Track each Agent's last heartbeat time; a timeout (default 60s) triggers an offline alert.

### 3.2 Agent Modules

#### 3.2.1 State Collector

- **Responsibilities:** Execute the checks defined by ASSCOR and produce a list of CheckResults.
- **Check implementation:** Based on Go syscalls, file reads and command execution. Examples:
  - AS-001 detects unnecessary services: parses systemd or /etc/init.d
  - OT-001 file permissions: `os.Stat` to obtain the file mode
  - RS-005 SYN Cookie: reads /proc/sys/net/ipv4/tcp_syncookies
- **Extensibility:** Allows loading external Lua scripts or WebAssembly plugins (future).

#### 3.2.2 Command Executor

- **Responsibilities:** Receive kernel commands and map them to local operations (e.g. invoking iptables, systemctl, ufw).
- **Security restrictions:** A whitelisted command set; arbitrary shell scripts are forbidden.

#### 3.2.3 Secure Communication Agent

- **Responsibilities:** Manage the gRPC connection, mTLS certificates, heartbeat timer and log stream upload.
- **Certificate management:** Generates a CSR on first start; the kernel issues a certificate after administrator approval. Certificates are rotated automatically afterwards.
- **Heartbeat mechanism:** Uses `time.Timer` instead of `time.Ticker` so that long-running `runChecks()` cannot pile up heartbeats and trigger a cascade of spurious reconnect errors.
- **TCP reads:** Uses `bufio.Reader.ReadBytes('\n')` to read responses line by line, resolving JSON parse failures caused by TCP half-packets.

## 4. Communication Protocols and Interface Definitions

### 4.1 Protobuf Service Definitions

```protobuf
syntax = "proto3";
package ASSCOR;

service KernelService {
  rpc Register(RegisterRequest) returns (RegisterResponse);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
}

service AgentService {
  rpc GetSnapshot(SnapshotRequest) returns (SnapshotResponse);
  rpc ExecuteCommand(CommandRequest) returns (CommandResponse);
  rpc StreamLogs(stream LogEntry) returns (Ack);
}

message RegisterRequest {
  string host_id = 1;
  string hostname = 2;
  string version = 3;
}

message RegisterResponse {
  bool accepted = 1;
  string session_id = 2;
  string ca_certificate = 3; // Used by the Agent to verify the kernel
}

message HeartbeatRequest {
  string host_id = 1;
  string session_id = 2;
  AssessmentResult result = 3; // Embedded assessment result, reducing RPC count
}

message HeartbeatResponse {
  bool ok = 1;
  double threat_coefficient = 2;
  repeated Command pending_commands = 3;
  AssessmentResult assessment_result = 4; // Assessment result (returned only when check results are carried)
}

message AssessmentResult {
  double final_score = 1;
  bool acceptable = 2;
  map<string, double> domain_scores = 3;
  repeated CheckResult checks = 4;
  map<string, double> edge_factors = 5;   // Edge factor details
  double threat_coefficient = 6;           // Threat coefficient μ
  double spc_score = 7;                    // SPC posture correction factor P_score
}

message CheckResult {
  string check_id = 1;
  string domain = 2;
  bool passed = 3;
  double delta = 4;
  string detail = 5;
}

message Command {
  string command_id = 1;
  string command = 2;            // e.g. "block_ip"
  map<string, string> params = 3;
  string signature = 4;          // HMAC signature
}

message CommandResponse {
  string command_id = 1;
  bool success = 2;
  string output = 3;
}
```

### 4.2 Secure Communication Flow

1. The Agent starts up and generates a key pair and a CSR.
2. It calls Register; the kernel verifies that the host ID is whitelisted (or subject to administrator approval).
3. The kernel issues an Agent certificate and returns the CA certificate.
4. The Agent establishes an mTLS connection to the kernel; all subsequent RPCs run over this connection.
5. The Agent periodically (e.g. every 5s) sends a Heartbeat carrying its latest assessment snapshot. The kernel returns the list of pending commands.
6. The kernel dispatches commands via ExecuteCommand; the Agent executes them and returns the results.
7. The Agent may optionally push real-time logs via StreamLogs.

## 5. Data Models

### 5.1 Core Domain Scores

```go
type DomainScores struct {
    AttackSurface      float64 `json:"attack_surface"`
    BusinessContinuity float64 `json:"business_continuity"`
    OperationTrust     float64 `json:"operation_trust"`
    Resilience         float64 `json:"resilience"`
}
```

### 5.2 Check Item Definition

```go
type CheckItem struct {
    ID          string
    Domain      string
    Name        string
    Description string
    Delta       float64            // Bonus when passed, or penalty when failed (signed)
    CheckFunc   func() (bool, string) // Returns pass/fail and details
}
```

### 5.3 Configuration File Structure (config.ini)

```ini
[weights]
attack_surface = 35
business_continuity = 25
operation_trust = 25
resilience = 15

[acceptability]
threshold = 80.0

[edge_factors]
two_factor_failure = 0.85

[resilience]
aci_network_segmentation = -15
aci_laps_enabled = -10
aci_offline_backup = -20
aci_edr_running = -10
aci_remote_logging = -10
```

### 5.4 Data Persistence and Storage Architecture

The SSAM 2.0 data store (ASSCOR implementation) follows a **memory-first + lazy persistence** strategy. Its core idea is "zero external database dependencies": every persisted format is human-readable JSON Lines or INI text, so data can be rescued with a plain text editor in disaster-recovery scenarios.

#### 5.4.1 Layered Storage Architecture

```
┌──────────────────────────────────────────────────┐
│           Hot tier (L0 — memory)                  │
│  protected by sync.RWMutex                        │
│  ├── results map[hostID]*AssessmentResult        │
│  ├── agents  sync.Map[hostID]*AgentRecord        │
│  ├── cveCache []SPCCVEScore                       │
│  └── config  map[string]string                    │
│                                                   │
│  Policy: updated on every assessment; lock-free   │
│          reads; 5min TTL                          │
├──────────────────────────────────────────────────┤
│           Warm tier (L1 — local files)            │
│  ├── data/assessments.jsonl   (assessment result log)  │
│  ├── data/agents.jsonl        (Agent registration records)│
│  ├── data/audit.jsonl         (audit log, append-only)   │
│  └── data/commands.jsonl      (command dispatch records) │
│                                                   │
│  Policy: batched flush every 30s; append-only,    │
│          never modified; automatic daily rotation │
├──────────────────────────────────────────────────┤
│           Cold tier (L2 — JSONL analytics store)  │
│  └── HistoricalStore: on-demand JSONL scan → trends/risks│
│                                                   │
│  Policy: historical trend analysis, compliance    │
│          audit, cross-host correlation queries    │
└──────────────────────────────────────────────────┘
```

#### 5.4.2 Storage Medium Selection

| Tier | Medium | Format | Rationale |
|--------|------|------|----------|
| L0 hot data | Process memory | Native Go map/struct | Nanosecond reads; assessment computation must have zero I/O latency |
| L1 warm data | Local disk | JSONL (one JSON object per line) | Human-readable; line-by-line appends need no file locks; real-time monitoring via `tail -f` |
| L2 cold data | Local disk / NFS | JSONL (HistoricalStore) | On-demand JSONL scanning, pure Go, zero external dependencies; ComputeTrends/ComputeRiskLevels provide historical trend and risk analysis |
| Audit log | Local disk + remote syslog | Append-only text | Tamper-evidence requirements: cannot be deleted or modified |

**JSONL vs. other formats:**

| Feature | JSONL | SQLite | Binary (Protobuf) |
|------|-------|--------|-------------------|
| Human readability | ★★★ | ★★☆ (needs sqlite3 client) | ★☆☆ |
| Write performance | ★★★ (append writes) | ★★☆ (B-tree writes) | ★★★ |
| Query capability | ★☆☆ (streaming scan only) | ★★★ (full SQL) | ★☆☆ |
| Corruption recovery | ★★★ (line-by-line recovery) | ★★☆ (needs repair tools) | ★☆☆ |
| Cross-platform compatibility | ★★★ | ★★★ | ★★★ |
| Backup friendliness | ★★★ (plain file sync) | ★★☆ (needs consistent snapshots) | ★★★ |

#### 5.4.3 Persisted Entity Models

```go
// Persisted assessment result record
type AssessmentRecord struct {
    Timestamp   time.Time              `json:"timestamp"`
    HostID      string                 `json:"host_id"`
    FinalScore  float64                `json:"final_score"`
    Acceptable  bool                   `json:"acceptable"`
    DomainScores struct {
        AttackSurface      float64 `json:"attack_surface"`
        BusinessContinuity float64 `json:"business_continuity"`
        OperationTrust     float64 `json:"operation_trust"`
        Resilience         float64 `json:"resilience"`
    } `json:"domain_scores"`
    EdgeFactors struct {
        TwoFactorFailure     float64 `json:"two_factor_failure"`
    } `json:"edge_factors"`
    ThreatCoefficient float64 `json:"threat_coefficient"`
    CheckCount        int     `json:"check_count"`
    FailedCheckCount  int     `json:"failed_check_count"`
}

// Persisted Agent registration record
type AgentRegistrationRecord struct {
    Timestamp  time.Time `json:"timestamp"`
    HostID     string    `json:"host_id"`
    Hostname   string    `json:"hostname"`
    Version    string    `json:"version"`
    Event      string    `json:"event"` // "registered" | "heartbeat" | "timeout" | "deregistered"
}

// Audit log entry
type AuditEntry struct {
    Timestamp  time.Time              `json:"timestamp"`
    Actor      string                 `json:"actor"`      // "kernel" | agent_id
    Action     string                 `json:"action"`     // "register" | "assess" | "command" | "policy_trigger"
    Target     string                 `json:"target"`     // host_id
    Detail     map[string]interface{} `json:"detail"`
    Success    bool                   `json:"success"`
}

// Command dispatch record
type CommandRecord struct {
    Timestamp  time.Time         `json:"timestamp"`
    CommandID  string            `json:"command_id"`
    HostID     string            `json:"host_id"`
    Command    string            `json:"command"`
    Params     map[string]string `json:"params"`
    Status     string            `json:"status"` // "pending" | "sent" | "ack_success" | "ack_failed" | "timeout"
    Signature  string            `json:"signature"`
}
```

#### 5.4.4 Core Persistence Implementation

```go
type PersistenceManager struct {
    mu          sync.Mutex
    dataDir     string
    writers     map[string]*jsonlWriter
    flushTicker *time.Ticker
    done        chan struct{}
}

type jsonlWriter struct {
    mu      sync.Mutex
    file    *os.File
    path    string
    day     int  // Day of the current file, used for automatic rotation
}

func NewPersistenceManager(dataDir string) *PersistenceManager {
    pm := &PersistenceManager{
        dataDir:     dataDir,
        writers:     make(map[string]*jsonlWriter),
        flushTicker: time.NewTicker(30 * time.Second),
        done:        make(chan struct{}),
    }
    go pm.flushLoop()
    return pm
}

func (pm *PersistenceManager) Append(dataset string, record interface{}) error {
    writer, err := pm.getWriter(dataset)
    if err != nil {
        return fmt.Errorf("persist %s: %w", dataset, err)
    }

    data, err := json.Marshal(record)
    if err != nil {
        return fmt.Errorf("marshal: %w", err)
    }

    writer.mu.Lock()
    defer writer.mu.Unlock()

    // Automatically rotate the log file per day
    today := time.Now().YearDay()
    if writer.day != today && writer.day != 0 {
        writer.file.Close()
        writer.file = nil
    }

    if writer.file == nil {
        fname := fmt.Sprintf("%s-%s.jsonl", dataset, time.Now().Format("20060102"))
        f, err := os.OpenFile(filepath.Join(pm.dataDir, fname),
            os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            return err
        }
        writer.file = f
        writer.day = today
        writer.path = fname
    }

    _, err = writer.file.Write(append(data, '\n'))
    return err
}

func (pm *PersistenceManager) flushLoop() {
    for {
        select {
        case <-pm.flushTicker.C:
            pm.flushAll()
        case <-pm.done:
            pm.flushAll()
            return
        }
    }
}

func (pm *PersistenceManager) flushAll() {
    pm.mu.Lock()
    defer pm.mu.Unlock()
    for _, w := range pm.writers {
        w.mu.Lock()
        if w.file != nil {
            w.file.Sync()
        }
        w.mu.Unlock()
    }
}

func (pm *PersistenceManager) Close() {
    close(pm.done)
    pm.flushTicker.Stop()
    pm.flushAll()
    for _, w := range pm.writers {
        w.mu.Lock()
        if w.file != nil {
            w.file.Close()
        }
        w.mu.Unlock()
    }
}
```

#### 5.4.5 Data Backup Strategy

| Backup type | Frequency | Method | Retention |
|----------|------|------|----------|
| Online hot backup | Every 30s | `PersistenceManager.Sync()` | N/A (real-time) |
| Local snapshot | Hourly | `cp data/ data.snapshot/` (hard links) | Keep 24 |
| Daily archive | Daily 00:00 | Previous day's JSONL files packed as tar.gz | Keep 90 days |
| Remote sync | Daily 02:00 | rsync/rclone → off-site storage | Keep 180 days |

```bash
# Daily archive script example (crontab)
0 0 * * *  /opt/ASSCOR/scripts/archive.sh

# archive.sh
#!/bin/bash
YESTERDAY=$(date -d "yesterday" +%Y%m%d)
DATA_DIR="/opt/ASSCOR/data"
ARCHIVE_DIR="/opt/ASSCOR/archive"
mkdir -p "$ARCHIVE_DIR"
find "$DATA_DIR" -name "*${YESTERDAY}*.jsonl" | tar czf "$ARCHIVE_DIR/ASSCOR-${YESTERDAY}.tar.gz" -T -
find "$ARCHIVE_DIR" -name "*.tar.gz" -mtime +90 -delete
```

#### 5.4.6 Read/Write Performance Optimizations

**Write optimizations:**

| Technique | Parameter | Effect |
|------|------|------|
| Batched buffered writes | Flush in batches every 30s | Reduces disk I/O frequency and eliminates per-record sync overhead |
| Append-only mode | Never modify or delete existing data | No random I/O; sequential writes reach ~150MB/s on mechanical disks |
| Writer-level locks | One independent sync.Mutex per dataset | Assessment writes never block audit writes |
| Per-day file rotation | Single file ≤ that day's data volume | Avoids large-file fsync latency |

**Read optimizations:**

| Technique | Description |
|------|------|
| Direct L0 memory-cache hit | Zero-I/O reads of results; `sync.RWMutex` allows many readers, one writer |
| JSONL streaming parse | `bufio.Scanner` reads line by line; constant O(1) memory |
| Optional SQLite index | Composite index over host_id and timestamp columns |
| Per-day partitioned scans | When the time range is known, only the JSONL files for the relevant days are read |

**In-memory cache lifecycle:**

```
Assessment triggered
    │
    ▼
┌─────────────────────────┐
│ Cache hit?              │─── yes ──→ return directly (same host within ≤ 5min)
│ key = hostID            │
│ TTL = 5min              │
└──────────┬──────────────┘
           │ no / expired
           ▼
    ┌──────────────┐
    │ Run checks   │  ← Goroutine pool, max concurrency 10
    │ Compute score│
    │ Apply edge   │
    │ factors      │
    └──────┬───────┘
           ▼
    ┌──────────────┐
    │ Update L0    │  sync.RWMutex.Lock() → write map
    │ cache        │
    │ Append L1    │  asynchronous → does not block the response
    │ JSONL        │
    └──────┬───────┘
           ▼
        Return result
```

## 6. Concurrency Control Detailed Design

The SSAM 2.0 concurrency model (ASSCOR implementation) is built on Go's native concurrency primitives (Goroutine + Channel + the sync package), delivering safe, efficient, observable parallel task scheduling without introducing any third-party concurrency framework.

### 6.1 Concurrency Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     ASSCOR Concurrency Architecture      │
├─────────────────┬─────────────────┬─────────────────────┤
│  Goroutine pool │  Message         │  Data synchronization│
│  (compute-      │  dispatch layer  │  layer (shared-state │
│   intensive)    │  (event-driven)  │  protection)         │
├─────────────────┼─────────────────┼─────────────────────┤
│  Semaphore      │  EventBus async │  sync.RWMutex        │
│  Max concurrent:│  publish        │  sync.Map            │
│  10             │  non-blocking   │  atomic.Value        │
│  errgroup       │  goroutine      │  channel signaling   │
│  coordination   │  panic recover  │                      │
│  context timeout│  subscribers run│                      │
│  propagation    │  independently  │                      │
└─────────────────┴─────────────────┴─────────────────────┘
```

### 6.2 Concurrency Limit Strategy

#### 6.2.1 Assessment Concurrency Pool Design

Check execution is ASSCOR's most central compute-intensive task. Each check may incur I/O waits while running system commands, and unbounded goroutine spawning would exhaust system resources.

**Basis for concurrency figures:**

| Parameter | Value | Basis |
|------|-----|------|
| Max concurrent checks | 10 | Empirical: balances CPU utilization against I/O waits |
| Per-check timeout | 10s | `context.WithTimeout`, prevents a stuck command |
| Heartbeat interval | 5s (Agent → kernel) | Upper bound on assessment frequency |
| Assessment cache TTL | 5min | No re-assessment of the same host within 5 minutes |

**v1.5 fix — WorkerPool goroutine leak:** In the original implementation, the drain goroutine started after a task timeout was not added to the `WaitGroup`, so `Shutdown()` could not wait for all goroutines to exit. The drain goroutine now calls `p.wg.Add(1)` and `defer p.wg.Done()` and binds `p.ctx.Done()` as its exit signal, ensuring `Shutdown()` correctly waits for every goroutine to finish.

**Core Goroutine pool implementation:**

```go
type WorkerPool struct {
    semaphore chan struct{}
    ctx       context.Context
    cancel    context.CancelFunc
    wg        sync.WaitGroup
}

func NewWorkerPool(maxConcurrency int) *WorkerPool {
    ctx, cancel := context.WithCancel(context.Background())
    return &WorkerPool{
        semaphore: make(chan struct{}, maxConcurrency),
        ctx:       ctx,
        cancel:    cancel,
    }
}

func (p *WorkerPool) Submit(task func() error) {
    select {
    case p.semaphore <- struct{}{}:
        p.wg.Add(1)
        go func() {
            defer p.wg.Done()
            defer func() { <-p.semaphore }()
            if err := task(); err != nil {
                log.Printf("worker: task error: %v", err)
            }
        }()
    case <-p.ctx.Done():
        return
    }
}

func (p *WorkerPool) Wait() {
    p.wg.Wait()
}

func (p *WorkerPool) Shutdown() {
    p.cancel()
    p.Wait()
}

func (p *WorkerPool) ActiveWorkers() int {
    return len(p.semaphore)
}

func (p *WorkerPool) QueueDepth() int {
    return cap(p.semaphore) - len(p.semaphore)
}
```

#### 6.2.2 Concurrent Execution Flow

```
Check set [AS-001, AS-002, ..., OT-022]  (55 items total)
    │
    ▼
┌───────────────────────────────────┐
│ Filter by platform                │
│ → keep only checks applicable     │
│   to the current OS               │
└──────────────┬────────────────────┘
               │
               ▼
┌───────────────────────────────────┐
│ WorkerPool.Submit(task_i)         │
│ ┌─────┐ ┌─────┐      ┌─────┐     │
│ │ T?  │ │ T?  │ ...  │ T?  │     │  ← at most 10 in parallel
│ └──┬──┘ └──┬──┘      └──┬──┘     │
│    │       │            │         │
│    ▼       ▼            ▼         │
│  semaphore (capacity=10)          │
│    ├ slot free  → start goroutine │
│    │             immediately      │
│    └ no slot    → block until     │
│                   released        │
└──────────────┬────────────────────┘
               │
               ▼
┌───────────────────────────────────┐
│ Each task runs independently:      │
│  1. ctx, cancel := WithTimeout(10s)│
│  2. check.Check() → (bool, detail) │
│  3. cancel()                      │
│  4. result written to channel     │
└──────────────┬────────────────────┘
               │
               ▼
┌───────────────────────────────────┐
│ Collector reads results from the   │
│ channel; classifies passed/failed  │
│ aggregates by core domain          │
│ → computes DomainScore             │
└───────────────────────────────────┘
```

### 6.3 Race-Condition Handling Mechanisms

#### 6.3.1 Shared-State Protection Matrix

| Data structure | Concurrent access pattern | Protection | Race risk |
|----------|-------------|----------|----------|
| `results map[hostID]*AssessmentResult` | Many readers, one writer (assessment updates) | `sync.RWMutex` | Low — reads dominate |
| `agents map[hostID]*AgentRecord` | Many readers/writers (frequent heartbeat updates) | `sync.Map` | Medium — high-concurrency heartbeats |
| `cveCache []SPCCVEScore` | Periodic update + assessment reads | `sync.RWMutex` | Low — updated hourly |
| `pendingCmds map[hostID]map[cmdID]*Command` | One writer, many readers (Commander owns it) | `sync.Mutex` | Low — single goroutine writes |
| `config map[string]string` | Written at startup, read-only at runtime | Immutable after boot | None |
| `subscribe map[topic][]subscriber` | Many writers (registration) + many readers (runtime) | `sync.RWMutex` | Low — registration happens during startup |

#### 6.3.2 Lock-Ordering Strategy (deadlock avoidance)

```
Global lock acquisition order (violating this is a bug):
  1. Kernel.mu          (outermost)
  2. Module-level mu    (e.g. Assessor.mu, Policy.mu)
  3. Data-structure mu  (e.g. Container.mu, Bus.mu)
  4. File/network I/O   (innermost — never hold a lock while waiting on I/O)

Principles:
  • Never call external module methods while holding a lock
    (avoids implicit lock dependencies)
  • Never perform I/O while holding a lock (indeterminate timeouts)
  • RWMutex.RLock is reentrant; RWMutex.Lock is not
  • All ctx timeouts are set by the caller; never wait on ctx
    while holding a lock
```

#### 6.3.3 Resource-Leak Protection

```go
// Pattern every goroutine must follow:
func safeGoroutine(ctx context.Context, fn func() error) {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("goroutine panic recovered: %v\n%s", r, debug.Stack())
            metrics.Increment("goroutine.panics")
        }
    }()

    done := make(chan error, 1)
    go func() {
        done <- fn()
    }()

    select {
    case err := <-done:
        if err != nil {
            log.Printf("goroutine error: %v", err)
        }
    case <-ctx.Done():
        log.Printf("goroutine cancelled: %v", ctx.Err())
        // fn running in the goroutine must itself respond to ctx.Done()
    }
}
```

### 6.4 Thread-Safety Assurance Measures

#### 6.4.1 Concurrency-Safety Checklist

| Check | Mechanism | Verification method |
|--------|------|----------|
| Data races | `sync.RWMutex` / `sync.Map` / `atomic.Value` | `go test -race ./internal/kernel/...` |
| Deadlock prevention | Global lock-ordering convention | Static analysis + timeout watchdog |
| Goroutine leaks | `context.WithCancel` + `sync.WaitGroup` | `runtime.NumGoroutine()` monitoring |
| Channel blocking | All sends use select+default or context | Stress test: no goroutine pile-up over 1h |
| Memory leaks | TTL cache expiry cleanup | pprof heap profile |
| Panic propagation | EventBus recover + isolated goroutines | Inject a panic, verify other subscribers are unaffected |

#### 6.4.2 Concurrency-Safety Self-Check

```go
// Kernel runtime concurrency health check
func (k *Kernel) ConcurrencyHealthCheck() *ConcurrencyStatus {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)

    return &ConcurrencyStatus{
        GoroutineCount:    runtime.NumGoroutine(),
        HeapAllocMB:       m.Alloc / 1024 / 1024,
        WorkerPoolActive:  k.workerPool.ActiveWorkers(),
        WorkerPoolQueued:  k.workerPool.QueueDepth(),
        BusTopics:         k.bus.Topics(),
        AgentCount:        k.heartbeat.ListAgents(),
        Timestamp:         time.Now(),
    }
}

type ConcurrencyStatus struct {
    GoroutineCount    int       `json:"goroutine_count"`
    HeapAllocMB       uint64    `json:"heap_alloc_mb"`
    WorkerPoolActive  int       `json:"worker_pool_active"`
    WorkerPoolQueued  int       `json:"worker_pool_queued"`
    BusTopics         []string  `json:"bus_topics"`
    AgentCount        int       `json:"agent_count"`
    Timestamp         time.Time `json:"timestamp"`
}
```

#### 6.4.3 Concurrency Monitoring Metrics

| Metric | Alert threshold | Meaning |
|------|----------|------|
| `goroutine_count` | > 500 | Possible goroutine leak |
| `worker_pool_queued` | > capacity × 3 | Assessment tasks piling up |
| `heap_alloc_mb` | > 500 MB | Possible memory leak |
| `agent_heartbeat_miss_ratio` | > 0.3 | Too many Agents offline |
| `bus_subscriber_panics` | > 0 | A subscriber has a bug |
| `evaluation_timeout_count` | > 5/min | Checks running too slowly or stuck |

### 6.5 Heartbeat Batching and Asynchronous Pipeline

#### 6.5.1 Heartbeat Processing Pipeline

```
Agent heartbeat (every 5s)
    │
    ▼
┌───────────────┐
│ gRPC Handler   │  ← receives heartbeat, returns immediately (non-blocking)
│ async dispatch │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ buffered      │  ← capacity 256, prevents heartbeat bursts
│ channel       │    from exploding goroutines
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Heartbeat     │  ← single consumer goroutine, updates sync.Map;
│ Consumer      │    coalesces duplicate heartbeats from the same
│               │    host within 5s
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ EventBus      │  ← Publish("agent.heartbeat", hostID)
│ notify        │    Assessor subscribes → triggers assessment
│ subscribers   │
└───────────────┘
```

```go
type HeartbeatPipeline struct {
    inbound chan *apiv1.HeartbeatRequest
    dedup   map[string]time.Time
    mu      sync.Mutex
}

func NewHeartbeatPipeline() *HeartbeatPipeline {
    hp := &HeartbeatPipeline{
        inbound: make(chan *apiv1.HeartbeatRequest, 256),
        dedup:   make(map[string]time.Time),
    }
    go hp.consume()
    return hp
}

func (hp *HeartbeatPipeline) Submit(req *apiv1.HeartbeatRequest) {
    select {
    case hp.inbound <- req:
    default:
        metrics.Increment("heartbeat.dropped")
        log.Printf("heartbeat pipeline full, dropping request from %s", req.HostId)
    }
}

func (hp *HeartbeatPipeline) consume() {
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()

    var batch []*apiv1.HeartbeatRequest

    for {
        select {
        case req := <-hp.inbound:
            hp.mu.Lock()
            last, exists := hp.dedup[req.HostId]
            if exists && time.Since(last) < 2*time.Second {
                hp.mu.Unlock()
                continue // Coalesce duplicate heartbeats within 2s
            }
            hp.dedup[req.HostId] = time.Now()
            hp.mu.Unlock()
            batch = append(batch, req)

        case <-ticker.C:
            if len(batch) == 0 {
                continue
            }
            for _, req := range batch {
                processHeartbeat(req)
            }
            batch = batch[:0]

            // Clean up stale dedup records
            hp.mu.Lock()
            now := time.Now()
            for id, t := range hp.dedup {
                if now.Sub(t) > 10*time.Second {
                    delete(hp.dedup, id)
                }
            }
            hp.mu.Unlock()
        }
    }
}
```

### 6.6 Concurrency Rate-Limit Parameter Summary

| Parameter | Default | Configurable | Description |
|------|--------|--------|------|
| `worker_pool.max_concurrency` | 10 | Yes | Upper bound on concurrently running checks |
| `worker_pool.task_timeout` | 10s | Yes | Maximum execution time per check |
| `heartbeat.pipeline_buffer` | 256 | No | Heartbeat receive buffer size |
| `heartbeat.dedup_window` | 2s | No | Heartbeat dedup window |
| `heartbeat.batch_interval` | 1s | Yes | Heartbeat batch-processing interval |
| `persistence.flush_interval` | 30s | Yes | JSONL flush interval |
| `assessment.cache_ttl` | 5min | Yes | Assessment result cache validity |
| `spc.fetch_interval` | 1h | Yes | CVE data refresh interval |
| `cti.update_interval` | 15min | Yes | Threat coefficient μ update interval |
| `log.buffer_size` | 64KB | Yes | Log buffer size |

**v1.5 fix — RateLimiter duplicate close panic:** Calling the original `RateLimiter.Stop()` multiple times closed the `stopCleanup` channel repeatedly and panicked. A `stopped` boolean flag now guarantees `close(r.stopCleanup)` executes exactly once, preventing a runtime crash during resource teardown.

## 7. Security Implementation

- **mTLS certificates:** Uses Go's crypto/tls. The kernel loads the CA certificate and server private key; Agents load client certificates. Certificates can be generated by the built-in CA (based on crypto/x509).
- **Command signing:** The kernel signs command bodies with hmac.New and Agents verify the signature. If no HMAC key is configured, the Agent emits a SECURITY ALERT at startup and, at runtime, rejects all remote commands and records a security event. The signature covers `cmdID` + `action` + all `params` (sorted by key), preventing parameter tampering.
- **Agent privileges:** The Agent runs as a non-root user; sudo rules permit only the necessary network/service management commands. The command execution whitelist strictly limits executable paths, forbids generic shells such as `sh` and `cmd`, and performs metacharacter injection detection.
- **Command parameter validation:** Before execution, `RunCmdTimeout` checks whether any parameter contains shell metacharacters (`|;&\`$()<>{}\n\r`) and refuses execution immediately if it does, preventing command injection.
- **Environment variable injection protection:** Before injecting environment variables, the extended executor verifies that key names contain no `=` or newline characters and values contain no newlines, preventing environment-variable injection into the host process.
- **SessionID security:** The random suffix of the SessionID generated at Agent registration was increased from 4 bytes (32-bit entropy) to 16 bytes (128-bit entropy) to prevent session-ID guessing. `rand.Read` errors are no longer ignored — on failure a log entry is written and a deterministic fill is used as a fallback.
- **Command request validation:** The `ExecuteCommand` interface now validates that `CommandId` and `HostId` are non-empty, preventing forged command acknowledgments.
- **Kernel hardening:** The kernel runs ASSCOR self-assessment on itself; a score below 90 raises an alert. Listening ports are opened only to the Agent network segment.
- **File permissions:** Audit logs and assessment result files are tightened to 0600 (readable/writable by the running user only), preventing sensitive data leakage.
- **Extension execution security:** Before external tool adapters execute, symlinks are resolved to their final path, preventing whitelist bypass through symbolic links.
- **Log integrity:** Log fields pass through `sanitizeLogField` (newline filtering) before being written, preventing log injection; `Sync()` is called after writes to guarantee the data reaches disk.

## 8. Build and Deployment

### 8.1 Compilation

```bash
# Kernel (full feature set: all optional module build-tags)
go build -tags "heartbeat,commander,policy,cti,assessor,attck_ext,spc,collector,sourcemanager,persistence,srdwrapper,integrity,resilience,comms,checks,adapter,engine" \
    -o build/ASSCOR-kernel ./cmd/kernel/

# Kernel (zero-bloat minimal kernel: no tags, extension framework + lifecycle + core infrastructure only)
go build -o build/ASSCOR-kernel-min ./cmd/kernel/

# Standalone assessment tool (needs engine/checks/adapter/spc/attck_ext)
go build -tags "engine,checks,adapter,spc,attck_ext" -o build/ASSCOR ./cmd/asscor/

# Agent (needs the checks tag)
go build -tags "checks" -o build/ASSCOR-agent ./cmd/agent

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
    -tags "heartbeat,commander,policy,cti,assessor,attck_ext,spc,collector,sourcemanager,persistence,srdwrapper,integrity,resilience,comms,checks,adapter,engine" \
    -o build/ASSCOR-kernel-linux-amd64 ./cmd/kernel/
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags "checks" -o build/ASSCOR-agent-linux-amd64 ./cmd/agent/

# Cross-compile the Windows Agent
GOOS=windows GOARCH=amd64 go build -tags "checks" -o build/ASSCOR-agent.exe ./cmd/agent
```

All build artifacts are written to the `build/` directory. `scripts/build.sh` and `deploy/Makefile` carry a built-in `MODULE_TAGS` variable; `make -f deploy/Makefile build` or `./scripts/build.sh [version]` builds the three binaries in one step.

### 8.2 Running

```bash
# Kernel (reads config.ini by default)
./ASSCOR-kernel -config config.ini -listen :50051

# Agent
./ASSCOR-agent -kernel 192.168.1.100:50051 -host-id web-server-01
```

### 8.3 Containerization

```dockerfile
FROM golang:1.21 as builder
WORKDIR /app
COPY . .
RUN go build -o ASSCOR-kernel ./cmd/kernel

FROM debian:bookworm-slim
COPY --from=builder /app/ASSCOR-kernel /usr/local/bin/
COPY config.ini /etc/ASSCOR/
CMD ["/usr/local/bin/ASSCOR-kernel", "-config", "/etc/ASSCOR/config.ini"]
```

> **Note:** Containerizing the Agent is not recommended, since it needs access to the host's system state.

## 9. Extensibility Design

- **Custom checks:** Injected through configuration-file entries that run external scripts (the `command` field); Lua/WebAssembly sandboxing is planned for the future.
- **Attack-vector plugins (AVD):** New detection logic is registered in the attackvectors/ directory and the framework loads it automatically.
- **Multi-kernel federation:** The kernel exposes a gRPC service for an upper federation layer to call, exchanging cluster-level assessment results.
- **IDS integration:** An IDSConnector interface is defined; Suricata/Snort alert ingestion can be implemented against it.

## 10. Migration from the Existing Python DSC Modules

The existing Python modules (firewall_controller, service_controller, etc.) are migrated directly into Go check functions. For example:

```go
// checks/linux/firewall.go
func CheckFirewallStatus() (bool, string) {
    // Run iptables -L or check firewalld status
    // Return whether it is active, plus details
}
```

Thus the Python prototypes serve as an early reference implementation for the Agent, while the Go version is the official product.

## 11. Microkernel (μKernel) Architecture — Detailed Design

### 11.1 Architecture Layers

ASSCOR's μKernel uses a plugin-based microkernel architecture organized into four layers:

```
┌─────────────────────────────────────────────────────┐
│  Communication layer (gRPC/JSON RPC + mTLS)         │
│  KernelService: Register, Heartbeat                 │
│  AgentService:  GetSnapshot, ExecuteCommand, StreamLogs│
├─────────────────────────────────────────────────────┤
│  Service layer (Service Implementations)            │
│  KernelServiceImpl / AgentServiceImpl               │
│  protocol codec (JSON Codec) + request routing      │
├─────────────────────────────────────────────────────┤
│  Kernel layer (Plugin Kernel Core)                  │
│  ┌──────────┬──────────┬──────────┬───────────┐     │
│  │ Plugin   │ Lifecycle│ DI       │ Extension │     │
│  │ Registry │          │ Container│ Points    │     │
│  ├──────────┴──────────┴──────────┴───────────┤     │
│  │        Message bus (Event Bus — pub/sub)     │     │
│  └────────────────────────────────────────────┘     │
├─────────────────────────────────────────────────────┤
│  Module layer (Plugin Modules — optional via build-tag)│
│  Heartbeat│SPC│CTI│Assessor│Policy│Commander│Collector│
│  SourceManager│Persistence│SRDWrapper│ATT&CK(attck_ext)│
└─────────────────────────────────────────────────────┘
```

> **Microkernel extraction:** The module layer has been stripped out of the kernel's former "god package" (originally 72 files / 24.8k LOC) into independent packages. The kernel now keeps only the extension framework (DI/bus/extension points/plugin lifecycle), the lifecycle engine, interface contracts, the interceptor chain, and other core infrastructure (40 files). The 17 functional modules are compiled on demand via Go build tags: a default `go build ./cmd/kernel/` (no tags) compiles the **zero-bloat minimal kernel**, and building with the full tag set compiles the complete feature set. Each module implementation lives in `internal/<module>/` gated by `//go:build <tag>`; contract types stay in `internal/kernel/*_interface.go`/`*_types.go`, and wiring stubs live in `cmd/kernel/<tag>_on.go`/`<tag>_off.go` (`new<module>()` returns either the implementation or nil).

### 11.2 Core Components

#### 11.2.1 Plugin Interface — the Plugin Contract

Every kernel module must implement the `Plugin` interface, declaring its metadata, dependencies, and lifecycle callbacks:

```go
type Plugin interface {
    Info()         PluginInfo           // Name, version, description, author
    Dependencies() []PluginDependency   // Declared external interfaces required
    Init(ctx, kernel) error             // Init: register with the DI container, declare extension points
    Start(ctx) error                    // Start: subscribe to the message bus, launch background tasks
    Stop(ctx) error                     // Stop: graceful shutdown, release resources
    State()        PluginState          // Current state
}
```

**Plugin state machine:**

```
Unregistered → Registered → Initialized → Started → Running
                                                  ↓
                                            Stopping → Stopped
                                                  ↓
                                               Failed
```

**Enhancement interfaces:**
- `PriorityPlugin`: declares start/stop priority (smaller value starts earlier and stops later)
- `HealthCheckable`: provides runtime health checks
- `ConfigurablePlugin`: supports runtime configuration hot-update

#### 11.2.2 DI Container — Dependency Injection

A lightweight dependency injection container that decouples interfaces from implementations via type mapping:

```go
type Container struct {
    bindings map[reflect.Type]interface{}  // interface type → implementation instance
    aliases  map[string]reflect.Type       // named alias → interface type
}

// Core methods
func (c *Container) Bind(iface, impl interface{})
func (c *Container) Resolve(iface interface{}) (interface{}, bool)
func (c *Container) Inject(target interface{}) error  // struct tag: `inject:"name"`
```

**Injection styles:**
1. **Type injection:** `c.Bind((*AssessorInterface)(nil), assessorModule)`
2. **Named injection:** `c.BindNamed("config", (*Config)(nil), cfg)`
3. **Struct tag injection:** `type Foo struct { Assessor AssessorInterface \`inject:"assessor"\` }`

#### 11.2.3 Message Bus — Inter-Module Communication Protocol

An internal event bus based on the publish/subscribe pattern enabling loose coupling between modules:

```go
type Bus struct {
    subscribers map[string][]subscriber  // topic → subscriber list
}

// Core operations
func (b *Bus) Subscribe(topic, id string, handler MessageHandler)
func (b *Bus) Publish(ctx context.Context, msg Message)
func (b *Bus) PublishSync(ctx context.Context, msg Message) []error
```

**Publish modes:**

| Mode | Method | Semantics | Typical use |
|------|------|------|----------|
| Asynchronous | `Publish` | Non-blocking; each subscriber runs in its own goroutine | Low-priority notifications (e.g. `agent.heartbeat`, `config.reloaded`) |
| Synchronous | `PublishSync` | Blocking; calls all subscribers in order, returns an error list | Critical business messages (e.g. `assessor.result`, `policy.action`, `spc.updated`) |

**v1.5 fix:** Critical messages such as `assessor.result` and `policy.action` were originally published asynchronously with `Publish`, which could lose messages or reorder processing. They now use synchronous `PublishSync`, so processing only continues after every subscriber has finished, and publish errors are recorded.

**Predefined message topics:**

| Topic | Publisher | Publish mode | Description |
|------|--------|----------|------|
| `agent.registered` | Heartbeat | Async | Agent registration event |
| `agent.heartbeat` | Heartbeat | Async | Agent heartbeat (triggers assessment) |
| `agent.timeout` | Heartbeat | Async | Agent timeout alert |
| `assessor.result` | Assessor | **Sync** | Assessment completed |
| `assessor.self_check` | Assessor | Async | Kernel self-assessment result |
| `policy.action` | Policy | **Sync** | Automated response action |
| `spc.updated` | SPC | **Sync** | SPC posture correction updated |
| `cti.updated` | CTI | Async | Threat intelligence updated |
| `cti.threat_detected` | CTI | Async | Threat-detection alert |
| `command.enqueued` | Commander | Async | Command queued for execution |
| `command.result` | Commander | Async | Agent acknowledgment of command result |
| `config.reloaded` | ConfigWatcher | Async | Config hot-reload notification |
| `config.changed` | ConfigWatcher | Async | Config-file change detected |
| `adapter.findings` | AdapterIntegration | Async | Adapter findings injected into assessment |
| `source_manager.deployed` | SourceManager | Async | Deployment source deployment complete |

**Extension points (lifecycle hooks):**

| Extension point | Trigger | Arguments |
|--------|----------|------|
| `kernel.pre_init` | Before all plugins' Init | nil |
| `kernel.post_init` | After all plugins' Init | nil |
| `kernel.pre_start` | Before all plugins' Start | nil |
| `kernel.post_start` | After all plugins' Start | nil |
| `kernel.pre_stop` | Before the shutdown sequence begins | nil |
| `kernel.post_stop` | After all plugins' Stop | nil |
| `assessor.pre_evaluate` | Before an assessment starts | hostID |
| `assessor.post_evaluate` | After an assessment completes | AssessmentResult |
| `spc.pre_calculate` | Before SPC computation | hostID |
| `spc.post_calculate` | After SPC computation | SPCCorrection |

#### 11.2.4 Plugin Lifecycle Management

The kernel's `Bootstrap()` executes in priority order:

1. Sort by `PriorityPlugin.Priority()` (smaller values start first)
2. Iterate plugins, calling `ConfigurablePlugin.Configure()` when implemented
3. Resolve `Dependencies()` and inject dependencies from the DI container
4. Run the `kernel.pre_init` extension point
5. Iterate plugins, calling `Plugin.Init()`
6. Run the `kernel.post_init` extension point
7. Run the `kernel.pre_start` extension point
8. Iterate plugins, calling `Plugin.Start()`
9. Run the `kernel.post_start` extension point

Shutdown (`Shutdown()`) stops plugins in reverse order of descending priority.

### 11.3 Built-in Plugin Modules

| Plugin ID | Type | Priority | Responsibility | Build tag | Implementation package |
|---------|------|--------|------|-----------|--------|
| `config_watcher` | ConfigWatcherModule | 1 | Config watching, weight hot-reload, SIGHUP-triggered reload | Always compiled (kernel) | `internal/kernel/` |
| `concurrency` | ConcurrencyModule | 2 | Concurrency control, semaphore rate limiting, health checks | Always compiled (kernel) | `internal/kernel/` |
| `persistence` | PersistenceModule | 3 | JSONL persistence, daily rotation, batched flush, dashboard reports | `persistence` | `internal/persistence/` |
| `heartbeat` | HeartbeatModule | 5 | Agent heartbeat tracking, timeout detection (60s), dead-node cleanup | `heartbeat` | `internal/heartbeat/` |
| `cti` | CTIModule | 10 | Threat intelligence management, computes global threat coefficient μ | `cti` | `internal/cti/` |
| `spc` | SPCModule | 20 | Security posture computation, localized CVE impact assessment (NVD/EPSS/KEV/MISP/CNNVD/CNVD/OSCAL) | `spc` | `internal/spc/` |
| `attck` | ATTACKModule | 21 | ATT&CK V19 technique mapping, detection analysis, threat intelligence, adversary emulation, assessment engineering, APT attribution, threat hunting | `attck_ext` | `internal/attck/` |
| `scoring_engine` | ScoringEngineModule | 35 | Scoring engine adapter layer, injects the SSAM/Prism algorithm engines | `assessor` | `internal/assessor/` |
| `assessor` | AssessorModule | 40 | Assessment engine controller: runs checks, computes scores, SIEM push | `assessor` | `internal/assessor/` |
| `adapter_integration` | AdapterIntegrationModule | 45 | Adapter integration: periodically runs external adapters and publishes findings | Always compiled (kernel) | `internal/kernel/` |
| `policy` | PolicyModule | 50 | Policy management: threshold evaluation and state machine (OK/Warning/Critical/Isolated) | `policy` | `internal/policy/` |
| `source_manager` | SourceManagerModule | 55 | Deployment source management: config/script deployment and version control | `sourcemanager` | `internal/sourcemanager/` |
| `commander` | CommanderModule | 60 | Command dispatch, HMAC-SHA256 command signing | `commander` | `internal/commander/` |
| `log_collector` | LogCollectorModule | 70 | Agent log collection, append-only writes to local files | `collector` | `internal/collector/` |
| `cli` | CLIModule | 90 | Interactive CLI terminal + Unix-socket remote connection | Always compiled | `internal/cli/` |
| `srd_adapters` | SRDAdapterModule | 110 | SRD external-result adapter pipeline | `srdwrapper` | `internal/srdwrapper/` |
| `securemode` | SecureModeModule | — | Secure mode: default/run dual-mode config protection (AES-256-GCM envelope encryption + argon2id), CLI `mode`/`config-set` command family, kernel-managed agents with encrypted registry persistence; registered via the DI container (`BindNamed("securemode")`) and wired by `cmd/kernel/main.go` — not a standard Plugin-lifecycle module | `securemode` | `internal/securemode/` (off by default: no-tag builds omit it, behavior unchanged) |

**Full build command (all optional module build-tags):**

```bash
go build -tags "heartbeat,commander,policy,cti,assessor,attck_ext,spc,collector,sourcemanager,persistence,srdwrapper,integrity,resilience,comms,checks,adapter,engine,securemode" -o ASSCOR-kernel ./cmd/kernel/
```

The default `go build ./cmd/kernel/` (no tags) compiles the zero-bloat minimal kernel — the extension framework + lifecycle + core infrastructure only. `scripts/build.sh` and `deploy/Makefile` carry the synchronized `MODULE_TAGS`.

> **Dormant components brought into the extension system:** The communication service (`comms`), integrity (`integrity`), resilience (`resilience`), checks (`checks`), adapter (`adapter`) and assessment engine (`engine`) have all been extracted from always-compiled components into build-tag optional modules. `integrity`/`resilience` use a "stub-within-package" pattern (`//go:build <tag>` implementation + `//go:build !<tag>` empty implementation) so that always-compiled consumers (`adapter`/`comms`/`assessor`) still compile without the tags. `engine`'s contract types (`AssessorEngine`/`ATTACKProvider`/`SPCProvider`/`SPCLocalAsset`/`SPCCorrection`/`AssessmentPhase`/`AssessmentHook`/`HookRegistrar`) were moved up to `internal/kernel/engine_types.go`, with the implementation stripped out behind `//go:build engine`.

**Health-check interface:** The key plugins (SPC, Heartbeat, Assessor, Persistence, Concurrency) implement `HealthCheckable`, and `Kernel.HealthCheck()` queries the health of all plugins in one place.

### 11.4 Dual Protocol Stack: JSONRPC Compatibility Layer + Native gRPC

ASSCOR's μKernel implements a dual protocol stack, supporting a zero-external-dependency JSONRPC compatibility layer and a native gRPC protocol built on `google.golang.org/grpc`:

#### 11.4.1 JSONRPC Compatibility Layer (zero external dependencies)

```
api/v1/ASSCOR.pb.go
├── Message type definitions (RegisterRequest, HeartbeatRequest, ...)
│   └── one-to-one correspondence with the api/v1/ASSCOR.proto spec
├── ServiceRegistry (service registration and dispatch)
│   ├── Register(desc) — registers a service method
│   └── Dispatch(ctx, service, method, payload) — routes to a Handler
├── ServerCodec interface (protocol encoding/decoding)
│   └── JSONCodec implementation — JSON-based request/response serialization
└── MethodHandler — func(ctx, payload) -> (payload, error)
```

**Compatibility guarantees:**
- All message fields are fully consistent with the `.proto` definitions
- Serialization format is JSON (currently); migration to Protobuf binary format is possible in the future
- Service and method names match the gRPC convention: `"ASSCOR.v1.KernelService/Register"`

#### 11.4.2 Native gRPC Protocol (high-performance scenarios)

A native gRPC protocol layer implemented on `google.golang.org/grpc`, supporting Protobuf binary serialization and HTTP/2 multiplexing:

```
api/v1/grpc.go
├── Protobuf message definitions (PBSnapshotRequest, PBCommandRequest, PBLogEntry, ...)
├── gRPC service interfaces
│   ├── KernelServiceServer (GetSnapshot, Register, Heartbeat)
│   └── AgentServiceServer (ExecuteCommand, StreamLogs)
├── PB ↔ JSON conversion methods
│   └── reuses the existing KernelServiceImpl / AgentServiceImpl logic
└── streaming logs (AgentService.StreamLogs, client streaming)

internal/kernel/grpc_server.go
├── GRPCServer configuration (TLS/mTLS, Keepalive, MaxRecvSize)
├── Protocol conversion handlers
│   ├── grpcKernelHandler → KernelServiceImpl
│   └── grpcAgentHandler → AgentServiceImpl
└── graceful shutdown (GracefulStop)
```

**Configuration ([adapter] section of config.ini):**

| Config key | Default | Description |
|--------|--------|------|
| `grpc.enabled` | off | Enable the native gRPC protocol |
| `grpc.listen_addr` | :50052 | gRPC listen address |
| `grpc.tls_enabled` | off | Enable TLS/mTLS |
| `grpc.max_recv_size` | 4194304 | Maximum received message size (4MB) |
| `grpc.keepalive_min` | 30s | Minimum keepalive interval |

### 11.5 Weight Hot-Reload Mechanism

ConfigWatcherModule watches `config.ini` for changes and automatically triggers weight reloads:

- **Polling detection:** checks the file modification time every 30 seconds and re-parses the config when it changes
- **Signal trigger:** listens for SIGHUP and reloads immediately
- **Reload scope:** domain weights (AttackSurface/BusinessContinuity/OperationTrust/Resilience), thresholds, threat coefficient
- **Event publication:** publishes a `config.reloaded` event to the message bus after a successful reload
- **Atomicity:** the full configuration is parsed first, then the Assessor is updated, avoiding intermediate states

### 11.6 SPC Cache Persistence

The SPC module's CVE cache supports disk persistence to avoid a cold-start fetch after restarts:

- **Load at startup:** loads the cache from `{DataDir}/spc_cache.json` in `Start()`
- **Save on exit:** saves the cache to disk when `fetchLoop()` exits (kernel shutdown)
- **Atomic writes:** writes to a temporary file first, then replaces with `os.Rename`, preventing data corruption from interrupted writes
- **Cache format:** JSON serialization containing the CVE list, indexes, and last-update time

### 11.7 Adapter Integration Module

AdapterIntegrationModule periodically runs 21 external adapters (11 probes + 10 management-type) and feeds their findings into the assessment pipeline through the four-stage Fetch → Parse → Map → Validate flow:

- **Periodic execution:** runs the adapter pipeline every 6 hours by default (`syncLoop()`)
- **Immediate execution:** runs an initial sync immediately at startup (avoids the first Ticker delay)
- **Concurrency control:** a semaphore caps the workers at 10, with a 120-second global timeout
- **Result conversion:** `NormalizedFinding.ToCheckResult()` maps adapter findings to CheckResults
- **Event publication:** adapter findings are published to the message bus via the `adapter.findings` event
- **Score injection:** the Assessor runs `runAdapterPipeline()` inside `AssessFromResults()` / `Assess()` and merges the results into the assessment
- **Delegation deduplication:** `buildDelegatedSet()` skips built-in checks already covered by external adapters (13 delegation rules)
- **Plugin registration:** AdapterIntegrationModule registers as a Kernel Plugin (v1.4 fix), ensuring background sync, event publication, and on-demand fetching actually take effect

**The 21 adapters:**

| Category | P0 | P1 | P2 |
|------|:--:|:--:|:--:|
| Probes | Trivy, Nuclei | Lynis, OpenSCAP, Wazuh Agent, Suricata, Falco, ClamAV | OSV-Scanner, AIDE, Nikto |
| Management | Ansible, NetBox | FreeIPA, Keycloak, Wazuh SIEM, Rundeck | Jira, Terraform, OpenTofu, Snipe-IT |

### 11.8 CLI Agent Management Module

New in v1.5, the CLI Agent management module provides full-lifecycle management of Agents from the command line:

#### 11.8.1 Command Set

| Command | Function | Required permission |
|------|------|----------|
| `agent start --host <hostID>` | Start the given Agent | PermWrite |
| `agent stop --host <hostID>` | Stop the given Agent | PermWrite |
| `agent restart --host <hostID>` | Restart the given Agent | PermWrite |
| `agent status [--host <hostID>]` | Query Agent status | PermRead |
| `agent logs --host <hostID> [--level <lvl>] [--format json\|csv]` | View/export Agent logs | PermRead |
| `agent config --host <hostID> --set <key>=<value>` | Modify Agent configuration parameters | PermAdmin |

#### 11.8.2 Multi-Instance Management

- **Single-instance operations:** `--host <hostID>` targets one Agent
- **Batch operations:** `--all` runs the same command against every registered Agent
- **Filtered operations:** `--filter <expr>` filters the Agent list by tag/group

#### 11.8.3 Permission Control

A four-level permission model is introduced; the current user's permission is verified before a command runs:

| Permission level | Identifier | Allowed operations |
|----------|------|-----------|
| Read-only | `PermRead` | Query status, view logs |
| Read-write | `PermWrite` | Start/stop/restart Agents |
| Administrator | `PermAdmin` | Modify configuration, manage permissions |
| Superuser | `PermSuper` | All operations, including permission assignment |

#### 11.8.4 Formatted Output

All commands support two output formats:
- **Text table** (default): human-readable tabular output for terminals
- **JSON format** (`--json` flag): structured JSON for scripting and automation

#### 11.8.5 Command Registration Architecture

Agent command registration builds on the `Command` interface and a `Registry`, staying compatible with the existing CLI framework:

```go
type Command interface {
    Name() string
    Description() string
    RequiredPerm() PermissionLevel
    Execute(ctx context.Context, args []string) error
}
```

### 11.9 ConfigWatcher Safe Type Assertion

v1.5 fix: the original `ConfigWatcherModule` used a bare type assertion `p.(*AssessorModule)` when fetching the Assessor plugin reference; a mismatched plugin type would panic and crash the kernel. It now uses the safe form `am, ok2 := p.(*AssessorModule)`: on a type mismatch it logs a warning instead of panicking, keeping configuration hot-reload stable.

### 11.10 Version Compatibility Strategy

| Component | Version strategy | Description |
|------|----------|------|
| Plugin interface | Add optional methods; never remove existing ones | Backward compatible |
| Message topics | New topics do not break existing subscriptions | New topics must be documented |
| Extension points | Add only, never remove | Registered extension points remain valid forever |
| API message types | New fields use new numbers | Existing fields cannot be changed |
| Configuration keys | New keys ship with defaults | Missing config does not block startup |

### 11.11 mTLS Certificate Management

Built-in CA system based on Go's `crypto/x509`:

```
Checked automatically at startup in the certs/ directory:
  1. No CA certificate → generate a self-signed CA (RSA 4096, 10 years)
  2. No server certificate → issue a Server Cert from the CA (RSA 2048, 1 year)
  3. Agent registration → CSR submitted → CA issues an Agent Cert

mTLS constraints:
  - Minimum TLS 1.2
  - Cipher suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (preferred)
  - Client certificates must be issued by the kernel CA
  - Server certificates must be issued by the kernel CA
```

### 11.12 Build and Verification

```bash
# Windows
go build -o ASSCOR-kernel.exe ./cmd/kernel/

# Linux (cross-compiled)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ASSCOR-kernel-linux-amd64 ./cmd/kernel/

# Run (development mode, no mTLS)
./ASSCOR-kernel.exe -config config.ini -no-mtls

# Run (production mode, mTLS)
./ASSCOR-kernel.exe -config config.ini -listen :50051 -cert-dir certs

# Verify
curl -X POST http://localhost:50051/ -d '{"service":"ASSCOR.v1.KernelService","method":"Register","payload":{"host_id":"test-01","hostname":"test","version":"1.2"}}'
```

### 11.13 Security Analysis: The Case for a Zero-External-Dependency Architecture

ASSCOR's security (the SSAM 2.0 implementation project) is not materially weakened by "zero external dependencies + a self-developed gRPC layer"; in several key areas it is actually strengthened — but this also shifts the full weight of security responsibility onto the team's own engineering capability. Below is a systematic, dialectical analysis from the two dimensions of attack surface and defensive mechanisms.

#### 11.13.1 Areas Where Security Is Strengthened

**Eliminating the software-supply-chain attack surface (largest gain)**

Adopting the conventional `google.golang.org/grpc` and its transitive dependency chain means trusting every version of dozens of third-party packages (including `protobuf`, `x/net`, `x/sys`, and others) and their maintainers. Such libraries have suffered severe security flaws historically — e.g. CVE-2023-44487, the HTTP/2 rapid-reset attack. ASSCOR builds its entire communication layer in-house, shrinking the auditable code surface to Go standard-library calls written only by the development team, and cutting off this potential attack path completely. For a security product, not introducing uncontrolled external code into itself is itself a top-priority security requirement and significantly reduces supply-chain attack risk.

**Enforcing a minimal attack surface**

The self-developed "gRPC-compatible layer" is essentially a lightweight HTTP JSON dispatcher. It does not implement the full complexity of HTTP/2 frame handling, HPACK header compression, or stream multiplexing — precisely the areas where historical gRPC vulnerabilities concentrate. Under basic security-engineering principles, protocol-stack complexity correlates positively with the number of potentially exploitable defects; the simplified design directly shrinks the attack surface.

**A seamless security loop with the built-in CA**

The automatic mTLS issuance mechanism designed in §11.11 avoids the operational risks of manually managing OpenSSL commands and certificate files: key leakage, forgotten certificate expiry, and wrong permission configurations. All certificate generation, issuance and verification logic is performed by the kernel binary itself, forming a closed-loop, fully auditable certificate-lifecycle management system that strengthens key management security.

#### 11.13.2 Potential Risks Acknowledged and Mitigated by Design

**Self-developed code may introduce logic flaws**

Newly built components — the EventBus, DI container, JSON Codec — are "new wheels" that have not undergone long community battle-testing or security review, and may harbor latent defects such as race conditions, memory leaks, or serialization injection.

| Risk category | Mitigation | Whitepaper section |
|----------|----------|-----------|
| Concurrency resource exhaustion | Goroutine pool + semaphore limiting, preventing unbounded goroutine explosion | §6 concurrency and performance design |
| Chaotic component-init state | Strictly ordered, dependency-injected Bootstrap flow | §11.2.4 plugin lifecycle management |
| Panic propagation | EventBus recovers each subscriber's panic in isolation; BusMetrics tracks panic/error/message counts | [bus.go](file:///f:/ASSCOR/internal/kernel/bus.go) |

**Missing the security interceptors of the gRPC ecosystem**

The standard gRPC framework ships authentication, audit logging, traffic rate limiting, and circuit-breaking fallback interceptors out of the box. A self-developed communication layer requires the team to implement these security controls itself.

| Missing capability | Compensation | Whitepaper section |
|----------|----------|-----------|
| Transport authentication | Go standard-library mTLS (TLS 1.2+); security equivalent to standard gRPC transport guarantees | §11.11, §7 |
| Command tamper protection | Every kernel-dispatched command carries an HMAC-SHA256 signature; Agents execute only after verification | §4.1, §7 |
| Audit logs | LogCollector writes append-only; logs cannot be deleted; file permission 0600 | §3.1.7, [collector.go](file:///f:/ASSCOR/internal/collector/collector.go) |
| Agent permission sandbox | Runs as non-root; executes only audited system-administration commands via sudo whitelist | §7 |
| Traffic rate limiting | RateLimiter token-bucket interceptor; stale client buckets cleaned automatically (5-minute cycle, 30-minute expiry) | [ratelimit.go](file:///f:/ASSCOR/internal/kernel/ratelimit.go) |
| Circuit-breaking fallback | CircuitBreaker interceptor; window capped at 1000 entries to prevent unbounded memory growth | [circuitbreaker.go](file:///f:/ASSCOR/internal/kernel/circuitbreaker.go) |
| Audit interceptor | AuditLogInterceptor records client, service, method, latency and result for every request | [interceptor.go](file:///f:/ASSCOR/internal/kernel/interceptor.go) |

**JSON parsing may face injection-style attacks**

As a text protocol, JSON carries some parsing-security risk.

- **Mitigation:** Every message strictly matches the strongly typed structures defined by the `.proto` files. Go's `json.Unmarshal` parses JSON into fixed struct types — the process executes no dynamic scripts, fundamentally eliminating traditional JSON-injection attack risk. In addition, the architecture supports a smooth future migration to Protobuf binary format, further reducing the parser attack surface.

#### 11.13.3 Conclusion: The Security Balance Tips Toward "Controllability"

Choosing the "zero external dependencies + self-developed gRPC layer" technical path is essentially **staking the team's own code quality and security engineering capability against the unknown supply-chain risks inside community libraries**. For a product like ASSCOR — where the security assessment platform itself is the key attack surface — this decision is defensible:

- If the team has solid systems programming skills, concurrency-safety experience, and cryptographic best-practice knowledge, the system's **overall security improves markedly**, because the attack surface is known and minimal, and every security mechanism stays entirely under the team's control.
- If the team lacks experience in these areas, self-developed components may become new weak points that introduce undiscovered logic flaws.

The whitepaper's designs — mTLS transport encryption, command HMAC signing, least-privilege principles, concurrency-safety limits — already provide explicit defenses for the most critical risk points. Therefore, **provided the development team implements strictly to this whitepaper's specification and pairs it with comprehensive security auditing (static code analysis, dynamic penetration testing, fuzzing) and continuous-integration verification, ASSCOR's security will not be degraded by "zero external dependencies" — it will actually be strengthened by greater self-control and accountability.**

## 12. Project Structure and Directory Conventions

```
ASSCOR/
├── cmd/
│   ├── kernel/          # Kernel entry point (μKernel CLI)
│   │   └── main.go
│   ├── agent/           # Agent entry point
│   │   └── main.go
│   └── asscor/           # Standalone entry point
│       └── main.go
├── internal/
│   ├── kernel/          # Microkernel core (extension framework + lifecycle + interface contracts only, 40 files)
│   │   ├── kernel.go     # Kernel bootstrap, lifecycle orchestration, global health check
│   │   ├── plugin.go     # Plugin interface, state machine, priority/health-check/configurable interfaces
│   │   ├── di.go         # DI container (type binding, named aliases, struct-tag injection)
│   │   ├── bus.go        # Message bus (pub/sub, sync/async publish, BusMetrics observability)
│   │   ├── extensions.go # Extension-point registry (lifecycle hooks + custom extension points)
│   │   ├── platform_extensions.go # Centralized platform-level extension-point definitions (89)
│   │   ├── ctxkey.go     # Context keys
│   │   ├── lifecycle.go  # Lifecycle engine | locator.go — locator | blocker.go — blocker
│   │   ├── crypto.go     # CA certificate management, server/Agent certificate issuance, mTLS config
│   │   ├── workerpool.go # Concurrency control (semaphore + WorkerPoolMetrics + health check)
│   │   ├── ratelimit.go  # Interceptor: token-bucket rate limiting
│   │   ├── circuitbreaker.go # Interceptor: circuit breaker
│   │   ├── interceptor.go # Interceptor chain (rate limit + circuit breaker + audit)
│   │   ├── auditlog.go   # Audit log interceptor
│   │   ├── config_watcher.go # Config watcher plugin (weight hot-reload, SIGHUP)
│   │   ├── adapter_integration.go # Adapter integration plugin
│   │   ├── siem_push.go  # SIEM push | source_manager_service.go — source management service
│   │   └── *_interface.go / *_types.go # Per-module interface contracts and shared types
│   ├── assessor/        # Assessment engine plugin (//go:build assessor) — AssessorModule + ScoringEngineModule
│   ├── spc/             # SPC security posture computation plugin (//go:build spc, 10 files)
│   ├── policy/          # Policy management plugin (//go:build policy)
│   ├── cti/             # Threat intelligence plugin (//go:build cti)
│   ├── commander/       # Command dispatch plugin (//go:build commander)
│   ├── heartbeat/       # Heartbeat monitoring plugin (//go:build heartbeat)
│   ├── attck/           # ATT&CK V19 plugin (//go:build attck_ext, 12 files)
│   ├── collector/       # Log collection plugin (//go:build collector)
│   ├── sourcemanager/   # Source management plugin (//go:build sourcemanager)
│   ├── persistence/     # Persistence plugin (//go:build persistence)
│   ├── srdwrapper/      # SRD wrapper plugin (//go:build srdwrapper)
│   ├── integrity/       # Integrity protection plugin (//go:build integrity, HMAC signing + constant-time compare)
│   ├── resilience/      # Resilience plugin (//go:build resilience, circuit breaker + Guard + panic recovery)
│   ├── comms/           # Communication service plugin (//go:build comms, server/services/grpc_server)
│   ├── checks/          # Check library (//go:build checks, linux/ 80 checks)
│   ├── adapter/         # Adapter interfaces + delegation rules (//go:build adapter, 21 adapters; framework always compiled)
│   ├── adapterhub/      # AdapterHub manager layer (//go:build adapter, rule engine + sync/health loops)
│   ├── engine/          # Assessment engine core (//go:build engine) + engine adapters (ssam/prism/srd)
│   ├── historicalstore/ # Historical store (pure utility package, always compiled)
│   ├── topology/        # Topology registry (pure utility package, always compiled)
│   ├── oscal/           # OSCAL export (pure utility package, always compiled)
│   ├── cli/             # CLI command module + install/uninstall/upgrade (internal/deploy merged in)
│   ├── agent/           # Agent implementation
│   │   └── agent.go      # Agent core (HMAC alerting, mTLS on by default, cross-platform paths)
│   ├── model/           # Domain models
│   ├── config/          # INI config parsing (API-key source auditing)
│   ├── extmgr/          # Extension manager (symlink-resolution protection)
│   ├── logger/          # Structured logging (slog wrapper)
│   ├── version/         # Version constants
│   └── common/          # Shared utilities (command-execution whitelist, metacharacter injection detection)
├── optional/               # External extension modules and packages (independent Go modules, enabled manually)
│   ├── pkgmgr/             # Extension package manager (dependency resolution, external repo references, version constraints)
│   ├── algorithms/         # Algorithm extensions → modules/ (single modules) + packages/ (multi-module packages)
│   ├── adapters/           # Adapter extensions
│   ├── checks/             # Check extensions
│   └── platform/           # Platform-layer extensions
├── api/
│   └── v1/
│       ├── ASSCOR.proto   # Protobuf spec (service + message definitions)
│       ├── ASSCOR.pb.go   # JSONRPC compatibility layer implementation (zero external dependencies)
│       └── grpc.go       # Native gRPC protocol implementation (Protobuf messages + service interfaces)
├── config.ini           # Kernel default config (weights/thresholds/check deltas/edge factors)
├── agent.ini            # Agent default config (heartbeat/reconnect/mTLS)
├── certs/               # mTLS certificate directory (auto-generated)
├── docs/                # Whitepapers and documentation
├── build/               # Build artifact output directory
├── go.mod
└── go.sum
```

## 13. ATT&CK V19 Threat Analysis Module

### 13.1 Module Positioning

The ATT&CK V19 module (`attck.New()`, plugin ID `attck`, priority 21, version 1.0.0, `//go:build attck_ext`) is the threat analysis core of the ASSCOR μKernel. Built on the MITRE ATT&CK V19 framework, it implements a complete threat analysis chain from detection, intelligence, and emulation through assessment. The module is injected into the assessment engine via the `engine.ATTACKProvider` interface and integrates deeply with the SSAM assessment engine, the SPC posture calculator, and the CTI threat intelligence manager.

### 13.2 Module File Architecture

```
internal/attck/                # ATT&CK V19 module (//go:build attck_ext)
├── attck.go                 # Module core: Plugin interface implementation, Init/Start/Stop lifecycle, attck.New()
├── attck_model.go           # Data model: 28 struct definitions (detection rules, alerts, IOCs, emulation scenarios, attack chains, behavioral indicators...)
├── attck_detection.go       # Detection & analysis submodule: rule engine, anomaly records, alert correlation, summary statistics
├── attck_ti.go              # Threat intelligence submodule: IOC management, threat-actor profiling, TTP tracking, alert enrichment
├── attck_emulation.go       # Adversary emulation submodule: scenario management, auto-generation, safe-mode execution
├── attck_assessment.go      # Assessment & engineering submodule: gap analysis, control mapping, mitigation suggestions, improvement tracking
├── attck_apt_chain.go       # APT enhancement: attack-chain reconstruction engine, multi-indicator correlation
├── attck_apt_detect.go      # APT enhancement: behavioral detection engine, baseline management, beacon detection
├── attck_apt_attribution.go # APT enhancement: APT attribution engine, multi-source evidence fusion
├── attck_apt_hunt.go        # APT enhancement: threat hunting framework, hypothesis management
└── attck_test.go            # Unit tests: 70+ test cases covering all submodules
```

> **Extraction note:** The ATT&CK module implementation has been moved out of `internal/kernel/` into `internal/attck/` (`//go:build attck_ext`) and is no longer compiled into the default kernel build. The module exposes the `kernel.ATTACKProvider` interface (contract defined in `internal/kernel/engine_types.go`, implementation behind `//go:build engine`) and is injected via `attck.New()` in `cmd/kernel/attck_ext_on.go`; `cmd/asscor`'s `attck_ext.go` follows the same build-tag gating.

### 13.3 Core Data Structures

The module defines 28 core structs, grouped by functional domain:

**Detection & analysis domain:**

| Struct | Purpose |
|--------|------|
| `DetectionRule` | Detection rule definition (ID, query expression, severity, ATT&CK mapping) |
| `DetectionAlert` | Detection alert (host, rule, raw log, acknowledgment state) |
| `AnomalyEvent` | Anomaly event (host, score, ATT&CK technique, metrics) |
| `CorrelationResult` | Alert correlation result (technique, alert list, correlation strength) |
| `DetectionSummary` | Detection summary statistics (alerts per severity, anomalies, rules) |

**Threat intelligence domain:**

| Struct | Purpose |
|--------|------|
| `IOCEntry` | IOC indicator (type, value, confidence, associated threat actor, expiry) |
| `ThreatActorProfile` | Threat-actor profile (ID, technique list, targeted industries, motivation, origin country) |
| `TTPTrack` | TTP tracking record (actor, technique, first/most recent observation time) |

**Adversary emulation domain:**

| Struct | Purpose |
|--------|------|
| `EmulationScenario` | Emulation scenario (technique steps, target hosts, safe-mode flag) |
| `EmulationStep` | Emulation step (technique ID, expected result, safe alternative) |
| `EmulationResult` | Emulation result (success/failure, execution time, observed behaviors) |

**Assessment & engineering domain:**

| Struct | Purpose |
|--------|------|
| `AssessmentReport` | Assessment report (coverage, gap list, mitigation suggestions) |
| `ControlMapping` | Security control mapping (technique → mitigation → implementation state) |
| `Mitigation` | Mitigation measure (ID, description, implementation complexity, priority) |
| `ImprovementTrack` | Improvement tracking (goal, action list, progress percentage) |

**APT enhancement domain:**

| Struct | Purpose |
|--------|------|
| `AttackChain` | Attack chain (stage list, severity, attribution result) |
| `AttackStage` | Attack stage (tactic/technique, evidence, confidence) |
| `AttributionResult` | Attribution result (primary actor, confidence, evidence chain, alternative actors) |
| `BehavioralIndicator` | Behavioral indicator (monitored metric, threshold, detection window, ATT&CK mapping) |
| `BehavioralBaseline` | Behavioral baseline (host metric baseline values, sample count, computation time) |
| `BehavioralAlert` | Behavioral alert (baseline value, actual value, deviation) |
| `BeaconDetection` | Beacon detection (interval, jitter, score, data-point count) |
| `HuntHypothesis` | Hunting hypothesis (target technique, data sources, queries, priority, status) |
| `HuntResult` | Hunt result (acknowledgment state, findings, confidence) |
| `MultiIndicatorCorrelation` | Multi-indicator correlation (alert/anomaly/IOC/beacon counts, aggregate severity) |

### 13.4 Interface Design

`ATTACKInterface` defines 50+ methods grouped by submodule:

```go
type ATTACKInterface interface {
    // Core capabilities (3)
    GetAllTactics() []ATTACKTactic
    GetTechniquesByTactic(tacticID string) []ATTACKTechnique
    CalculateCoverage(checkResults map[string]bool) []ATTACKCoverage

    // Detection & analysis (8)
    RegisterDetectionRule(rule DetectionRule) error
    EvaluateDetectionRule(ruleID, hostID, rawLog string, fields map[string]string) (*DetectionAlert, error)
    GetAlerts(hostID, severity string, limit int) []DetectionAlert
    AcknowledgeAlert(alertID string) bool
    RecordAnomaly(event AnomalyEvent)
    GetAnomalies(hostID string, minScore float64, limit int) []AnomalyEvent
    CorrelateAlerts(hostID string) []CorrelationResult
    GetDetectionSummary() DetectionSummary

    // Threat intelligence (9)
    AddIOC(entry IOCEntry) error
    GetIOCs(iocType string, techniqueID string, limit int) []IOCEntry
    SearchIOC(value string) []IOCEntry
    DeleteIOC(iocID string) bool
    ExpireIOCs() int
    UpsertThreatActor(profile ThreatActorProfile) error
    AddTTPTrack(track TTPTrack) error
    EnrichAlertWithTI(alertID string) (*DetectionAlert, map[string]interface{})
    GetTISummary() map[string]interface{}

    // Adversary emulation (5)
    CreateScenario(scenario EmulationScenario) error
    GenerateScenarioFromActor(actorID string) (*EmulationScenario, error)
    RunEmulation(scenarioID, hostID string, safeMode bool) (*EmulationResult, error)
    GetEmulationResults(scenarioID string, limit int) []EmulationResult
    DeleteScenario(scenarioID string) bool

    // Assessment & engineering (7)
    PerformGapAnalysis(hostID string) (*AssessmentReport, error)
    GetControlMapping(techniqueID string) *ControlMapping
    CreateImprovementTrack(track ImprovementTrack) error
    GetImprovementTrack(trackID string) *ImprovementTrack
    ListImprovementTracks() []ImprovementTrack
    UpdateImprovementAction(trackID, actionID string, status string) error
    CalculateImprovementProgress(trackID string) (float64, error)

    // APT enhancement (11)
    ReconstructAttackChain(hostIDs []string) (*AttackChain, error)
    GetAttackChains(hostID string, limit int) []AttackChain
    CorrelateMultiIndicator(hostIDs []string) []MultiIndicatorCorrelation
    RegisterBehavioralIndicator(indicator BehavioralIndicator) error
    EvaluateBehavioralIndicators(hostID string, metrics map[string]float64) []BehavioralAlert
    DetectBeaconing(hostID string, events []TimeSeriesPoint) []BeaconDetection
    PerformAttribution(chainID string) (*AttributionResult, error)
    GenerateAPTAnalysisReport(hostIDs []string) (*APTAnalysisReport, error)
    CreateHuntHypothesis(hypothesis HuntHypothesis) error
    ExecuteHunt(hypothesisID string, hostID string) (*HuntResult, error)
    AutoGenerateHypotheses(hostID string) ([]HuntHypothesis, error)
}
```

### 13.5 Extension-Point Registration (platform-centralized in v0.2.3)

Extension points are defined centrally by the ASSCOR platform layer (`kernel/platform_extensions.go: RegisterAllExtensionPoints()`), rather than in each module's `Init()` method. `KernelContext.Extensions()` returns the `ModuleExtensions` interface (which has no `RegisterPoint`), so the compiler forbids modules from defining extension points beyond their authority.

```go
// platform_extensions.go — single source of truth
func RegisterAllExtensionPoints(r *ExtensionRegistry) {
    r.RegisterPoint(ExtensionPoint{
        Name: "attck.coverage.complete", Description: "Called after coverage analysis completes", Version: "1.0",
    })
    r.RegisterPoint(ExtensionPoint{
        Name: "attck.apt.matched", Description: "Called when APT group match is detected", Version: "1.0",
    })
    // ... 76 extension points in total (6 kernel + 70 business modules)
}
```

Modules subscribe to existing extension points via `kc.Extensions().RegisterExtension()` and fire events via `kc.Extensions().Execute()`.

### 13.6 Integration Path with the SSAM Assessment System

```
┌──────────────────────────────────────────────────────────────┐
│                     ASSCOR μKernel                            │
│                                                              │
│  ┌─────────────┐    assessor.result    ┌──────────────────┐  │
│  │   Assessor   │──────────────────────→│  Policy Manager  │  │
│  │  (SSAM 2.0)  │                       │  (auto-response)  │  │
│  └──────┬───────┘                       └────────▲─────────┘  │
│         │                                       │            │
│         │ check_results                         │ event      │
│         ▼                                       │ triggers   │
│  ┌─────────────┐    attck.apt.chain_detected    │            │
│  │   ATTACK     │───────────────────────────────┘            │
│  │  Module v2.0 │                                             │
│  │              │←──── spc.updated ──── SPC Module            │
│  │              │←──── cti.threat ──── CTI Module            │
│  │  ┌────────┐  │                                             │
│  │  │Detection│  │                                             │
│  │  │Intel   │  │                                             │
│  │  │Emulation│  │                                             │
│  │  │Assess  │  │                                             │
│  │  │APT     │  │                                             │
│  │  └────────┘  │                                             │
│  └─────────────┘                                              │
└──────────────────────────────────────────────────────────────┘
```

**Integration paths explained:**

1. **Assessment → Detection:** The Assessor's check results (`checkResults map[string]bool`) feed ATT&CK coverage calculation and gap analysis.
2. **Detection → Policy:** APT attack-chain detection, behavioral alerts and beacon detection trigger automatic Policy Manager responses through the event bus.
3. **SPC → Attribution:** SPC's CVE matching results can cross-validate against the known exploit preferences of the threat actors in APT attribution.
4. **CTI → Intelligence:** The CTI module's threat coefficient μ and the ATT&CK threat-intelligence submodule share data sources.

### 13.7 Concurrency Safety

All shared state in the module is protected by `sync.RWMutex`; writes use `Lock()`, reads use `RLock()`. Every public method acquires the lock on entry and releases it in a `defer`.

Key concurrency scenarios:

| Scenario | Race risk | Protection |
|------|----------|----------|
| Rule evaluation writes alerts + alert queries | Read/write race | `Lock`/`RLock` |
| Attack-chain reconstruction writes + attribution reads | Read/write race | `Lock`/`RLock` |
| Beacon detection writes + beacon queries | Read/write race | `Lock`/`RLock` |
| Automatic hypothesis generation + manual creation | Write/write race | `Lock` |

## 14. Future Roadmap

- [x] ~~Web UI dashboard (community contribution)~~ → implemented, then removed entirely to tighten the attack surface (2026-08-15, P0-1)
- [ ] Federated cluster support
- [x] ~~Attack simulation integration (Atomic Red Team)~~ → implemented as an adapter (`internal/engine/srd/atomicred.go`)
- [x] ~~OSCAL standard report format~~ → export implemented (`internal/oscal/`), supports JSON/XML
- [ ] Machine-learning tuning of dynamic thresholds

## Version History

- **v2.0** — 2026-06-28. Full completion and production-readiness fixes. Performance: eliminated duplicate SPC/ATT&CK computation, moved regexp compilation out of hot paths, removed the `f.Sync()` anti-pattern, deleted dead `cpeIndex` code. Memory & stability: removed a duplicated SPC module, ATT&CK cache eviction (10 entries), CVE priority eviction, graceful EventBus draining, asynchronous heartbeat-driven assessment. Features: CTI OTX/MISP threat-intelligence integration, bidirectional Wazuh SIEM outbound push, backup/archive system (hourly snapshots + daily tar.gz), L2 HistoricalStore cold storage, kernel self-assessment, Commander command-TTL expiry, Heartbeat Agent pruning, AdapterIntegration goroutine-leak fix, Persistence log retention, CLI SPC subcommands + source deploy, Parse upgrades for 6 management adapters, 10 management DelegationRules, kernel console assessment reports, configurable Agent log format. Whitepaper fixes (L2 storage, IAM references, adapter timeouts, 30x baselines). Testing: 23 kernel integration tests (CTI/Heartbeat/Commander/SPC/HistoricalStore/SIEM). Goroutine-safety fixes: 9 data races across server/interceptor/circuitbreaker/assessor/SPC/ATT&CK, a RegisterFormula functional defect, 5 plugin double-`Stop()` panics, an SRD goroutine leak, and a CLI `m.done` deadlock. Extension-point error logging (15 sites); Collector Sync persistence (flush every 5s); Prism IL Bayesian-inference model expansion; CLI external-command extension; configuration hot-reload fixes (engine cfg pointer update + enabled by default); systemd service + Dockerfile + build scripts; date/version sync across 12 whitepapers.
- **v1.9** — 2026-06-15. Completed whitepaper roadmap goals: Atomic Red Team attack-simulation adapter and tests (structured/flat/single-technique input formats; risk scores mapped from success/failure/skip states and detection triggers); OSCAL standard report export engine and tests (JSON/XML, covering the SSAM/Prism/SPC three-layer risk structure; Prism IR aggregation emitted into OSCAL prop fields); roadmap checklist updated.
- **v1.1** — 2026-05-16. Protocol updates (AssessmentResult gains edge_factors, threat_coefficient, spc_score); Agent heartbeat mechanism documented (Timer to avoid pile-up, bufio line reads); agent.ini configuration reference added; build artifacts consolidated into build/.
- **v1.2** — 2026-05-20. Security-audit fixes merged into docs: HMAC key alert mechanism, API-key source audit, RateLimiter automatic cleanup, CircuitBreaker window cap, Bus panic observability (BusMetrics), JSONL file permissions tightened to 0600, CVE cache cap of 100,000, symlink-bypass protection, config-parse error logging, Server WaitGroup graceful shutdown. Added the standalone entry point (cmd/ASSCOR); updated the project directory structure; documented the interceptor chain (rate limit + circuit breaker + audit).
- **v1.3** — 2026-05-21. Dual protocol-stack upgrade: native gRPC protocol support added (`google.golang.org/grpc`, Protobuf binary serialization + HTTP/2 multiplexing) with the JSONRPC compatibility layer kept as the zero-dependency option; weight hot-reload mechanism (ConfigWatcherModule: 30s polling + SIGHUP); SPC cache disk persistence (load at startup / save on exit, atomic writes); adapter integration module (AdapterIntegrationModule: periodic external-adapter execution injected into the assessment flow); health checks for key plugins (SPC/Heartbeat/Assessor/Persistence/Concurrency implement `HealthCheckable`, unified `Kernel.HealthCheck()`); updated built-in plugin list and directory structure.
- **v1.4** — 2026-05-21. AdapterIntegrationModule registration fix: registered the module in the Kernel plugin list (`main.go:105`), fixing background scheduled sync, `adapter.findings` event-bus publishing, and the on-demand `CollectFindings()` fetch that were not taking effect; added the full adapter inventory (P0/P1/P2 tiers for all 21 adapters and four-stage pipeline details); documented the industry configuration-file system.
- **v1.5** — 2026-05-22. Project-wide code-audit fixes merged into docs: HMAC signature covers params against tampering (H-03); critical messages switched to synchronous PublishSync (H-05); ConfigWatcher safe type assertion to prevent panics (H-06); exclusive-switch Policy Manager fixes threshold overlap (M-02); CTI threat-severity weighting (M-01); WorkerPool goroutine-leak fix (M-04); RateLimiter duplicate-close panic fix (M-03); command-parameter shell-metacharacter detection (M-06); environment-variable injection protection (M-05); SPC CVE-matching logic fix and EPSS logarithmic scaling (M-07, L-05); SessionID entropy raised to 128 bits (M-08); log-injection protection and Sync flush (L-01, L-02); ExecuteCommand parameter validation (L-03); rand.Read error handling (L-04); PB String() recursion fix (H-01); dynamic-scoring FillFromLegacy fix (H-02); Assessor hostID parameterization (H-04). Additions: CLI Agent management module (§11.8 — lifecycle commands/multi-instance/permissions/formatted output); message-bus publish-mode documentation (sync/async semantics); directory-structure updates.
- **v1.6** — 2026-05-25. ATT&CK V19 module expansion merged into docs: new §13 ATT&CK V19 threat analysis module (positioning, file architecture, 28 core data structures, ATTACKInterface 50+-method design, extension-point registration, SSAM integration path, concurrency safety); four core submodules (detection & analysis / threat intelligence / adversary emulation / assessment & engineering); APT attack analysis and detection enhancement (attack-chain reconstruction / behavioral detection / attribution engine / threat hunting); SPC module split (spc_fetch.go/spc_match.go/spc_persist.go); additional SPC data sources (CNNVD/CNVD); precise CPE version matching; concurrent sharded NVD API requests; directory-structure updates; built-in plugin-list updates.

> **Note:** SSAM (System Security Acceptability Model) is the core algorithm, currently version 2.0, published as the standalone pure-functional library [github.com/chins-xing/ssam](https://github.com/chins-xing/ssam). ASSCOR is the open-source platform framework implementing SSAM, currently version v0.2.3. The two version numbers evolve independently.
