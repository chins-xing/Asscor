# ASSCOR User Manual

> Version: v0.2.3 | SSAM 2.0 | Last updated: 2026-08-12

> The scores ASSCOR produces are the **result of a mathematical model, not an absolute security ground truth.**
> Treat scoring as a decision aid rather than a decision substitute. The model captures the
> quantifiable dimensions it knows, but the complete picture of security extends well beyond
> what any formula can cover.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Quick Start](#2-quick-start)
3. [Deployment Architecture](#3-deployment-architecture)
4. [Kernel Deployment](#4-kernel-deployment)
5. [Agent Deployment](#5-agent-deployment)
6. [TLS Certificate Management](#6-tls-certificate-management)
7. [Configuration Reference](#7-configuration-reference)
8. [SPC Security Posture Module](#8-spc-security-posture-module)
9. [MLPS Mapping and Scoring Thresholds](#9-mlps-mapping-and-scoring-thresholds)
10. [ATT&CK V19 Threat Analysis Module](#10-attck-v19-threat-analysis-module)
11. [Logging](#11-logging)
12. [Daemon Mode](#12-daemon-mode)
13. [Offline Assessment Mode](#13-offline-assessment-mode)
14. [Environment Variables Reference](#14-environment-variables-reference)
15. [Troubleshooting](#15-troubleshooting)
16. [CLI Command Reference](#16-cli-command-reference)
17. [Custom Extensions](#17-custom-extensions)
18. [Algorithm Integrity Protection](#18-algorithm-integrity-protection)
19. [Version History](#version-history)

---

## 1. Overview

ASSCOR is an open-source, distributed security-acceptability assessment platform implementing the System Security Acceptability Model (SSAM) 2.0. It evaluates host security posture across four mutually exclusive core domains and integrates the MITRE ATT&CK V19 threat-analysis framework, forming a complete chain from security assessment and threat detection through to APT attack analysis.

SSAM V2.0's three-layer semantic model (Intrinsic / Exposure / Threat) replaces the earlier ThreatCoeff/SPCScore dual-penalty scheme with a weighted average over three independent risk layers, improving the interpretability and fairness of scores. The core algorithm library is published as an independent module, [github.com/chins-xing/ssam](https://github.com/chins-xing/ssam) (`ssam-lib/`), with a pure-functional design and zero external dependencies, and is reached through the thin adapter layer `internal/engine/ssam/`.

| Core domain | Weight | What is assessed |
|-------------|--------|------------------|
| Attack Surface Management | 35% | Unused services, open ports, strong authentication, SSH configuration |
| Business Continuity | 25% | Running state of critical services, backup mechanisms, resource adequacy |
| Operation Trust | 25% | File permissions, audit logs, command-history tamper resistance, supply-chain integrity, SELinux/AppArmor |
| Resilience | 15% | Auto-ban precision, SYN cookies, connection limits, Acceptable Compromise Indicator (ACI) |

**Additional modules**:

| Module | Function |
|--------|----------|
| ATT&CK V19 | MITRE ATT&CK framework integration: detection analysis, threat intelligence, adversary emulation, assessment engineering, APT attack analysis and detection enhancement |
| SPC | Security posture calculation: multi-source vulnerability intelligence (NVD/EPSS/CISA KEV/CNNVD/CNVD) compared against the local asset inventory |
| CTI | Cyber threat intelligence management: computation of the dynamic threat coefficient μ |

**Scoring formula**:

```
SSAM_final = (Σ(S_i × W_i) / ΣW_i) × ΠM_j × μ × P_score
```

- `S_i`: core-domain score (0–100)
- `W_i`: core-domain weight (weights sum to 100)
- `M_j`: edge-factor multipliers (product applied only over factors that are Active and have Factor ∈ (0,1))
- `μ`: threat coefficient (default 1.0; adjusted dynamically by the CTI module)
- `P_score`: SPC correction factor (0.60–1.00, derived from CVE match results)

---

## 2. Quick Start

### 2.1 Prerequisites

- Target hosts: Linux (x86_64 / ARM64 / i386 supported)
- Network reachability between Kernel and Agent
- (Recommended) NVD API key: request one at https://nvd.nist.gov/developers/request-an-api-key

### 2.2 Minimal deployment (production, recommended)

```bash
# 1. Install and start the Kernel (one command handles systemd + FHS + PATH)
sudo ./ASSCOR-kernel-linux --install
sudo systemctl start asscor-kernel

# 2. Install and start the Agent (target host)
sudo ./ASSCOR-agent-linux --install
sudo systemctl start asscor-agent

# 3. Attach the management CLI
asscor-cli               # status / plugins / history / exit
```

### 2.3 Offline assessment (no Kernel/Agent required)

```bash
# Standalone mode: run the assessment directly on the local host; results print to the terminal
./ASSCOR-linux --config=/etc/asscor/config.ini          # text report
./ASSCOR-linux --config=/etc/asscor/config.ini -json    # JSON report
```

---

## 3. Deployment Architecture

```
┌─────────────────────────────────────────────────┐
│                  ASSCOR Kernel                    │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ │
│  │Assess│ │Policy│ │ SPC  │ │ CTI  │ │Cmdr  │ │
│  └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ │
│  ┌──────┐                                      │
│  │ATT&CK│  MITRE ATT&CK V19 threat analysis   │
│  └──┬───┘  detect/intel/emulate/assess/APT     │
│     │        │        │        │        │      │
│  ┌──┴────────┴────────┴────────┴────────┴──┐   │
│  │         μKernel Plugin Bus              │   │
│  └────────────────┬───────────────────────┘   │
│                   │ gRPC + mTLS                │
└───────────────────┼───────────────────────────┘
                    │
        ┌───────────┼───────────┐
        │           │           │
   ┌────┴────┐ ┌────┴────┐ ┌────┴────┐
   │ Agent A │ │ Agent B │ │ Agent C │
   │(host-01)│ │(host-02)│ │(host-03)│
   └─────────┘ └─────────┘ └─────────┘
```

**Component descriptions**:

| Component | Responsibility |
|-----------|----------------|
| Kernel | Microkernel that manages plugin lifecycle, the gRPC service, and CLI interaction |
| Agent | Deployed on the assessed host; collects check-item data and reports it to the Kernel |
| CLI | Interactive terminal built into the Kernel; provides command-line management |

## 4. Kernel Deployment

### 4.1 Command-line options

```
ASSCOR-kernel [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config` | `config.ini` | Configuration file path |
| `--listen` | `:50051` | gRPC listen address |
| `--no-mtls` | `false` | Disable mTLS (**development only**; production startup is rejected when `[comms] require_mtls=true`) |
| `--cert-dir` | `certs` | TLS certificate directory |
| `--verify-certs` | `false` | Verify certificate-chain consistency, then exit |
| `--force-regen-certs` | `false` | Force regeneration of all TLS certificates |
| `--daemon` | `false` | Run in daemon mode |
| `--pid-file` | `ASSCOR-kernel.pid` | PID file path |
| `--version` | — | Print version and exit |
| `--install` | — | Install as a systemd service (requires root) |
| `--uninstall` | — | Remove the systemd service (requires root) |
| `--upgrade` | — | In-place upgrade of the installed version (requires root) |
| `--check-install` | — | Verify installation integrity, then exit |
| `--cli <socket>` | — | Attach the CLI to a running Kernel over a Unix socket |
| `--log-format` | `json` | Log format: `json`, `text` |
| `--log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `--log-output` | `stderr` | Log destination: `stderr`, `stdout`, or a file path |

### 4.2 Production deployment (systemd + FHS, recommended)

The single binary carries its own installer: one command completes systemd service registration, the FHS directory layout, PATH symlinks, and user creation:

```bash
# Install (requires root)
sudo ./ASSCOR-kernel-linux --install

# Start + enable at boot
sudo systemctl start asscor-kernel
sudo systemctl enable asscor-kernel

# Install the Agent (same host or the assessed host)
sudo ./ASSCOR-agent-linux --install
sudo systemctl start asscor-agent
```

**FHS filesystem layout**:

```
/etc/asscor/config.ini              # Kernel configuration
/etc/asscor/agent.ini               # Agent configuration
/etc/asscor/config/                 # 6 industry template bundles
/opt/asscor/ASSCOR-kernel           # Kernel binary
/opt/asscor/agent/ASSCOR-agent      # Agent binary
/opt/asscor/asscor-cli.sock         # CLI Unix socket
/var/lib/asscor/                    # Data (CVE cache, assessment records, backups)
/var/lib/asscor/latest-assessment.json      # Latest assessment report
/var/lib/asscor/assessments-<date>.jsonl     # Historical assessment records
/var/log/asscor/kernel.log          # Kernel log
/usr/bin/asscor                     # Global command (symlink)
/usr/bin/asscor-cli                 # CLI convenience wrapper script
```

After installation, `asscor` and `asscor-cli` are usable from any path, including under `sudo`.

### 4.3 systemctl management

| Command | Effect |
|---------|--------|
| `systemctl start asscor-kernel` | Start the service |
| `systemctl stop asscor-kernel` | Stop (SIGTERM → graceful shutdown; CVE cache is saved) |
| `systemctl reload asscor-kernel` | SIGHUP → hot-reload config.ini (weights/thresholds/Prism/edge factors) |
| `systemctl status asscor-kernel` | Show service status |
| `journalctl -u asscor-kernel -f` | Follow logs in real time |

### 4.4 Version upgrade

```bash
# In-place upgrade (stops → backs up → replaces → starts automatically; rolls back on failure)
sudo ./ASSCOR-kernel-v0.2.3-linux-amd64 --upgrade
asscor --version         # confirm the version
```

The upgrade re-creates PATH symlinks automatically and keeps the previous binary as `.bak`.

### 4.5 Remote CLI

When the Kernel runs as a systemd service (no interactive terminal), attach the CLI over the Unix socket:

```bash
asscor-cli               # convenience wrapper (auto-connects to the socket)
# or
asscor --cli /opt/asscor/asscor-cli.sock

asscor> status           # show Kernel status
asscor> plugins          # list plugins
asscor> exit             # disconnect (Kernel keeps running)
```

> `exit`/`quit` only disconnect the current CLI session; the Kernel keeps running. Only `systemctl stop` fully stops the Kernel.

### 4.6 Manual start examples

```bash
# Standard startup (mTLS enabled)
./ASSCOR-kernel-linux --config=/etc/asscor/config.ini --listen=:50051

# Development mode (no mTLS) — first set [comms] require_mtls=false explicitly in config.ini,
# otherwise the production-enforced mTLS policy rejects a --no-mtls startup (isolated dev only)
./ASSCOR-kernel-linux --no-mtls --log-level=debug --log-format=text

# Daemon mode
./ASSCOR-kernel-linux --daemon --pid-file=/var/run/ASSCOR-kernel.pid

# Verify certificates
./ASSCOR-kernel-linux --verify-certs --cert-dir=/etc/asscor/certs

# Regenerate certificates
./ASSCOR-kernel-linux --force-regen-certs --cert-dir=/etc/asscor/certs
```

### 4.7 Startup output

When the Kernel starts, it prints its load status:

```
ASSCOR μKernel
  Framework: v0.2.3   SSAM: 2.0

  Listen:   :50051 (mTLS: true)
  Log:      json (info) -> stderr
  Plugins:  18 loaded
    {heartbeat} v1.0.0 — Agent heartbeat tracking
    {spc} v1.0.0 — Security Posture Calculator
    {cti} v1.0.0 — Cyber Threat Intelligence
    {assessor} v1.0.0 — SSAM security assessment engine
    {policy} v1.0.0 — Policy enforcement and compliance
    {commander} v1.0.0 — Agent command dispatch
    {log_collector} v1.0.0 — Agent log collection
    {persistence} v1.0.0 — Data persistence layer
    {concurrency} v1.0.0 — Concurrency control
    {attck} v1.0.0 — MITRE ATT&CK V19 threat analysis
    {config_watcher} v1.0.0 — Configuration hot-reload
    {adapter_integration} v1.0.0 — External adapter integration
    {source_manager} v1.0.0 — External source management

    {comms} — JSONRPC + gRPC communication servers
    {srd_adapters} v1.0.0 — SRD external result adapters
    {cli} v1.0.0 — Command-line interface
```

## 5. Agent Deployment

### 5.1 Command-line options

```
ASSCOR-agent [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config` | `agent.ini` | Agent configuration file path |
| `--kernel` | `127.0.0.1:50051` | Kernel address (host:port) |
| `--host-id` | hostname | Agent host identifier |
| `--tls` | `false` | Enable mTLS connection |
| `--tls-skip-verify` | `false` | Skip TLS certificate verification (**development only**) |
| `--cert-dir` | `certs` | TLS certificate directory |
| `--install` | — | Install as a systemd service (requires root) |
| `--uninstall` | — | Remove the systemd service (requires root) |
| `--upgrade` | — | In-place upgrade (requires root) |
| `--version` | — | Print version and exit |
| `--log-format` | `json` | Log format |
| `--log-level` | `info` | Log level |
| `--log-output` | `stderr` | Log destination |

### 5.2 Deployment examples

```bash
# Production install (systemd)
sudo ./ASSCOR-agent-linux --install
sudo systemctl start asscor-agent

# Manual run: connect to a remote Kernel (mTLS)
./ASSCOR-agent-linux --kernel=192.168.1.10:50051 --tls --cert-dir=/etc/asscor/certs

# Specify a host ID
./ASSCOR-agent-linux --kernel=10.0.0.5:50051 --tls --host-id=web-server-01

# Development mode
./ASSCOR-agent-linux --kernel=localhost:50051 --tls-skip-verify --log-level=debug
```

> The Agent must run as root to perform system-level checks (reading `/etc/shadow`, `iptables`, etc.). When run as a non-root user, checks that require root privileges are skipped automatically and flagged.

### 5.3 Agent configuration file

The Agent supports its own INI configuration file (default `agent.ini`) with the following format:

```ini
[agent]
kernel_addr = 192.168.1.10:50051
host_id = web-server-01
tls_enabled = true
cert_dir = /etc/ASSCOR/certs

[logging]
format = json
level = info
output = /var/log/ASSCOR-agent.log
```

Command-line arguments take precedence over the configuration file.

---

## 6. TLS Certificate Management

ASSCOR uses mTLS (mutual TLS) to secure communication between Kernel and Agent.

### 6.1 Automatic certificate generation

On first startup, the Kernel automatically generates the following files in the certificate directory:

```
certs/
├── ca.crt        # CA certificate
├── ca.key        # CA private key
├── server.crt    # Kernel server certificate
├── server.key    # Kernel server private key
├── agent.crt     # Agent client certificate
└── agent.key     # Agent client private key
```

### 6.2 Certificate operations

```bash
# Verify certificate-chain consistency
./ASSCOR-kernel-linux --verify-certs --cert-dir=/etc/asscor/certs

# Force-regenerate all certificates (old certificates are deleted)
./ASSCOR-kernel-linux --force-regen-certs --cert-dir=/etc/asscor/certs
```

### 6.3 Certificate distribution

Distribute `ca.crt`, `agent.crt`, and `agent.key` to the certificate directory on every Agent host.

> **Security note**: private key files (`.key`) should have permissions 0600 and be readable by root only.

---

## 7. Configuration Reference

Configuration files use the INI format; the default path is `config.ini`.

### 7.1 Weight configuration

```ini
[weights]
attack_surface = 35        # Attack Surface Management weight
business_continuity = 25   # Business Continuity weight
operation_trust = 25       # Operation Trust weight
resilience = 15            # Resilience weight
```

> The four weights must sum to 100.

### 7.2 Acceptability threshold

```ini
[acceptability]
threshold = 80.0                       # SSAM score threshold
compliance_framework = GB/T 22239-2019 Level 3  # Compliance framework
```

The threshold is linked to the MLPS (Chinese Multi-Level Protection Scheme, GB/T 22239-2019) level:

| MLPS level | SSAM threshold |
|------------|----------------|
| Level 2 | ≥ 65 |
| Level 3 (default) | ≥ 80 |
| Level 4 | ≥ 90 |

### 7.3 Edge factors

```ini
[edge_factors]
two_factor_failure = 0.85    # Multiplier when two-factor authentication is missing

[edge_factors.level4_override]
two_factor_failure = 0.70    # Multiplier at MLPS Level 4 when three-factor authentication is missing
```

Edge factors take part in the multiplicative product only when their triggering condition is met; their values lie in the range (0, 1).

### 7.4 Threat configuration

```ini
[threat]
coefficient = 1.0     # Threat coefficient μ (default 1.0; adjusted dynamically by the CTI module)
spc_enabled = true    # Whether the SPC correction is enabled
```

### 7.5 Check-item deltas

```ini
[check_deltas]
AS-001 = -8      # Attack Surface check item
OT-001 = -10     # Operation Trust check item
RS-001 = -10     # Resilience check item
BC-005 = -10     # Business Continuity check item
AC-001 = -15     # MLPS Level 4 additional-control check item
EF-001 = 0       # Edge-factor check item
```

A negative delta means points are deducted when the check fails; a positive one is a compensating bonus. Each check-item ID follows the `XX-NNN` numbering scheme:

- `AS`: Attack Surface
- `OT`: Operation Trust
- `RS`: Resilience
- `BC`: Business Continuity
- `AC`: MLPS Level 4 Additional Control
- `EF`: Edge Factor
- `KS`: Kernel Security extension

### 7.6 Extension configuration

```ini
[extensions]
kernel_security = on        # Enable the Kernel Security extension domain

[extension_weights]
kernel_security = 10        # Kernel Security extension weight
```

## 8. SPC Security Posture Module

The SPC module compares external vulnerability data sources (NVD/EPSS/CISA KEV/CNNVD/CNVD) against the local asset inventory and outputs an individual correction factor, P_score (0.60–1.00).

> **Methodology statement (known limitations)**: SPC's validation logic is based on CPE string matching — it cross-references the name/version of installed packages against the affected product versions in the CVE databases. It does **not** perform exploit validation, runtime-reachability analysis, binary analysis, or verification of compensating mitigations. Matches may produce false positives (vulnerabilities already mitigated by WAF/virtual patching whose version numbers were never updated) and false negatives (matching version numbers but customized variants). SPC is positioned as a "vulnerability-intelligence aggregation and version-comparison engine", not an "exploit validator"; there are currently no plans to introduce deep validation capabilities.

### 8.1 Basic configuration

```ini
[spc]
enabled = true              # Enable or disable
min_pscore = 0.60           # P_score lower bound
cache_retention_days = 365  # CVE cache retention (days)
fetch_interval_h = 1        # Auto-refresh interval (hours)
```

### 8.2 NVD data source

```ini
[spc.nvd]
base_url = https://services.nvd.nist.gov/rest/json/cves/2.0
api_key =                   # Leave empty to read from the NVD_API_KEY environment variable
sync_interval_h = 6         # Sync interval
use_last_mod = true         # Incremental sync mode
no_rejected = true          # Filter out rejected CVEs
```

**API key notes**:

- Without a key: request limit is 5 requests/30 s; the system automatically applies a 4-way concurrent sharded strategy
- With a key: request limit is 50 requests/30 s; the system automatically applies a 2-way concurrent sharded strategy
- Obtain a key at: https://nvd.nist.gov/developers/request-an-api-key

### 8.3 EPSS data source

```ini
[spc.epss]
enabled = true
data_url = https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
sync_interval_h = 24
```

### 8.4 CISA KEV data source

```ini
[spc.cisa_kev]
enabled = true
catalog_url = https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
sync_interval_h = 24
```

### 8.5 CNNVD data source

```ini
[spc.cnnvd]
enabled = false
base_url = https://www.cnnvd.org.cn/home/data
api_key =                   # Leave empty to read from the CNNVD_API_KEY environment variable
sync_interval_h = 24
```

### 8.6 CNVD data source

```ini
[spc.cnvd]
enabled = false
base_url = https://www.cnvd.org.cn/shareData
sync_interval_h = 24
```

### 8.7 MISP data source

```ini
[spc.misp]
base_url =                  # MISP server address
api_key =                   # Leave empty to read from the MISP_API_KEY environment variable
verify_tls = true
sync_interval_h = 1
tlp_filter = white          # TLP tag filter
```

### 8.8 OSCAL import

```ini
[spc.oscal]
enabled = false
input_format = json         # json / yaml / xml
results_path = ./oscal_results/
plan_path = ./oscal_plan/
```

### 8.9 CPE matching mechanism

The Agent automatically converts installed packages to CPE 2.3 format (`cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*`); the SPC module matches against them in the following priority order:

1. **Exact version match** (MatchExactVersion): vendor, product, and version all identical
2. **Version range match** (MatchVersionRange): vendor and product identical, version within the affected range
3. **Product match** (MatchProduct): vendor and product identical, no version information
4. **Vendor match** (MatchVendor): only vendor identical
5. **Description match** (MatchDescription): package name appears in the CVE description

---

## 9. MLPS Mapping and Scoring Thresholds

### 9.1 Check coverage

| MLPS level | Automated checks |
|------------|------------------|
| Level 3 | 53 |
| Level 4 | 53 + 9 = 62 |

### 9.2 Core-domain check distribution

| Core domain | Check prefix | Count (Level 3) |
|-------------|--------------|-----------------|
| Attack Surface Management | AS-001 – AS-017 | 17 |
| Operation Trust | OT-001 – OT-022 | 22 |
| Resilience | RS-001 – RS-012 | 12 |
| Business Continuity | BC-005 – BC-007 | 3 |
| MLPS Level 4 additional controls | AC-001 – AC-008 | 8 (Level 4 only) |
| Edge factors | EF-001 – EF-002 | 2 |

### 9.3 Scoring-threshold linkage

Change the `[acceptability] threshold` value to switch the threshold associated with each MLPS level:

```ini
# MLPS Level 2
threshold = 65.0

# MLPS Level 3 (default)
threshold = 80.0

# MLPS Level 4
threshold = 90.0
```

## 10. ATT&CK V19 Threat Analysis Module

ASSCOR v0.2.3 integrates the MITRE ATT&CK V19 framework as a μKernel plugin (`attck`, priority 21, version 1.0.0). The module provides a complete threat-analysis capability chain spanning detection, intelligence, simulation, and assessment, and extends it with APT attack-analysis and detection-enhancement submodules.

### 10.1 Four core submodules

| Submodule | Core capabilities |
|-----------|-------------------|
| **Detection & Analysis** | Detection-rule engine (register/evaluate/delete), anomaly-event recording and querying, alert correlation analysis, detection summary statistics |
| **Threat Intelligence** | IOC management (add/delete/query/search/expiry cleanup), threat-actor profiling, TTP tracking, alert intel enrichment |
| **Adversary Emulation & Red Team** | Emulation-scenario management, automatic scenario generation from APT groups, safe-mode emulation execution, emulation-result recording |
| **Assessment & Engineering** | Gap analysis (defensive coverage), security-control mapping, mitigation-recommendation generation, continuous-improvement tracking |

### 10.2 APT attack analysis and detection enhancement

On top of the four core submodules, the APT enhancement layer provides advanced threat-analysis capabilities:

| Function | Description |
|----------|-------------|
| **Attack-chain reconstruction** | Reconstructs multi-stage attack chains automatically from multi-source evidence (alerts, anomalies, IOCs), ordered by ATT&CK tactic sequence |
| **Behavioral detection** | Behavioral-indicator registration and evaluation, host-behavior baseline management, C2 beacon detection (interval-jitter analysis) |
| **APT attribution engine** | Multi-source evidence fusion (TTP overlap 60% + IOC match 40%), APT-group matching with confidence scores |
| **Threat hunting framework** | Hunting-hypothesis CRUD, automatic hypothesis generation from the attack-transition matrix, hypothesis execution and confirmation |

### 10.3 Collaboration with the SSAM assessment system

The ATT&CK module and the SSAM assessment system form a bidirectional enhancement loop:

- **Resilience-domain enhancement**: APT attack-chain detection results are injected into the policy manager over the event bus, influencing host security-state judgments
- **SPC linkage**: threat-actor information produced by the APT attribution engine can be cross-validated against SPC vulnerability intelligence to adjust P_score dynamically
- **CTI collaboration**: the CTI module's threat coefficient μ and the ATT&CK threat-intelligence submodule share data sources
- **Policy linkage**: APT detection alerts trigger automatic response actions in the policy manager

### 10.4 ATT&CK configuration

```ini
[attck]
enabled = true                  # Whether the ATT&CK module is enabled
version = v19                   # ATT&CK framework version
auto_hunt = false               # Whether hunting hypotheses are generated automatically
beacon_threshold = 0.7          # Beacon-detection score threshold
attribution_threshold = 0.6     # APT attribution confidence threshold
safe_emulation = true           # Whether emulation defaults to safe mode
```

### 10.5 CLI operations

The ATT&CK module is operated from the Kernel's interactive CLI:

```
# View the detection summary
ASSCOR> attck summary

# Register a detection rule
ASSCOR> attck rule add --name "suspicious_powershell" --technique T1059 --severity high

# List IOCs
ASSCOR> attck ioc list --type ip

# Run a gap analysis
ASSCOR> attck gap --host=web-server-01

# Reconstruct an attack chain
ASSCOR> attck chain --host=web-server-01

# Run APT attribution
ASSCOR> attck attribute --chain=<chainID>

# Generate a hunting hypothesis
ASSCOR> attck hunt generate --host=web-server-01

# Run an adversary emulation
ASSCOR> attck emulate --scenario=<scenarioID> --host=web-server-01 --safe
```

---

## 11. Logging

### 11.1 Log configuration

```bash
# JSON format (default; suited to log-collection systems)
-log-format json -log-level info -log-output /var/log/ASSCOR-kernel.log

# Text format (suited to human reading)
-log-format text -log-level debug -log-output stderr
```

### 11.2 Log levels

| Level | Purpose |
|-------|---------|
| `debug` | Detailed debug information, including request/response details |
| `info` | Normal operational information (recommended for production) |
| `warn` | Warnings such as missing configuration or degraded operation |
| `error` | Errors that need attention and handling |

### 11.3 Log component prefixes

Every log line carries a component prefix for filtering:

```
{"time":"...","level":"info","component":"spc","msg":"CVE cache loaded","count":1234}
{"time":"...","level":"warn","component":"kernel","msg":"NVD API key not configured"}
```

Common component prefixes: `kernel`, `spc`, `cti`, `assessor`, `policy`, `commander`, `heartbeat`, `cli`, `tls`

---

## 12. Daemon Mode

```bash
# Start the daemon
./ASSCOR-kernel-linux --daemon --pid-file=/var/run/ASSCOR-kernel.pid

# Stop the daemon
kill $(cat /var/run/ASSCOR-kernel.pid)
```

In daemon mode, logs are redirected automatically to `ASSCOR-kernel.log`.

---

## 13. Offline Assessment Mode

The `ASSCOR` command provides standalone offline assessment without deploying a Kernel or an Agent, printing results immediately to the terminal:

```bash
# Text report (printed directly to the terminal)
./ASSCOR-linux --config=/etc/asscor/config.ini

# JSON report (can be redirected to a file)
./ASSCOR-linux --config=/etc/asscor/config.ini -json > report.json
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config` | `config.ini` | Configuration file path |
| `--json` | `false` | Output in JSON format |

Full capabilities of standalone mode:

- **Core checks**: 80 local security checks (including the KS Kernel-Security domain)
- **SPC posture calculation**: automatically fetches NVD/EPSS/KEV data and computes results when data sources are configured
- **ATT&CK analysis**: coverage, kill chain, APT attribution, risk prediction
- **External adapter dispatch**: tools enabled in the `[adapters]` section of config.ini (Trivy/Lynis/Suricata/ClamAV/AIDE, etc.) are executed automatically and their findings are dispatched to the corresponding check items
- **SRD/Prism three-layer analysis**: Core (dynamic scoring) → Semantic (fuzzy states) → Inference (trend prediction)

> **Report-location note**: standalone mode prints reports **to the terminal/stdout only**; nothing is written to disk. For persistent historical reports, use Kernel + Agent mode (reports are written automatically to `/var/lib/asscor/`; see §4.2).

### 13.1 Report-location reference

| Mode | Report location |
|------|-----------------|
| Standalone `ASSCOR` | Terminal stdout (`-json > file` to save) |
| Kernel service mode | `/var/lib/asscor/latest-assessment.json` (latest) / `/var/lib/asscor/assessments-<date>.jsonl` (history) (the Web UI was removed on 2026-08-15 as part of attack-surface reduction) |

---

## 14. Environment Variables Reference

| Environment variable | Purpose | Precedence |
|----------------------|---------|------------|
| `NVD_API_KEY` | NVD API key | Overrides `api_key` in config.ini |
| `MISP_API_KEY` | MISP API key | Overrides `api_key` in config.ini |
| `CNNVD_API_KEY` | CNNVD API key | Overrides `api_key` in config.ini |
| `OTX_API_KEY` | OTX threat-intelligence API key | Overrides `otx_api_key` in config.ini |
| `MISP_URL` / `MISP_API_KEY` | MISP threat-intelligence address / key | Override the corresponding config.ini entries |
| `NETBOX_TOKEN` | NetBox API token | Overrides `[netbox] api_token` |
| `SNIPEIT_TOKEN` | Snipe-IT API token | Overrides `[snipe_it] api_token` |
| `WAZUH_PASSWORD` | Wazuh SIEM password | Overrides `[wazuh_siem] password` |
| `JIRA_TOKEN` | Jira API token | Overrides `[jira] api_token` |
| `RUNDECK_TOKEN` | Rundeck API token | Overrides `[rundeck] api_token` |
| `FREEIPA_TOKEN` | FreeIPA API token | Overrides the corresponding `api_token` |
| `KEYCLOAK_TOKEN` | Keycloak API token | Overrides the corresponding `api_token` |
| `<ENV>_FILE` (e.g. `NETBOX_TOKEN_FILE`) | Secret-file path (Docker-secrets style); the file content (whitespace-trimmed) is used as the credential | Lower than the same-name environment variable; higher than config.ini |

> **Unified credential precedence (v0.2.3)**: environment variable > secret file (`<ENV>_FILE` or the `api_token_file`
> config item) > config.ini value. `${VAR}` placeholders in config.ini values are expanded at load time
> (left as-is with a warning when unset, so credentials never fail silently). SPC/CTI and all adapter
> connectors share this mechanism; the resolved source is written to the audit log (e.g.
> `adapter credential loaded from environment variable`).

> **Security note**: API keys should be supplied via environment variables or secret files; hardcoding them in
> configuration files or command-line arguments is prohibited.

## 15. Troubleshooting

### 15.1 Kernel startup failure

| Symptom | Likely cause | Solution |
|---------|--------------|----------|
| `FATAL: kernel bootstrap failed` | Plugin initialization failure | Check the log output and confirm the configuration file format is correct |
| `WARN: server start failed` | Port already in use | Change the `-listen` address or free the port |
| Certificate errors | Certificate files corrupt or mismatched | Regenerate with `-force-regen-certs` |

### 15.2 Agent connection failure

| Symptom | Likely cause | Solution |
|---------|--------------|----------|
| `connection refused` | Kernel not started, or wrong address | Confirm the Kernel address and port |
| `certificate verify failed` | Certificate mismatch | Redistribute the certificates and confirm the `cert_dir` path |
| `agent: fatal` | Configuration error | Run with `-log-level debug` to see detailed errors |

### 15.3 SPC data-sync issues

| Symptom | Likely cause | Solution |
|---------|--------------|----------|
| `CVE cache is empty` | Initial sync not finished | Wait for the background sync to finish (~1–5 minutes) |
| `NVD API rate limited` | No API key or requests too frequent | Configure the `NVD_API_KEY` environment variable |
| `SPC cannot calculate risk` | Cache is empty | Check the network and confirm the data source is reachable |

### 15.4 Abnormal scores

| Symptom | Likely cause | Solution |
|---------|--------------|----------|
| Score always 100 | All checks pass | Normal; indicates a healthy security state |
| Score abnormally low | Check-item delta values too large | Review the `[check_deltas]` configuration |
| P_score at 0.60 | High-risk CVE matches present | Use the `spc cve` command to inspect the matched CVE details |

---

## 16. CLI Command Reference

### 16.1 CLI overview

The ASSCOR Kernel ships with a built-in interactive CLI terminal, entered automatically after the Kernel starts. The CLI offers command registration, auto-completion, history, and plugin-extension capabilities.

**Entering the CLI**: after the Kernel starts, logs are redirected to `ASSCOR-kernel.log` and the terminal enters interactive mode:

```
ASSCOR μKernel
  Framework: v0.2.3   SSAM: 2.0
  Listen:   :50051 (mTLS: true)
  CLI active: logs redirected to ASSCOR-kernel.log

ASSCOR>
```

**Command syntax**: `command <subcommand|param> [options]`. Options take the form `--name=value` or `--name value`; boolean options are enabled with `--flag`. Press `Ctrl+D` or `Ctrl+C` to exit.

### 16.2 Common options

| Option | Short | Description |
|--------|-------|-------------|
| `--verbose` | `-v` | Show verbose output |
| `--json` | `-j` | Output in JSON format |
| `--quiet` | `-q` | Suppress non-essential output |
| `--help` | `-h` | Show command help |

### 16.3 Core commands

**help** — show help for a command or list all available commands: `help [command]`

**version** — show the ASSCOR framework version and the SSAM model version: `version`

**status** — show current Kernel status, including plugin states, uptime, and resource usage: `status [--format=json]`

### 16.4 Assessment commands

**assess** — trigger a security-acceptability assessment of the specified host.

```
Usage: assess [host] [options]
Args: host — target host ID (default: local)
Options: --format=json, --domain=attack_surface|business_continuity|operation_trust|resilience
```

### 16.5 SPC commands

**spc** — query the SPC module's CVE cache, P-score, KEV count, and correction data.

```
Usage: spc <summary|cve|kev|score|fetch> [options]
Options: --limit=N (default 20), --cvss-min=N, --kev-only, --host=HOST
Examples:
  ASSCOR> spc summary
  ASSCOR> spc cve --cvss-min=9.0 --kev-only
  ASSCOR> spc score --host=web-server-01
  ASSCOR> spc fetch
```

### 16.6 Agent-management commands

**agent** — manage registered Agents.

```
Usage: agent <list|status|start|stop|restart|config|command> [options]
Options: --host=HOST, --all, --filter=key=value, --limit=N (default 50), --watch
Examples:
  ASSCOR> agent list --filter=active=true
  ASSCOR> agent status --host=web-server-01
  ASSCOR> agent stop --host=db-master-01
  ASSCOR> agent command --host=web-01 --action=scan
```

**log** — view, filter, and export Agent runtime logs.

```
Usage: log <show|export> [options]
Options: --host=HOST, --level=debug|info|warn|error, --limit=N (default 50), --format=json|csv, --output=PATH
```

### 16.7 ATT&CK commands

**attck** — query analysis results from the MITRE ATT&CK V19 module: coverage, kill chain, APT matches, detection rules, and threat intelligence.

```
Usage: attck <summary|coverage|killchain|apt|detect|ti>
Options: --host=HOST, --limit=N (default 20), --json
```

Core subcommands:

```
ASSCOR> attck summary                                      # module overview: coverage/alerts/IOCs and other key metrics
ASSCOR> attck coverage --host=web01                         # detection coverage across 14 tactics
ASSCOR> attck killchain --host=web01                        # 9-stage kill-chain scoring
ASSCOR> attck apt --host=web01                              # APT-group matching results
ASSCOR> attck detect                                        # detection-rule and alert summary
ASSCOR> attck ti                                            # threat-intelligence (IOC/actor) summary
```

### 16.8 Diagnostic commands

**diag** — show Kernel runtime diagnostics (event-bus metrics, worker-pool state).

```
Usage: diag [--json]
Examples:
  ASSCOR> diag              # terminal-format output
  ASSCOR> diag --json       # JSON-format output
```

### 16.9 Policy commands

**policy** — view the current policy configuration and status snapshot.

```
Usage: policy
Notes: shows policy thresholds, the current host-state distribution, and recent policy actions
```

### 16.10 Plugin-management commands

**plugin** — list, inspect, and manage Kernel plugins.

```
Usage: plugin <list|info|health> [name]
Examples:
  ASSCOR> plugin list
  ASSCOR> plugin info spc
  ASSCOR> plugin health
```

### 16.11 External source-management commands

**source** — deploy, configure, start/stop, and audit external integration sources.

```
Usage: source <list|info|deploy|enable|disable|update|uninstall|run|config|audit> [name] [options]
Options: --category=scanner|management, --version=VERSION, --force, --limit=N (default 50)
```

### 16.12 System commands

**config** — view the current Kernel configuration: `config [key] [--format=json]`

**health** — run a health check against all Kernel plugins: `health [--json]`

### 16.13 Debug commands

**history** — view the command-execution history: `history [count] [--failed] [--clear]`

### 16.14 Interactive-terminal features

- **Auto-completion**: press `Tab` after typing a command (commands, subcommands, and options all complete)
- **Command history**: browse previous commands with the `↑`/`↓` arrow keys
- **Script integration**: every command supports `--json` for structured JSON output: `echo "spc summary --json" | asscor-cli`
- **Exit codes**: 0=success, 1=execution error, 2=usage error, 130=user cancel

### 16.15 Registering plugin custom commands

```go
cliPlugin, ok := k.Container().Resolve((*cli.CLIInterface)(nil))
if ok {
    cliMod := cliPlugin.(cli.CLIInterface)
    cliMod.RegisterCommand(cli.NewBaseCommand(
        cli.CommandInfo{
            Name: "mycmd", Short: "My custom command",
            Usage: "mycmd [args]", Category: cli.CategoryPlugin,
        },
        func(ctx *cli.CommandContext) *cli.CommandResult {
            return &cli.CommandResult{ExitCode: cli.ExitOK, Output: "Custom command executed\n"}
        },
    ))
}
```

## 17. Custom Extensions

ASSCOR supports three extension methods that require no Go coding, progressing from zero barrier to professional development.

### 17.1 Config-file-defined checks (`[user_check]`)

Add security checks directly to `config.ini` without any programming:

```ini
# Command check: runs a shell command; exit 0 or an output matching the string = pass
[user_check.nginx]
id = CU-001
domain = attack_surface
name = Nginx service status
description = Check if nginx is running
command = systemctl is-active nginx
delta = -8
output_match = active

# File-content check: verifies a file exists and its content matches a regex
[user_check.auditd]
id = CU-002
domain = operation_trust
name = Auditd rules
description = Verify auditd has shadow watch rules
file_path = /etc/audit/audit.rules
file_regex = -w /etc/shadow -p wa
delta = -10
```

Supported fields:

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique check ID, e.g. `CU-001` |
| `domain` | Yes | Owning domain (attack_surface / business_continuity / operation_trust / resilience / kernel_security) |
| `name` | Yes | Check name |
| `command` | * | Shell command (exit 0 = pass) |
| `output_match` | No | String that must appear in the output for a pass |
| `file_path` | * | Path of the file to check |
| `file_regex` | No | File content matching this regex = pass |
| `delta` | No | Deduction on failure (default -10) |

> *: at least one of `command` and `file_path` must be provided. After editing, run `systemctl reload asscor-kernel` for the changes to take effect.

### 17.2 External script adapters (`[adapter_script]`)

Run scripts written in any language (Bash/Python/anything); their JSON stdout automatically becomes adapter findings:

```ini
[adapter_script.my-monitor]
path = /opt/asscor/scripts/my-monitor.sh
```

Script stdout format (JSON array):

```json
[
  {
    "id": "MON-001",
    "title": "Disk usage warning",
    "severity": "high",
    "detail": "/dev/sda1 is 95% full",
    "domain": "business_continuity",
    "finding_type": "alert"
  }
]
```

**Security restrictions**:
- Script paths must be under `/opt/asscor/scripts/`, `/etc/asscor/scripts/`, or `/var/lib/asscor/scripts/`
- Scripts must be owned by root:root and not world-writable
- Symbolic links are rejected
- 30-second execution timeout
- 1 MB output cap

### 17.3 Plugin SDK (standalone Go module, professional development)

`pluginsdk/` provides a standalone Go module template. Plugins communicate with the Kernel over JSON-RPC (stdin/stdout), with **zero dependency on ASSCOR source code**:

```
pluginsdk/
├── go.mod           # standalone module definition
├── sdk.go           # Plugin interface + JSON-RPC loop
├── cmd/myplugin/    # complete example plugin
│   ├── main.go
│   └── extension.json
└── README.md
```

Development flow: copy the template → implement `HandleRequest()` → `go build` → `asscor> source deploy`.

---

## 18. Algorithm Integrity Protection (`[integrity]`)

Controls ASSCOR's integrity protection for the SSAM/Prism core algorithms:

```ini
[integrity]
sign_assessment = true    # HMAC-SHA256 signing of assessment reports (guards against forged reports)
verify_algo = true        # Verify SSAM/Prism constant integrity at startup
anti_debug = false        # Linux anti-debug detection (must be enabled explicitly)
```

| Mode | Scenario |
|------|----------|
| `sign=false, verify=false` | Lightweight single-binary deployment |
| `sign=true, verify=true` | Protects against forged assessment reports + algorithm verification (recommended) |
| `anti_debug=true` | Additional anti-debugging for sensitive environments |

---

## Version History

- **v0.2.3** (2026-08-12) — Technical-debt cleanup: 80 items closed (87 → 7, 92%), all P0 issues cleared (19/19); kernel split across 17 interface/type files; 25 test files / 222 test cases / 5 benchmarks; engine-hook ↔ extension-point bridging (8 phases); unified SemVer; extmgr bridging (9 types); engine adapters re-homed; ATT&CK separated behind a build tag; 10+ nil-guard fixes; TLS and systemd deduplication; pkgmgr consolidation; multi-algorithm orchestration made optional; extension-package management (package.json + pkgmgr + SCHEMA)
- **v0.2.1** (2026-07-17) — Extension system covering the full lifecycle of 65 extension points (probe → respond → report → remediate → verify → archive); isPermDenied permission-detection enhancement (EACCES/EPERM); CLI terminal-context exit + done signal + goDecoder fix; conditional CLI log restoration + socket permissions tightened to 0660; deployment-module refactor (helpers extracted / dead code removed / systemd sync + waitForServiceHealthy); dead extension point `verify.status_changed` activated; asscor-cli passes through `ASSCOR_CLI_SOCKET`; multi-algorithm orchestration as an optional module (multi-algo-orchestrator, mounted on its own extension point); extension-package manager (pkgmgr, package.json dependency declarations, external git-repo references); optional/external extension directories (algorithms/adapters/checks/platform)
- **v0.2.0** (2026-07-07) — Single-binary installation (--install/--uninstall/--upgrade/--version); FHS layout (/etc/asscor, /var/lib/asscor, /var/log/asscor); systemctl management + SIGHUP hot reload; remote CLI (Unix socket, asscor-cli); PATH symlinks (/usr/bin/asscor); standalone mode with adapter dispatch + SRD three-layer analysis; SSAM V2 weighted-average scoring; persistence path fixes; agent heartbeat-frequency tuning; config-defined checks ([user_check]); external script adapters ([adapter_script]); Plugin SDK (pluginsdk/); algorithm-integrity protection ([integrity]); CLI diag/policy ops commands
- **v0.2.0** (2026-06-28) — CLI spc subcommands (score/kev/fetch); kernel console assessment reports (config.ini console_report); configurable agent log format (agent.ini log_format); `source deploy` command; ATT&CK version/priority fixes; config hot-reload on by default; management-adapter Parse upgrade; systemd service + Dockerfile
- **v0.1.4-mvp** (2026-06-09) — SSAM V2.0 three-layer semantic model; ATT&CK V19 module; SPC multi-source feeds (CNNVD/CNVD/MISP); extension manager; Prism SRD engine
- **v0.1.3-mvp** (2026-05-25) — gRPC/JSONRPC dual protocol stack; weight hot-reload; SPC disk persistence; adapter-integration module
- **v0.1.2** (2026-05-22) — HMAC-signature fix; PublishSync for critical messages; policy-manager mutual-exclusion switch; CTI severity-level weighting
- **v0.1.1** (2026-05-16) — Agent heartbeat mechanism; build artifacts unified under the build/ directory
- **v0.1.0** (2026-05-13) — Initial release
