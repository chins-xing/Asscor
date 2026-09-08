# ASSCOR — Security Acceptability Assessment Runtime

> **Branch:** `ASSCOR-Research-Core` (research-specialized branch; not merged
> into `main`).
>
> This branch carries two research directions on top of the stable main
> baseline (v0.2.x):
> - **Topology / propagation research** — M0–M2 milestones (graph-model
>   foundation → lifecycle → semantic propagation); see
>   [docs/ASSCOR-Research-Core.md](docs/ASSCOR-Research-Core.md) and
>   `lunwen/research-core/`;
> - **Secure Mode** — an experimental module behind the `securemode` build
>   tag (see the Secure Mode chapter below).
>
> Difference from `main`: this branch contains the `securemode` experimental
> module and topology-research assets; `main` does not. When the research
> matures it flows back to `main` as documentation / a standalone module.

> **ASSCOR** (**ASS**ess + **COR**e) is an open-source, production-oriented
> security acceptability assessment platform. It does **not** replace
> vulnerability scanners, SIEMs, or penetration testing. Instead, it sits
> **above** those systems as an aggregation and judgment layer for
> *"security acceptability"*, giving operators a business-risk-oriented,
> unified view of every monitored host.
>
> Two algorithmic engines power it:
> - **SSAM 2.0** (System Security Acceptability Model) — a multi-dimensional,
>   computable assessment formula;
> - **Prism / SRD** (Systemic Risk Dynamics) — a three-layer risk-propagation
>   and prediction engine.

**Algorithm version:** SSAM 2.0 · **Project version:** v0.2.x
**License:** [Apache License 2.0](LICENSE)

> ⚠️ **0.x disclaimer:** until 1.0.0, ASSCOR may introduce breaking changes
> (configuration, CLI, interfaces, data formats). No stability or
> compatibility guarantee is made for any 0.x release.

> ⚠️ **The fundamental caveat.** SSAM is a *mathematical model*. A score is an
> **approximation, not ground truth**. A host scoring 85 is not necessarily
> more secure than one scoring 72. The score reports measurable dimensions
> *inside the model's framework* — not the whole of security. Context,
> attacker motivation, administrator vigilance, and unknown zero-days escape
> every formula. **We design models; we do not design reality.**
> Use the score as decision support, never as the decision itself.
> (Goodhart's law applies to security scores exactly as elsewhere.)

---

## Table of contents

1. [What ASSCOR is](#1-what-asscor-is)
2. [Platform architecture](#2-platform-architecture)
3. [The SSAM 2.0 engine](#3-the-ssam-20-engine)
4. [Acceptable-Compromise Indicators (ACI)](#4-acceptable-compromise-indicators-aci)
5. [Security Posture Calculator (SPC)](#5-security-posture-calculator-spc)
6. [Threat coefficient μ](#6-threat-coefficient-)
7. [Prism / SRD risk-dynamics engine](#7-prism--srd-risk-dynamics-engine)
8. [Adapting to graded protection frameworks](#8-adapting-to-graded-protection-frameworks)
9. [Dynamic extensions](#9-dynamic-extensions)
10. [Secure Mode (experimental, build-tag: securemode)](#10-secure-mode-experimental-build-tag-securemode)
11. [Build & quick start](#11-build--quick-start)
12. [Repository structure](#12-repository-structure)
13. [Documentation](#13-documentation)
14. [Known limitations](#14-known-limitations)
15. [License & community](#15-license--community)

---

## 1. What ASSCOR is

ASSCOR continuously assesses the **security acceptability** of every
monitored host — always watching, never blinking. Its core engine SSAM 2.0
introduces:

- **Four mutually exclusive core domains**, eliminating double scoring;
- **Edge factors** applied as multiplicative corrections when advanced
  protection is missing;
- **A dynamic threat coefficient** fed by live intelligence, so results
  track the evolving threat environment;
- **Fully administrator-customizable** weights, thresholds, and checks;
- **A strengthened resilience dimension** with Acceptable-Compromise
  Indicators (ACI) quantifying *survivability after partial compromise*;
- **A Security Posture Calculator (SPC)** localizing global vulnerability
  intelligence into a per-host posture correction;
- **Graded-protection framework mapping** (GB/T 22239-2019 and similar) with
  two-way compliance ↔ capability translation.

## 2. Platform architecture

ASSCOR follows a **microkernel + plug-in** architecture, communicating over a
**gRPC + JSONRPC dual protocol stack** with optional mTLS encryption. The
**Kernel** coordinates assessment and dispatches commands; the **Agent** runs
local checks and reports state.

| Component | Role |
|-----------|------|
| **Kernel** | Microkernel runtime: DI container, event bus, circuit breakers, interceptor chain, plug-in lifecycle |
| **Assessment engine** | SSAM V2.0 weighted scoring + SPC posture correction + ATT&CK V19 threat analysis |
| **Agent** | Concurrent execution of ~80 checks, automatic CPE generation, HMAC-signed command execution |
| **Adapters (21)** | Trivy / Nuclei / Lynis / Suricata / … via a Fetch → Parse → Map → Validate pipeline |
| **Prism / SRD** | Three-layer risk engine: Core (dynamic score) → Semantic (four-state fuzzy) → Inference (Markov prediction) |
| **Extension system** | 89 kernel extension points (83 platform + 6 lifecycle) + extmgr types + optional extension packages (pkgmgr + package.json) |
| **Microkernel separation** | The kernel keeps only the extension framework + lifecycle + interface contracts; **every functional module is a build-tag-gated plug-in** (zero-bloat default build) |
| **Security hardening** | HMAC assessment signing, self-calibrating algorithm-integrity checks, SHA-256 binary verification, mTLS |
| **CLI** | Interactive terminal + Unix-socket remote connection + operational commands with permission levels |
| **Deployment** | Single-binary install/upgrade/uninstall, systemd, Docker, FHS layout |

All functional modules are compiled in only when their build tag is enabled
(`heartbeat`, `commander`, `policy`, `cti`, `assessor`, `attck_ext`, `spc`,
`collector`, `sourcemanager`, `persistence`, `srdwrapper`, `integrity`,
`resilience`, `comms`, `checks`, `adapter`, `engine`, `securemode`, …).
The default kernel build carries only the core runtime.

## 3. The SSAM 2.0 engine

### 3.1 Four mutually exclusive core domains

| Domain | Core question | Typical checks |
|--------|---------------|----------------|
| Attack surface | Is the passive defense surface minimized? | Unused services off, non-essential ports silent, strong auth, SSH hardening |
| Business continuity | Do security policies hurt business operation? | Critical service state, business-port reachability, resource headroom, backups |
| Operation trust | Are configuration and operations tamper-proof and auditable? | Key file permissions, audit logs, command-history integrity, supply-chain integrity, MAC |
| Resilience | Can core defenses hold under sustained pressure / partial compromise? | Auto-blocking precision, kernel hardening params, connection limits, degradation policy, ACI |

Each domain scores 0–100; all checks are **mutually exclusive**, so one
weakness is never penalized twice. The engine runs a conflict check at load
time to guarantee disjointness (e.g. SSH port/password policy belongs only to
Attack Surface; SSH *audit-log integrity* belongs to Operation Trust).

### 3.2 Edge factors (multiplicative corrections)

Some global capabilities cannot be attributed to a single domain, yet their
absence weakens overall security. Edge factors apply as multiplicative
corrections.

> **SSAM 1.3 → 2.0 change:** supply-chain validation, auto-blocking, and
> resource pressure moved into their core-domain checks (OT-004, RS-003,
> BC-003) to remove double scoring. SYN Cookie remains an edge factor (it is a
> network-layer global control). SSAM V2.0 introduces the three-layer
> semantic model (intrinsic / exposure / threat), replacing the legacy
> ThreatCoeff + SPCScore double-penalty mechanism.

| Independent property | Factor when missing | Note |
|----------------------|--------------------:|------|
| Two-factor auth missing | ×0.85 | EF-002FA |
| SYN Cookie disabled | ×0.75 | network-layer global control (EF-SYNCOOKIE) |
| SELinux disabled | ×0.80 | MAC missing (EF-SELINUX) |
| AppArmor disabled | ×0.82 | MAC missing (EF-APPARMOR) |
| No SIEM integration | ×0.90 | EF-NO-SIEM |
| No IDS/IPS | ×0.88 | EF-NO-IDS |
| Level-4 (3FA) not met | ×0.82 | cascade override of EF-002FA (EF-3FA, CascadeOnly) |

All values are administrator-tunable. Factors and weights support
per-node-label/group overrides; unset entries inherit the global default.
Enabling the graded-protection Level-4 framework auto-loads
`edge_factors.level4_override`.

### 3.3 Assessment formula

```
SSAM_final = ( Σ(S_i × W_i) / ΣW_i ) × Π M_j × μ × P_score
```

- `S_i` — core-domain score (0–100)
- `W_i` — domain weight; defaults: attack_surface 35, business_continuity 25,
  operation_trust 25, resilience 15
  - the engine normalizes by `ΣW_i` when weights do not sum to 100, so
    scoring is insensitive to configuration error
- `M_j` — independent edge factor (0.0–1.0)
- `μ` — threat coefficient (0.60–1.00)
- `P_score` — SPC per-host posture correction (0.60–1.00)

The acceptability threshold `T` is administrator-set (default 80); the state
is *acceptable* when `SSAM_final ≥ T`.

## 4. Acceptable-Compromise Indicators (ACI)

Traditional resilience asks how well a system resists attack — but "never
compromised" is unrealistic. SSAM 2.0 adds **ACI** to the resilience domain:
once part of the system *is* compromised, can damage be contained within
acceptable bounds while core business keeps running? ACI (post-breach) and
anti-stress resilience (pre-breach) are complementary and non-overlapping.

Assessment dimensions: isolation capability, least-privilege effectiveness,
data protection (encryption, offline tamper-proof backups), recovery ability
(MTTR), and audit-trail retention. ACI assumes the attacker already holds
basic access to a component and measures how far the damage spreads.
Check deductions (network-segmentation −15, unique local-admin passwords −10,
offline backup integrity −20, EDR −10, remote audit-log mirroring −10,
application whitelisting −10, DLP −5, …) are applied directly inside the
resilience-domain 0–100 scale and are fully configurable.

## 5. Security Posture Calculator (SPC)

SPC bridges the gap between *global vulnerability intelligence* and *actual
risk on one host*: it continuously tracks authoritative vulnerability feeds,
combines them with the local asset inventory, and emits a per-host posture
correction vector.

- **Tier-1 feeds:** NVD, CNNVD, CNVD.
- **Tier-2 feeds:** EPSS (exploit prediction), CISA KEV (known exploited).
- **Tier-3 inputs:** per-host software inventory, services, ports, topology
  collected by agents.
- **SPC penalty** uses the root-sum-square form `√ΣPenalty²` rather than a
  linear sum, so a pile of low-severity CVEs cannot bottom out a score too
  early.

## 6. Threat coefficient μ

By integrating threat intelligence (OTX, MISP, …) the system maintains a
real-time coefficient `μ ∈ [0.60, 1.00]` (default 1.00). It is lowered when
high-severity vulnerabilities or active attacks appear, immediately affecting
the assessment of every managed host.

## 7. Prism / SRD risk-dynamics engine

Prism propagates risk over the network graph in three layers:

- **Core layer** — dynamic per-host scoring and propagation with debt decay
  and collapse modifiers;
- **Semantic layer** — trapezoidal/triangular membership functions mapping
  the Core score to a four-state fuzzy vector
  `[μ_Stable, μ_Degraded, μ_Untrusted, μ_Collapse]`;
- **Inference layer** — a Markov-chain predictor over a 4×4 expert-prior
  transition matrix, with N-step forecasts (default 30 days) and collapse
  detection (collapsing trend → collapse probability).

Both engines are published as standalone, zero-dependency Go modules:

| Engine | Role | Location |
|--------|------|----------|
| SSAM 2.0 | per-host acceptability score | `ssam-lib/` · github.com/chins-xing/ssam |
| Prism / SRD | three-layer risk propagation | `prism-lib/` · github.com/chins-xing/prism |

ASSCOR delegates to these libraries through thin adapters.

## 8. Adapting to graded protection frameworks

ASSCOR maps security capabilities onto graded-protection requirements
(GB/T 22239-2019 levels 2–4 and similar). The mapping is bidirectional:
checks that satisfy a compliance item surface their corresponding security
capability, and framework configuration adjusts weights / thresholds / edge
factors automatically. Eight industry configuration templates ship under
`configs/` (government, finance, healthcare, education, enterprise, …).

## 9. Dynamic extensions

The kernel exposes 89 extension points (83 platform + 6 lifecycle). The
extension manager (`extmgr`) supports nine extension types under a four-tier
execution policy (with command allowlists, SHA-256 checksums, timeouts, and
path protections). Extension *packages* (pkgmgr) can be distributed and
installed as self-contained bundles with a `package.json` manifest.

## 10. Secure Mode (experimental, build-tag: securemode)

> This branch-only experimental module (`internal/securemode/`) protects the
> static security of `config.ini` and `agent.ini`. Design & implementation
> records: [docs/superpowers/specs/2026-08-21-secure-mode-design.md](docs/superpowers/specs/2026-08-21-secure-mode-design.md);
> summary below.

### Features

- **Dual modes:** default (plaintext config files, behavior unchanged) / run
  (source files encrypted to `.enc`).
- **Envelope encryption:** AES-256-GCM envelope encryption + argon2id
  password derivation; entering run mode needs no password, modifying config
  via CLI or exiting run mode requires the password.
- **Agent managed by kernel:** on startup the agent self-generates an
  ephemeral password (regenerated each restart, never persisted), reports it
  to the kernel over the mTLS heartbeat, and automatically enters run mode;
  mode switches are kernel-initiated only
  (`mode agent <id> enter|exit|rotate-password`).

### Build

Default builds exclude securemode (no-tag builds behave exactly as before):

```bash
go build -tags securemode ./cmd/kernel ./cmd/agent
```

### CLI usage

| Command | Description |
|---------|-------------|
| `mode status` | current mode + per-config state + registered agents |
| `mode enter --password <pw>` | enter run mode (no password check; run password must be set) |
| `mode exit --password <pw>` | exit to default mode (restore plaintext) |
| `mode unlock --password <pw>` | after a kernel restart (run marker), unlock and load the config |
| `mode set-password --old <pw> --new <pw>` | rotate the run password (config.ini + registry re-encrypted) |
| `mode agent <id> status\|enter\|exit\|rotate-password` | agent management: status / instructions |
| `config-set <key> <value> --temp\|--persist --password <pw>` | modify config: `--temp` in-memory immediate / `--persist` to disk (needs reload) |

### Security design

- **Crash safety:** three-stage atomic conversion (write `.enc.tmp` → verify
  round-trip → rename → delete plaintext); a crash at any step loses no
  config; startup auto-detects crash residue (plaintext + `.enc` coexist →
  fail-closed, manual `.enc` validation then recovery).
- **Memory hardening:** run-mode config lives in memory (read-only snapshot +
  SHA-256 baseline + mprotect hardening) — hardening, not a tamper-proof
  guarantee.
- **Fingerprint-keyed registry:** agents register under their mTLS
  certificate fingerprint; a locked agent can still be unlocked after
  restart with its registered password.
- **Registry persistence:** the kernel persists the
  `fingerprint → agent_id → password` registry encrypted with the run-mode
  key (`.asscor-secrets.enc`), auto-decrypts it on run-mode restart, re-
  encrypts on password rotation, and removes it when leaving run mode.
- **Fail-closed:** a missing mode marker ≠ a corrupt one; a corrupt marker
  refuses to silently degrade to plaintext mode (possible tampering).

### Research paper

This branch also hosts the manuscript **"Attacker Cognitive Loop: An
Interpretable Rule-Based Engine for Estimating, Predicting, and Engaging
Adaptive Attackers"** (Jiahao Lai) in `lunwen/paper/`, together with the
24-node Containerlab experiment campaign (E1–E9) and its reviewer
attachment bundle. See the paper's own documentation for details.

## 11. Build & quick start

Requirements: Go ≥ 1.26. Builds are fully cross-compilable (`GOOS=linux`,
CGO_ENABLED=0).

```bash
# build the default kernel + agent
go build ./cmd/kernel ./cmd/agent

# build with all functional modules (incl. securemode on this branch)
go build -tags "heartbeat,commander,policy,cti,assessor,attck_ext,spc,collector,sourcemanager,persistence,srdwrapper,integrity,resilience,comms,checks,adapter,engine,securemode" ./cmd/kernel ./cmd/agent

# run the test suite
go test ./...
```

Single-binary deployment (systemd + FHS + PATH) is supported:

```bash
sudo ./ASSCOR-kernel-linux-amd64 --install            # install kernel as a systemd service
sudo ./ASSCOR-agent-linux-amd64 --install             # install agent on a target host
asscor-cli                                             # connect to the kernel CLI
```

See the [User Manual](docs/ASSCOR%20%E4%BD%BF%E7%94%A8%E6%89%8B%E5%86%8C.md)
(Chinese) for the full operational guide.

## 12. Repository structure

```
.
├── cmd/                 # binaries: kernel, agent, asscor (tag-gated)
├── internal/            # kernel + core modules (build-tag gated)
│   ├── kernel/          # microkernel core (DI, bus, lifecycle, contracts)
│   ├── engine/          # SSAM + SRD adapters
│   ├── securemode/      # Secure Mode module (tag: securemode, this branch)
│   ├── comms/           # gRPC + JSONRPC servers (tag: comms)
│   ├── agent/           # agent runtime (checks, CPE, heartbeat)
│   ├── cli/             # interactive + socket CLI
│   └── …                # heartbeat, commander, policy, cti, spc, extmgr, …
├── ssam-lib/            # SSAM 2.0 standalone engine (zero external deps)
├── prism-lib/           # Prism / SRD standalone engine (zero external deps)
├── optional/            # build-tag plug-ins (adversary packages, pkgmgr)
├── api/v1/              # protocol messages (pure PB; gRPC bindings are tag-gated)
├── configs/             # industry configuration templates
├── deploy/              # Makefile, docker compose, deployment scripts
├── docs/                # documentation (see §13)
├── lunwen/              # paper assets (this branch; reviewer-facing parts tracked)
└── build/               # local build output (git-ignored)
```

## 13. Documentation

| Document | Language | Content |
|----------|----------|---------|
| [README_EN.md](README_EN.md) | English | this overview |
| [README.md](README.md) | Chinese | full Chinese overview |
| [docs/README_EN.md](docs/README_EN.md) | English | documentation index |
| [docs/README.md](docs/README.md) | Chinese | documentation index |
| [docs/en/engineering-whitepaper.md](docs/en/engineering-whitepaper.md) | English | engineering implementation whitepaper |
| [docs/en/user-manual.md](docs/en/user-manual.md) | English | user manual |
| [docs/en/ssam-interface-spec.md](docs/en/ssam-interface-spec.md) | English | SSAM interface specification |
| [docs/en/srd-whitepaper.md](docs/en/srd-whitepaper.md) | English | SRD risk-dynamics whitepaper |
| [docs/en/secure-mode-whitepaper.md](docs/en/secure-mode-whitepaper.md) | English | Secure Mode whitepaper |
| Secure Mode design spec (`docs/superpowers/specs/2026-08-21-secure-mode-design.md`) | Chinese | module design & security model |

Chinese remains the primary documentation language for the in-depth
originals; English versions are maintained alongside.

## 14. Known limitations

- 0.x breaking changes are possible (see disclaimer above).
- SSAM scores are model outputs, not objective security truth — always treat
  them as decision support (Goodhart's law).
- Adapters requiring external tools (Trivy, OpenSCAP, …) need those binaries
  installed on the target host.
- The default build intentionally disables optional modules (integrity
  algorithm verification, HMAC signing, resilience guards, securemode, …):
  enable the corresponding build tags for a hardened deployment.
- Research-branch artifacts (Secure Mode, topology research, the ACL paper)
  are experimental and may change without notice.

## 15. License & community

Apache License 2.0 — see [LICENSE](LICENSE).

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines. The project is authored and maintained by Jiahao Lai
(<chins-xing@proton.me>). The goal is to reach a community-ready state and
then open collaboration on the Apache-2.0 codebase.
