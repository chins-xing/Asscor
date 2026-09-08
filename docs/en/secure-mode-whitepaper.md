# ASSCOR Secure Mode Whitepaper

> **Version:** v1.0 | **Applies to:** ASSCOR v0.2.3 (ASSCOR-Research-Core branch, build tag `securemode`) | **Date:** 2026-08-28
> **Companion documents:** [Secure Mode module design (SDD)](../superpowers/specs/2026-08-21-secure-mode-design.md), Engineering Implementation Whitepaper (§11 Micro-kernel Architecture), ASSCOR User Manual (Secure Mode chapter)
> **Module implementation:** `internal/securemode/` (23 files), build tag: `securemode`

---

## 1. Overview

Secure Mode provides the ASSCOR kernel (`config.ini`) and agents (`agent.ini`) with a **default**/**run** dual-mode model whose goal is the **at-rest security** of configuration files:

- **Default mode:** configuration files are stored in plaintext and can be edited directly — behavior is exactly that of the current release.
- **Run mode:** the configuration source file is encrypted into `.enc` (plaintext deleted) and the configuration contents are loaded into memory; modifying configuration via the CLI and exiting run mode both require the password, whereas entering run mode from default mode is **passwordless**.

The mode is **persistent state** (a marker file) that survives restarts: if the last session was in run mode, a password must be entered at the next startup to unlock. The security boundary is **"in run mode, config plaintext exists only in process memory"** — plaintext configuration never touches disk, so an attacker must breach process memory to obtain the configuration contents.

**Kernel/agent capability differences:**

- **Kernel:** full mode-management capability (CLI mode switching, configuration modification, password rotation).
- **Agent:** no runtime configuration capability is provided; the agent self-generates a temporary password at startup, reports it to the kernel over the mTLS connection, and **automatically enters run mode**; agent mode transitions **may be initiated only via the kernel CLI** — the agent's local CLI exposes no mode-switching commands (kernel-custodied mode).

> This module is an experimental module unique to the ASSCOR-Research-Core branch; default builds (without the `securemode` tag) compile to the same behavior as previous releases, and the main branch does not compile securemode.

---

## 2. Architecture

### 2.1 Module layout

A standalone `internal/securemode/` package that does not intrude on kernel/agent core code:

```
internal/securemode/
├── crypt.go        # AES-256-GCM envelope encryption + argon2id key derivation
├── state.go        # Mode state machine (default ↔ run) + marker-file persistence + startup/crash recovery
├── vault.go        # Config loading into memory, plaintext↔ciphertext conversion, target-file management, memory integrity
├── controller.go   # Mode controller: enter/exit/rotate/unlock/startup recovery/residue detection
├── cli.go          # CLI command registration (mode/config-set command family)
├── memguard.go     # Memory guard: SHA-256 baseline + read-only snapshot (runtime hardening)
├── password.go     # Password verifier file (argon2id hash, offline verification)
├── persist.go      # Registry encrypted persistence (P0-1)
├── registry.go     # Certificate-fingerprint → agent_id → password registry
├── securemode.go   # Constants and format definitions (magic "ASCM", format version 1)
└── *_test.go       # Per-component unit tests (incl. e2e combination tests)
```

### 2.2 Build-tag switch

Secure Mode is mounted with a **build-tag on/off** scheme (following the existing `assessor_on/off.go` pattern):

- `cmd/kernel/main.go` and `cmd/agent/main.go`: build-tag files `securemode_on.go` / `securemode_off.go`.
- **Default off:** compiling without the tag pulls in no securemode code; kernel/agent behavior is identical to previous releases (the zero-bloat minimal kernel is unaffected).
- **On:** `go build -tags securemode` compiles the full Secure Mode capabilities (CLI `mode`/`config-set` command family, agent custody, registry).

### 2.3 Mount points

- CLI: `internal/cli` registers the `mode` command family and the `config-set` subcommand.
- Agent side: `cmd/agent/main.go` mounts securemode's agent-custody logic (self-generated password, reporting, automatic entry into run mode); the agent's local CLI exposes only `mode status` (read-only).

### 2.4 Responsibility boundaries

| Component | Responsibilities | Not responsible for |
|---|---|---|
| **Kernel** | Full mode management (CLI switching / config changes / password rotation); maintains the password registry (persisted); instructs agents to switch; encryption of its own configuration | Encrypting inside agent processes; the agent local CLI |
| **Agent** | Self-generates a temporary password; encrypts/decrypts its own agent.ini; reports/requests passwords; executes mode instructions issued by the kernel; `mode status` (read-only) | Local mode switching / config modification; performs no authentication itself |
| **securemode package** | Cryptographic primitives; state machine and marker file; three-stage atomic transition; memory verification and hardening primitives; CLI command registration | Re-implementing authentication (reuses mTLS); policy arbitration between agent and kernel |

> **Authentication boundary:** securemode does **not re-implement any authentication**. Connection identity, the binding of agent_id to certificates, and revocation checks all reuse the existing mTLS identity system (`BindAgentCert`/`VerifyAgentCert`/`PeerCertFingerprintFromContext`). Securemode only maintains the password registry on top of it — **the password is unlock material, not an authentication credential**.

---

## 3. Cryptographic design

### 3.1 Envelope encryption (AES-256-GCM + argon2id)

```
Config plaintext ──AES-256-GCM──→ ciphertext .enc   (encrypted with a random data key DEK)
Password ──argon2id──→ derived key KEK
DEK ──AES-GCM(KEK)──→ envelope (DEK ciphertext, stored with the .enc header)
Verification: argon2id hash (wrong password → decryption fails → rejected)
```

- **DEK** (Data Encryption Key): 32 random bytes generated on every encryption, encrypts the config plaintext directly with AES-256-GCM (nonce prepended).
- **KEK** (Key Encryption Key): derived from the passphrase via **argon2id** (default parameters: time=1, memory=64 MiB, threads=4, keyLen=32) and used to encrypt the DEK — even if the KEK is compromised, only the DEK envelope is exposed; the plaintext is not decrypted.
- **Zeroization:** KEK/DEK buffers are zeroized immediately after use, shortening the keys' lifetime in memory.

### 3.2 `.enc` file format

File header + ciphertext payload:

| Field | Description |
|---|---|
| Magic `ASCM` (4 bytes) | Identifies Secure Mode encrypted files |
| Version (1 byte) | Current format version 1 |
| Salt (16 bytes) | argon2id salt |
| ArgonN / ArgonR / ArgonP / KeyLen (4 bytes each, big-endian) | argon2id parameters |
| Envelope | DEK ciphertext encrypted with KEK (AES-GCM) |
| Nonce | Envelope GCM nonce |
| Payload | Config plaintext encrypted with DEK (AES-GCM), GCM nonce prepended |

The `[bootstrap]` plaintext bootstrap section of agent.ini (kernel address, mTLS certificate paths, and other items required for connection) is **kept in plaintext** during encryption, while the remaining sections are encrypted — after an agent restart, the connection information can be read without a password, and the protected sections are then unlocked with the password delivered by the kernel.

### 3.3 Exact KDF parameter validation (malicious-file defense)

`Decrypt`/`Verify` perform **strict validation** of `.enc` headers and verifier files:

- **Version must == 1**; magic mismatch, truncation, or out-of-range fields → rejected.
- **The four KDF parameters must exactly equal `DefaultKDFParams()`** (N=1, R=64 MiB, P=4, KeyLen=32) — v1 files are written only by `Encrypt`, which always records the default parameters; any other value is attacker-controlled header input that could be exploited in argon2 (thread count narrowed to uint8 becoming <1 → panic) or OOM/CPU DoS (unbounded memory/time cost), and is therefore rejected before any derivation.
- File size is capped at `MaxConfigSize` (10 MiB).

> **Purpose:** prevent maliciously crafted `.enc`/verifier files from triggering panic, OOM, or CPU exhaustion (DoS) — the fail-closed semantic carried down to the file-parsing layer.

---

## 4. Crash safety

### 4.1 Three-stage atomic transition

The plaintext → ciphertext transition uses a **three-stage atomic transition**: a crash at any stage cannot lose the configuration.

```
1. Encrypt-and-write: plaintext → .enc.tmp (temp file) → fsync to disk
2. Verify: decrypt .enc.tmp with the in-memory key, compare byte-for-byte with the in-memory config (integrity check)
3. Commit: rename .enc.tmp → config.ini.enc (atomic replacement) → only now is the plaintext deleted
```

- The plaintext is fsynced once **before encryption** to guard against filesystem-cache loss.
- **OOM protection:** encryption runs in a streaming pipeline (bufio chunking — the file is never read whole); if an OOM crash occurs mid-encryption, the plaintext is unharmed (stage 3 was never reached).

### 4.2 Crash-residue detection

Startup detects residue states such as plaintext coexisting with `.enc`:

| Residue state | Determination | Handling |
|---|---|---|
| Plaintext + orphan `.enc.tmp` (crash in stage 1/2) | Plaintext is authoritative; tmp is inert garbage | Ignore `.enc.tmp`; start normally in plaintext mode |
| Plaintext + `.enc` (stage-3 crash window) | **Residue** | **Fail-closed**: refuse automatic handling; restore after manually validating `.enc` (delete the plaintext if valid, roll back to plaintext if invalid) |
| `.enc` only (no plaintext) | Run mode (locked) | Password required to unlock and load |

> `.enc` is the authoritative copy: content that decrypts and byte-for-byte matches the in-memory config counts as valid.

### 4.3 Fail-closed semantics

- Disk write failure (fsync/rename failure): abort the transition, current state unchanged, plaintext not deleted.
- Residue states that cannot be adjudicated automatically → refuse startup / refuse silent downgrade; prompt for manual handling.
- Corrupt mode marker (see §6) → refuse silent downgrade to plaintext mode.

---

## 5. Memory hardening

> **Scope:** the measures in this section are **runtime hardening** — **not tamper-resistance guarantees**. They raise the attack bar, slow down memory forensics, and increase the probability of detection, but they do not promise to hold against attackers with kernel-level privileges (root/kernel modules/physical memory access). The security model takes "in run mode, config plaintext appears in process memory only" as its boundary; the measures below make **reading/rewriting that plaintext harder and more detectable** — not impossible.

1. **SHA-256 baseline checksum:** when the config plaintext is loaded into memory, a SHA-256 baseline is computed; while in run mode, before every `config` read and every `mode exit`, the current in-memory content is re-hashed and compared against the baseline — if tampering is detected (injection/debugger rewriting) → refuse the operation and alert.
2. **Read-only snapshot:** in run mode the configuration is exposed through an immutable view (`config set` rebuilds a new snapshot through a controlled channel instead of mutating in place).
3. **Access restriction (hardening):** the in-memory plaintext region in run mode uses `mprotect(PROT_READ)` read-only pages (on Linux); the existing `integrity.IsDebugged()` anti-debug capability detects debugger attachment — both are hardening measures that reduce attacker convenience, not integrity guarantees.

---

## 6. Mode state machine

### 6.1 Kernel state machine

```
         mode enter (passwordless)
  default ─────────────────────→ run
     ↑                              │
     │      mode exit (password)    │
     └──────────────────────────────┘
        (decrypt .enc → restore plaintext → delete .enc)
```

| Transition | Precondition | Description |
|---|---|---|
| `mode enter` | Default mode | **Passwordless**; encrypts the source file (three-stage atomic transition), loads config into memory |
| `mode exit` | Run mode | **Password required**; decrypts and restores plaintext, deletes `.enc`, returns to default mode |
| `mode set-password` | Run mode | **Old password required**; two-stage rotation (verify old password → write new verifier → re-encrypt all vaults from memory; plaintext never written to disk) |
| `mode unlock` | run marker after restart | **Password required**; unlocks and loads the protected config into the memory guard (Ruling 3) |

### 6.2 Marker file (persists across restarts)

- Path: `data_dir/.asscor-mode` (contains version + mode + self-check hash; written atomically via tmp+rename).
- **Startup recovery:**
  - marker = default → normal plaintext startup
  - marker = run → prompt for password → decrypt `.enc` and load into memory → remain in run mode
  - no marker → default mode (first use)

### 6.3 corrupt ≠ missing (fail-closed)

| State | Meaning | Behavior |
|---|---|---|
| **Missing** | First use / run mode never entered | Start in default mode (no historical state to restore — safe) |
| **Corrupt** | Exists but cannot be parsed / fails validation (incl. hash-tamper detection) | **Fail-closed**: refuse silent downgrade to default mode (otherwise an attacker could damage the marker file to "knock" the system back into plaintext mode). Behavior: refuse startup or force the password-unlock flow, with the alert "mode marker corrupt, suspected tampering" |

The marker file carries a file-level checksum (SHA-256); any checksum failure counts as corrupt and takes the fail-closed branch.

### 6.4 Startup half-state check (M1 fail-closed completeness)

Startup performs a full consistency check over the combination "marker file × vault state × verifier file"; every half state (interrupted transition) is fail-closed:

- `default marker + .enc only + verifier present` → interrupted EnterRun (plaintext already deleted, marker not yet written back) → manual recovery.
- `default marker + .enc only + no verifier` → interrupted EnterRun (plaintext deletion preceded verifier-file write) → manual recovery.
- `run marker + no verifier` → interrupted EnterRun or tampering → fail-closed (run mode without password-verification material = cannot unlock; refuse startup).

---

## 7. CLI usage

### 7.1 Kernel CLI command table (full capability)

| Command | Description | Password |
|---|---|---|
| `mode status` | View current mode, protected files, verification status, registered agents | — |
| `mode enter --password <pw>` | default→run: encrypt the source file, load config into memory | Passwordless (a run password must already be set) |
| `mode exit --password <pw>` | run→default: decrypt and restore plaintext | **Required** |
| `mode unlock --password <pw>` | After a kernel restart (run marker), unlock and load the config | **Required** |
| `mode set-password --old <pw> --new <pw>` | Set/rotate the run password (config.ini and registry re-encrypted in sync) | Old password required |
| `mode agent <id> status` | View an agent's current mode/registration status | — (kernel authority) |
| `mode agent <id> enter` | Instruct an agent to encrypt and enter run mode (idempotent if already entered) | — (kernel authority) |
| `mode agent <id> exit` | Instruct an agent to decrypt back to default mode | — (kernel authority) |
| `mode agent <id> rotate-password` | Instruct an agent to rotate its password and re-encrypt | — (kernel authority) |
| `config-set <key> <value> --temp\|--persist [--password <pw>]` | Modify configuration (see 7.3) | Required in run mode |

### 7.2 Agent local CLI (restricted)

| Command | Description |
|---|---|
| `mode status` | Read-only view of the current mode (kernel-custodied; cannot switch locally) |
| `--mode-status` | One-shot query flag (`cmd/agent/main.go`) for querying mode state in non-interactive environments |

The agent local CLI provides **no** mutation capability — no `mode enter/exit/set-password`, no `config-set`, etc. — configuration changes and mode transitions are always issued through the kernel CLI.

### 7.3 `config-set` two-stage persistence

```
config-set <key> <value>
  ├── --temp    (default): modifies memory + takes effect immediately, nothing written to disk; reverts to the on-disk value after restart
  └── --persist: modifies memory + writes to disk (plaintext in default mode / encrypted in run mode);
                 does not take effect immediately — requires a manual config reload to re-load
```

- In default mode there is no securemode-held in-memory config: `config-set` needs `--persist` to edit the plaintext file.
- In run mode a modification is committed only after the memory snapshot passes the integrity check (tamper detection).

> **I-1 runtime write-back:** after `config-set`/`mode unlock` modifies the in-memory config in run mode, the change is written back into the running kernel through the `ModeCLI.OnConfigChanged` hook (`config.Parse` → `SetConfigObj` + `assessor.ReloadConfig`), so `--temp` takes effect immediately; via `SetConfigLoader`, the config watcher reads the memory guard in run mode, so SIGHUP/polling reloads cannot bypass the encrypted config.

---

## 8. Kernel custody of agents

### 8.1 Lifecycle

```
Agent startup (on-disk agent.ini is plaintext .ini + [bootstrap] bootstrap section)
  │
  ├─ Read the plaintext bootstrap section (kernel address, mTLS cert paths, and other connection essentials)
  ├─ Connect to the kernel (mTLS)
  ├─ Self-generate a random temporary password (regenerated at every restart; never written to disk, memory only)
  ├─ Encrypt agent.ini → agent.ini.enc (three-stage atomic transition), delete the plaintext
  ├─ Report the password to the kernel over the mTLS heartbeat (the kernel registers
  │    agent_id → password keyed by the requesting certificate's fingerprint; forged
  │    registrations with a mismatched fingerprint are rejected at the transport layer)
  └─ Automatically enter run mode (config resident in memory: read-only snapshot + SHA-256 baseline)
```

- **Password lifecycle:** an agent password is an **ephemeral unlock secret**, not a long-term secret — it unlocks only the `.enc` of the current run session, its lifetime is bound to a single process run, and it naturally rotates on restart. Agents store **no password material on disk**.
- **Agent-restart unlock:** on restart the agent reads the plaintext bootstrap section and connects to the kernel → the kernel delivers the password currently registered for that agent → the protected section is decrypted → run mode is entered (the agent has no interactive state machine of its own; its state is driven by the kernel).

### 8.2 Instruction channels

- **Unlock password delivery:** via the **heartbeat-response channel** (signals such as `HeartbeatResponse.SecureModeNoSecret`) — a locked agent has no `hmac_key` and therefore cannot validate pending commands, so unlock-type instructions do not depend on the command channel.
- **exit / rotate-password:** delivered via the **pending-command channel** (`securemode_exit` / `securemode_rotate`); after exit, `reloadProtectedConfig` restores the `hmac_key` and command-validation capability.

### 8.3 Self-recovery (I-2)

Locked-state self-recovery of an agent: **three unanswered heartbeats** or a `SecureModeNoSecret` signal → self-generate a new password + `Vault.ReencryptOverwrite` re-encrypts the `.enc` (without reading the old `.enc`) + re-report with `reported=false`; the old protected contents are discarded per spec §8.2. Equivalent to a fresh registration.

### 8.4 Authentication boundary

- The certificate fingerprint for registration/unlock/switch requests is taken from `kernel.PeerCertFingerprintFromContext(ctx)` — the same mechanism as the existing identity hardening of Register/Heartbeat.
- The kernel **first verifies that the fingerprint carried by the request is already registered** — if an attacker forges an agent_id and reports a password whose certificate fingerprint does not match the registry, the kernel rejects that "illegal registration" request at the transport layer, never reaching application logic.
- **One certificate, one identity:** a certificate may register exactly one agent identity, consistent with the existing `BindAgentCert` constraint.

---

## 9. Registry persistence (P0-1)

The kernel maintains a **`certificate fingerprint (SHA-256 hex) → agent_id → password`** triple registry:

- **Key structure:** the mTLS client certificate fingerprint is the primary key, with agent_id and password under it — not merely `agent_id → password` (the defense line is pushed from the application layer down to the transport layer).
- **Persistence:** the registry is stored **in encrypted form** (`data_dir/.asscor-secrets.enc`, envelope-encrypted with the kernel's own run-mode key).
  - Kernel in **run mode**: the registry is persisted encrypted.
  - Kernel in **default mode**: the registry is not persisted (no agent is expected to be in run mode then).
- **Kernel-restart recovery:**
  1. Kernel starts → reads its own mode marker:
     - Kernel **default**: registry empty; each agent follows the "restart → self-generate new password → re-report" flow.
     - Kernel **run**: unlock with the kernel password → decrypt the persisted registry → restore the `fingerprint → agent_id → password` triples.
  2. After the kernel recovers the registry, an agent in run mode that restarts can be given its password to unlock; if the agent has already regenerated its password (it restarted first while the kernel registration was still valid), the kernel's registered version is authoritative (agent reports overwrite older registrations, ordered by requesting fingerprint + timestamp).
  3. **Deadlock guard:** if, after a kernel restart, registry persistence/decryption fails (fail-closed) → the kernel **refuses to start run mode**, and an already-persisted registry is **not deleted** — a manual remediation path (recover with the kernel password).
- **Agent-only restart (kernel not restarted):** the agent self-generates a **new** password on restart and reports it → the kernel updates the registration under that fingerprint (new password overwrites the old) → unlock requests tied to the old password become invalid immediately.
- **Password-rotation linkage:** when the kernel's `mode set-password` rotates, the registry (`.asscor-secrets.enc`) is re-encrypted in sync with the new run key; exiting run mode removes the registry file.

---

## 10. Build and deployment

### 10.1 Build commands

A default build (no tag) contains no securemode and behaves identically to previous releases:

```bash
go build ./cmd/kernel ./cmd/agent
```

Enable full Secure Mode capabilities:

```bash
go build -tags securemode ./cmd/kernel ./cmd/agent
```

Combined with all product-module tags (full-feature kernel):

```bash
go build -tags "securemode,heartbeat,commander,policy,cti,assessor,attck_ext,spc,collector,sourcemanager,persistence,srdwrapper,integrity,resilience,comms,checks,adapter,engine" -o ASSCOR-kernel ./cmd/kernel/
```

### 10.2 Deployment notes

- **Protected files:** kernel `config.ini` (path of the `-config` argument); agent `agent.ini` (path of the `-config` argument; only the protected sections are encrypted — the `[bootstrap]` plaintext bootstrap section is preserved).
- **Run-mode disk layout** (under data_dir):
  - `.asscor-mode` — mode marker (survives restarts)
  - `.asscor-pw` — password verifier file (argon2id hash + KDF parameters)
  - `.asscor-secrets.enc` — agent registry (encrypted persistence; run mode only)
  - `<config>.enc` — encrypted configuration file (plaintext deleted)
- **Restart unlock:** under a run marker, the kernel executes `mode unlock --password <pw>` after startup to unlock and load the config before the service continues (Ruling 3).
- **Upgrade/downgrade:** exit run mode (`mode exit`) to restore plaintext, then upgrade normally; re-run `mode enter` afterwards if encryption is still desired.
- **Manual remediation path:** fail-closed scenarios — crash residue / corrupt registry / corrupt marker — keep the on-site files (plaintext backup or `.enc`) and are validated and restored manually per §4/§6/§9; no file that may carry configuration is ever deleted automatically.

---

## 11. Security model summary

| Threat surface | Protection | Standing |
|---|---|---|
| Static theft of config files (disk read / backup theft) | AES-256-GCM envelope encryption + argon2id | **Guarantee** (security boundary: plaintext only in process memory) |
| Password brute force | argon2id memory-hard KDF (64 MiB) + reject on wrong password | Raises cost |
| Malicious `.enc`/verifier files (panic/OOM/CPU DoS) | Exact KDF-parameter + version validation, size cap | Fail-closed rejection |
| Crash losing configuration | Three-stage atomic transition + fsync + residue detection | A crash at any stage loses no config |
| Marker-file tamper downgrade | corrupt ≠ missing; fail-closed refuses downgrade to plaintext | Detect and block |
| Reading plaintext from process memory | mprotect read-only pages + anti-debug + SHA-256 baseline | **Runtime hardening, not a tamper-resistance guarantee** |
| Forged agent registration | Certificate-fingerprint primary key + transport-layer check | Defense pushed down to the transport layer |

> **Non-goals (YAGNI):** no TPM/system-keyring integration; no multi-user password system (the single password is the only unlock path); no encrypted-config sync between agent and kernel (agent config is protected independently); no re-implementation of authentication (reuses mTLS); no in-memory tamper-resistance guarantee; agent passwords are not long-term credentials.

---

## 12. References

- [Secure Mode module design (SDD, 2026-08-21)](../superpowers/specs/2026-08-21-secure-mode-design.md)
- README.md — "Secure Mode (experimental, build tag: securemode)" section
- Engineering Implementation Whitepaper §11 Micro-kernel Architecture (§11.3 plugin table, securemode row)
- ASSCOR User Manual — "Secure Mode" chapter (operator's-manual perspective)
