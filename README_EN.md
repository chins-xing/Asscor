# ASSCOR — Security Acceptability Assessment Runtime

> **ASSCOR** (**ASS**ess + **COR**e) is an open-source, production-oriented
> security acceptability assessment platform.
> It does not replace vulnerability scanners, SIEMs, or penetration testing;
> instead, it serves as the **"security acceptability" aggregation and
> judgment layer** above those systems, providing a business-risk-oriented
> unified view of every monitored host.
>
> ASSCOR embeds two core algorithmic engines:
> - **SSAM 2.0** (System Security Acceptability Model) — a multi-dimensional
>   computable assessment formula
> - **Prism / SRD** (Systemic Risk Dynamics) — a three-layer risk propagation
>   and prediction engine

**Algorithm version:** SSAM 2.0 | **Project version:** ASSCOR v0.2.3
**Date:** 2026-08-16 | **Status:** released
**License:** [Apache License 2.0](LICENSE)

> ⚠️ **v0.x disclaimer:** until 1.0.0, ASSCOR may introduce breaking changes
> (config, CLI, interfaces, data formats). The author provides no stability or
> compatibility guarantee for any 0.x release.

---

## 1. What is ASSCOR?

ASSCOR continuously assesses the **security acceptability** of each monitored
host. A score is **a model's judgment, not ground truth** — see the SSAM
caveat below. The platform is built as a **microkernel** with optional
build-tag modules: the kernel keeps only the extension framework (dependency
injection, event bus, extension registry, plugin lifecycle); all functional
modules are plugins.

Two engines are published as standalone zero-dependency Go modules:

| Engine | Role | Location |
|--------|------|----------|
| **SSAM 2.0** | per-host acceptability score σ ∈ [0,100] | `ssam-lib/`, github.com/chins-xing/ssam |
| **Prism / SRD** | three-layer risk propagation over the network graph | `prism-lib/`, github.com/chins-xing/prism |

### SSAM 2.0 formula (summary)

```
final = (intrinsic × 0.5 + exposure × 0.3 + threat × 0.2) × 100
intrinsic = Σ(domain scores × weights) / Σ weights × edge factor
```

Domain weights: attack_surface 40, business_continuity 25, operation_trust
25, resilience 15, kernel_security 10.

**Caveat.** SSAM is a mathematical model. A score of 85 does not mean a host
is more secure than one with 72; it reports measurable dimensions inside the
model's framework. Do not turn the score into a target (Goodhart's law):
use it as decision support, never as the decision itself.

### SRD (Systemic Risk Dynamics)

SRD propagates risk over the network graph with **weighted transmission**:
`base × (0.1 + 0.9 × (100 − SSAM)/100)` — high-risk sources propagate nearly
fully (focus), low-risk sources decay to a 10% floor (noise suppression).
This feeds the risk view consumed by the assessment pipeline.

---

## 2. Repository structure

```
F:\Argus
├── ssam-lib/      # SSAM 2.0 standalone engine (zero external deps)
├── prism-lib/     # Prism/SRD standalone engine (zero external deps)
├── internal/      # kernel + core modules
│   ├── attackerstate/   # ACL: attacker state engine
│   ├── predictor/       # ACL: action distribution predictor
│   ├── engagement/      # ACL: engagement planner (utility + decoy catalog)
│   └── defensecycle/    # ACL: closed-loop controller (contain/collect/engage)
├── optional/      # build-tag plugins (17 modules)
├── cmd/           # binaries (kernel, agent, exprunner, decoyd, tracecheck)
├── docs/          # project development docs (kept in-repo)
└── lunwen/        # PAPER ASSETS — not tracked by git
    ├── paper/           # LaTeX/MDPI manuscript + markdown source
    ├── attachment/      # experiment data, manual, whitepaper EN, README_EN
    ├── clab-lab/        # 24-node Containerlab topology + experiment JSONL
    ├── references/      # cited papers (TXT/PDF)
    └── research-core/   # research-core markdown material
```

---

## 3. The paper: Attacker Cognitive Loop (ACL)

The manuscript **"Attacker Cognitive Loop: An Interpretable Rule-Based Engine
for Estimating, Predicting, and Engaging Adaptive Attackers"** lives in
`lunwen/paper/`. It proposes a **guided** (rather than blocking)
active-defense paradigm: a closed loop that

1. **estimates** the attacker's cognitive state from evidence,
2. **predicts** the next action as a probability distribution,
3. **selects** deceptive interventions by an explicit utility function,
4. switches between **contain / collect / engage** based on decision
   sharpness (normalized entropy of the predicted distribution).

### How the paper relates to ASSCOR

| Paper component | ASSCOR implementation |
|-----------------|------------------------|
| Attacker state engine | `internal/attackerstate/` |
| Action predictor | `internal/predictor/` |
| Engagement planner | `internal/engagement/` |
| Closed-loop controller | `internal/defensecycle/` |
| Host platform (SSAM/SRD inputs, topology) | ASSCOR kernel + SSAM 2.0 + Prism/SRD |
| Experiment harness | `cmd/exprunner/`, `cmd/decoyd/` (build-tag gated) |

ACL is an **optional, build-tag-gated extension** of the ASSCOR platform:
it consumes target state (SSAM scores, exposure, topology) through existing
interfaces and publishes evidence back. Every formula in the paper is
implemented, unit-tested, and runnable — no component exists only on paper.

### Validation (real experiments, 24-node topology)

The paper reports a live experiment campaign on a 24-node Containerlab
topology (18 hosts + 5 routers + kernel edge) with MITRE Caldera + Atomic
Red Team as the adversarial simulation stack:

- **E1–E9**: intent-tracking accuracy **100%** (28/28 rounds), including a
  multi-stage campaign (recon→credential→data_theft) and an unknown-TTP
  fallback (contain);
- **E7**: repeated identical attacks converge the predicted distribution
  (sharpness 0.695→0.752, entropy 0.547→0.444) — evidence for the paper's
  Q7 (AI/automation convergence);
- **Comparison C1/C2/C3**: no-ACL baseline is blind (0 decoy hits); decoys
  provide the intelligence channel; ACL-dynamic deployment follows the
  prediction.

Full data, the experiment manual, and the reproduction scripts are in
`lunwen/attachment/`.

---

## 4. Branches

- **`main`** — stable baseline (v0.2.x): the assessment runtime
  (SSAM/PRISM/SRD, microkernel, plugins) without the attack-loop extension.
- **`ASSCOR-Research-Core`** — the topology-specialized research branch
  (formerly v0.3.0) on which the ACL engine, its adversarial modules, and
  the paper are developed. The paper's implementation artifacts are
  reproducible from this branch.

The split is deliberate: `main` preserves the stable, production-facing
assessment platform; the research branch carries experimental topology and
engagement work without destabilizing the release baseline.

---

## 5. Building and testing

```bash
go build ./...          # kernel + modules (expr/decoyd are tag-gated)
go test ./internal/...  # unit tests
# experiment harness (Linux, for the lab):
GOOS=linux go build -tags expr   -o exprunner cmd/exprunner/
GOOS=linux go build -tags decoyd -o decoyd   cmd/decoyd/
# paper trace reproduction:
go run -tags tracecheck ./cmd/tracecheck
```

---

## 6. License

Apache License 2.0. See [LICENSE](LICENSE).

---

*For the paper, experiment data, and reproduction manual, see
`lunwen/attachment/`.*
