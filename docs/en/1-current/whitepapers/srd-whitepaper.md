# Systemic Risk Dynamics (SRD) Whitepaper
## — Risk Semantics, State Evolution, and Systemic Collapse Theory for Complex Systems
### Attachment: Prism Risk Dynamics Engine Specification v3.1 — Revision 2

---

# Document Information

| Item | Content |
|---|---|
| Project name | Systemic Risk Dynamics |
| Abbreviation | SRD |
| Engine codename | Prism |
| Type | Risk dynamics theoretical framework + risk dynamics engine specification |
| Core focus | Risk semantics, risk evolution, system degradation, systemic collapse, spatiotemporal propagation, state inference |
| Theoretical nature | Interpretable, derivable, semi-deterministic risk system |
| Applicable domains | Security, cloud platforms, industrial control, complex systems, AI infrastructure |
| Version | v3.1-R2 |
| Date | 2026-06-28 (updated 2026-06-28) |
| Design principle | Minimum-verifiable — keep only what cannot be replaced at the computation layer. The deterministic core remains under pure-function constraints; fuzzy semantics and future inference become first-class engine capabilities |

---

# Abstract

Traditional security systems have long been built on CVSS, checklists, compliance, vulnerability counting, and static scoring. These models assume that risk is static, discrete, and deterministic.

Real systems, however, exhibit: long-term degradation, risk propagation, trust drift, dynamic structure, fuzzy boundaries, nonlinear collapse, temporal accumulation, and uncertain input.

Therefore:

## Risk is not a "vulnerability count" — it is the evolution of system state.

SRD (Systemic Risk Dynamics) holds that **system risk is in essence a dynamic risk state space.** SRD's core goal is not to "compute a score" but to **understand how a system degrades, propagates, accumulates, and collapses, and to derive its future states.**

Prism is the engineering implementation of SRD theory — a **risk dynamics engine**. It outputs three structured reports that answer three fundamental questions:

1. **Raw Risk Report** — What happened to the system? (deterministic evaluation)
2. **Semantic Risk Report** — What state is the system in now? (fuzzy semantic attribution)
3. **Future Risk Report** — What states may the system become? (state inference)

Everything else — service classification, hazard annotation, trust-zone definition, data collection, persistence, API exposure, visualization — is the responsibility of the caller (the ASSCOR Kernel).

---

# Part I: Foundations of SRD Theory

---

# 1. Problem Definition

## 1.1 The Problems of Traditional Security Systems

Traditional security systems typically compute:

$$Risk = \sum_i Score_i$$

Risk is treated as the linear accumulation of problems. This model has fundamental flaws:

| Problem | Description |
|---|---|
| Static | Cannot describe risk evolution |
| Independence assumption | Assumes risks are mutually independent |
| No temporal dimension | Cannot describe long-term degradation |
| No propagation semantics | Cannot describe risk diffusion |
| No system context | Cannot describe the blast radius |
| No collapse semantics | Cannot describe systemic failure |
| No fuzzy states | Assumes deterministic input |
| No trust model | Cannot express declining trust |

Consequently, what traditional systems obtain is usually only a "statistical result," not the "true state of the system."

---

# 2. Core SRD Theory

SRD's claim:

## Risk is not a vulnerability. Risk is degradation of system state.

Systems do not fail instantaneously; they **degrade over the long term**. Risk is likewise not an isolated event but **propagation through a trust structure**.

SRD therefore combines:

## risk semantics + state evolution + fuzzy inference + state reasoning

to build a risk dynamics system.

---

# 3. The Three-Layer Model of Prism

Prism is defined as a **Risk Dynamics Engine** composed of three layers:

```
Prism
│
├── Core Layer        — deterministic evaluation layer
├── Semantic Layer    — fuzzy semantic layer
└── Inference Layer   — state inference layer
```

**Core principles**:

- **Core Layer**: pure functions; repeatable, interpretable, auditable. Handles deterministic computation of time, space, propagation, debt, and collapse.
- **Semantic Layer**: maps the Core Layer's numeric outputs into risk-state memberships, answering "what state the system is currently in".
- **Inference Layer**: given the current state and **any pluggable state inference model**, derives a future state probability distribution, answering "what states the system may become".

**Prohibited**: the Core Layer must not use probabilistic reasoning, machine learning, Bayesian prediction, or neural networks.

---

# 4. Risk Semantic Space

SRD defines risk as **multidimensional risk semantics**. System risk is composed of the following dimensions:

| Dimension | Meaning | Where implemented |
|---|---|---|
| Service Type | service semantics | caller CMDB data |
| Hazard Type | hazard semantics | already implied in SSAM check-item Domain/Delta |
| System Weight | system importance | implied by edge density and direction in the topology graph |
| Impact Scope | blast radius | implied by topology connectivity |
| Impact Duration | impact duration | FailSince → security debt formula |
| Collapse Potential | capacity of the system to collapse | emerges naturally when multiple debts are concurrent |
| Trust State | trust state | already quantified by the SSAM score |
| Persistence Level | risk persistence | implied by the magnitude of the Delta value |

**Key principle**: these dimensions are **theoretical concepts**, not code enumerations. Their engineering expression is distributed across SSAM output, caller topology data, and Prism's debt formulas; they do not need to be modeled separately.

---

# 5. Risk State Space

## 5.1 Four-State Risk Model

SRD defines four risk states:

| State | Meaning |
|---|---|
| Stable | Stable — the system is at an acceptable security level |
| Degraded | Degraded — part of the defensive capability has declined; risk is accumulating |
| Untrusted | Untrusted — the trust structure is damaged; the system may have been partially breached |
| Collapse | Collapse — systemic failure; core control is lost |

## 5.2 Fuzzy State Attribution

Real-world risk is not a TRUE/FALSE Boolean judgment but a fuzzy condition of being partially trusted, partially degraded, and partially out of control. A system can therefore **belong to several states simultaneously**.

For example:
- Stable: 0.10
- Degraded: 0.70
- Untrusted: 0.35
- Collapse: 0.05

This means the system is **predominantly in the Degraded state but already shows significant signs of Untrusted**.

## 5.3 State Transitions

System state evolves over time:

$$Stable \rightarrow Degraded \rightarrow Untrusted \rightarrow Collapse$$

SRD's goal is not "chasing zero risk" but **sustaining an acceptable state over the long term** and perceiving state transitions promptly when they occur.

---

# 6. Temporal Risk Dynamics

SRD holds that **risk evolves continuously**: it accumulates, diffuses, amplifies, drifts, and collapses.

Risk is therefore a function of time:

$$R(t) = R_0 \cdot e^{\lambda t}$$

or:

$$R(t) = R_0 + \alpha \cdot \log(1 + t)$$

The engineering implementation uses Prism's security debt formulas (see §14.3).

---

# 7. Network Semantic Reduction

SRD does not attempt to solve the network topology in full. Real networks have complex structures — Overlay, Mesh, VPN, NAT, SDN, Dynamic Routing, Kubernetes, Cloud Fabric — for which a complete network solution is prohibitively expensive.

SRD therefore performs **security semantic reduction** — reducing the complex network to a directed weighted graph:

- Node = an assessed asset (state comes from the SSAM IR)
- Edge = a business connection (RiskTransmission is set by the caller from business knowledge)

The caller (ASSCOR) is responsible for syncing topology from CMDB/NetBox and annotating the risk transmission rate directly on each edge. Prism does not derive transmission rates — the caller knows its own network better.

---

# 8. Collapse Potential — Systemic Collapse

SRD introduces Collapse Potential: the **capacity of the system to collapse**. Traditional systems treat risk as linearly cumulative, but in reality, the failure of certain controls causes an **overall decline in the system's trustworthiness**.

For example: no SIEM, no MFA, no backup, no IDS, no audit — these are not simple point deductions but **systemic trust collapse**.

SRD uses:

$$Risk = S \times C$$

**Engineering implementation**: the collapse effect emerges naturally from the accumulation of security debt — when multiple critical check items remain failing over the long term, the debt grows superlinearly, which is equivalent to a collapse correction. The Core Layer outputs a CollapseModifier in the RawRiskReport for the Semantic Layer to use in its state judgment.

---

# 9. Interpretability Principles

SRD explicitly rejects **black-box AI risk scoring**. SRD therefore adopts **constrained reasoning**:

- **Core Layer — deterministic evaluation**: pure functions, fully auditable
- **Semantic Layer — fuzzy semantic attribution**: membership mapping over deterministic output; rules are transparent and traceable
- **Inference Layer — state inference**: infers only state transition probabilities, never risk scores; inference models are pluggable and their rules are transparent
- **Traceable**: every output can be traced back to a specific check item, topology edge, or state transition record

---

# 10. The Risk Dynamics Triad

SRD uniformly defines risk through the risk dynamics triad, emphasizing that risk is observable, measurable, and predictable:

$$R = (State, Velocity, Forecast)$$

where:

- $State$ = **Current State** — from the Semantic Layer
- $Velocity$ = **Risk Velocity** (the rate of change of risk) — from the Core Layer's time derivative and dynamics trend
- $Forecast$ = **Future State Forecast** — from the Inference Layer

This triad replaces the traditional single risk-score paradigm. Velocity is measurable: e.g., "the score drops by 0.12 per day" directly reflects how fast risk is worsening. It makes abstract risk dynamics concrete and actionable.

---

# 11. Core Principles

1. Risk is not a vulnerability count
2. Risk is not a score
3. Risk is not a probability
4. Risk is the continuous evolution of system state in time and space
5. Risk has temporal semantics
6. Risk is propagative
7. Risk has fuzzy boundaries
8. Risk degrades over the long term
9. Systems exhibit collapse effects
10. Risk must be interpretable
11. The theory layer must be stable and pure
12. The goal of security assessment should be to understand how a system degrades, propagates, accumulates, and collapses, and to derive its future states
13. The security objective is sustaining an acceptable state over the long term

---

# Part II: Prism Engineering Specification

---

# 12. Design Principles

## 12.1 Three-Layer Architecture with a Single Pure-Function Core

Prism uses a three-layer architecture:

- **Core Layer**: a pure-functional kernel — identical input always produces identical output; no internal mutable state, no I/O, no network calls, no locks, no goroutines; depends only on the Go standard library and the `math` package.
- **Semantic Layer**: a fuzzy reasoning layer — deterministic transformations based on Core Layer output; no I/O, no external dependencies; membership function parameters are configurable.
- **Inference Layer**: a state reasoning layer — supports any state inference model; a Markov chain implementation is provided by default; models are passed in by the caller, or the built-in prior is used. Performs no I/O and stays purely computational.

## 12.2 Single Responsibility

Prism does exactly three things:

1. **Core Layer — compute the dynamic score and risk velocity**: given a node's SSAM score, the timeline of failing check items, and the list of incoming edges, return a raw risk report containing the score, debt, propagation, collapse correction, and the rate of risk change.
2. **Semantic Layer — compute the semantic state**: given the raw risk report, return the four-state memberships and the current dominant state.
3. **Inference Layer — derive the future state**: given the current semantic state and an optional inference model, return a state prediction over a given time window together with its confidence.

Prism is not responsible for: data collection, vulnerability scanning, threat intelligence, configuration management, persistence, API exposure, classification enumerations, or visualization.

## 12.3 Responsibility Boundaries

| Component | Responsibility |
|---|---|
| SSAM (ssam-lib) | single-node risk evaluation, outputs SSAM IR |
| **Prism (prism-lib)** | **risk dynamics engine: raw risk + semantic state + future inference** |
| ASSCOR platform | data collection, topology sync, state management, API exposure, scheduling, persistence, visualization |

**Key decision**: the ServiceType enumeration, HazardType classification, and TrustZone definition all live at the ASSCOR layer, not in Prism. Prism only receives caller-prepared data, executes the computation, and returns structured reports.

---

# 13. Data Model

## 13.1 Input: Node State

```go
type NodeState struct {
    HostID       string
    SSAMScore    float64        // FinalScore from the SSAM IR (0-100)
    FailedChecks []CheckFailure // failing check items with their first-failure times
}

type CheckFailure struct {
    CheckID  string
    Delta    float64  // the check item's Delta from SSAM (negative, e.g. -15)
    FailUnix int64    // first-failure timestamp — recorded by the caller, removed on recovery
}
```

## 13.2 Input: Topology Edge

```go
type EdgeState struct {
    Source           string  // upstream node HostID
    Target           string  // downstream node HostID
    RiskTransmission float64 // risk transmission rate (0, 1]
                             // set by the caller based on business knowledge
                             // 1.0 = fully trusted adjacency (public → DMZ)
                             // 0.1 = well isolated (production → SIEM log reporting)
}
```

## 13.3 Configuration

```go
type PrismConfig struct {
    // Core Layer parameters
    DebtAlpha     float64 // debt superlinearity exponent, default 1.2
    PropCap       float64 // propagation penalty cap, default 0.25
    DebtCap       float64 // debt penalty cap, default 0.30
    DebtNormDays  float64 // debt normalization denominator, default 1500
    PathDecay     float64 // path decay factor, default 0.80
    MaxPathDepth  int     // maximum search depth, default 5
    ScoreFloor    float64 // lower-bound floor term, default 0.40
    CollapseBeta  float64 // collapse superlinearity exponent, default 1.5

    // Semantic Layer parameters
    StableThreshold    float64 // upper threshold for Stable membership, default 0.90
    DegradedThreshold  float64 // upper threshold for Degraded membership, default 0.70
    UntrustedThreshold float64 // upper threshold for Untrusted membership, default 0.50
    // The Collapse threshold is implied by the lower bound of UntrustedThreshold

    // Inference Layer parameters
    HorizonDays    int     // default prediction time window (days), default 7
}
```

**No hard-coded coefficient table. Cap-type parameters are defined through score semantics; Norm-type parameters are back-computed from calibration scenarios; semantic thresholds are parameterized and configurable.**

## 13.4 Core Layer Output: Raw Risk Report

```go
type RawRiskReport struct {
    HostID           string
    SsamScore        float64 // raw SSAM score
    PrismScore       float64 // orthogonalized dynamic score [0, 100]
    ExternalRisk     float64 // this node's external risk E(v) ∈ [0, 1]
    PropagatedRisk   float64 // incoming-edge propagated risk R_prop ∈ [0, 1]
    PropPenalty      float64 // applied propagation penalty ∈ [0, Cap_prop]
    DebtRaw          float64 // unnormalized total debt
    DebtPenalty      float64 // normalized debt penalty ∈ [0, Cap_debt]
    CollapseModifier float64 // collapse modifier ∈ [0, 1]
    RiskVelocity     float64 // rate of risk change (score/day; negative = worsening)
}
```

## 13.5 Semantic Layer Output: Semantic Risk Report

```go
type SemanticRiskReport struct {
    HostID                string
    StableMembership      float64   // Stable membership [0, 1]
    DegradedMembership    float64   // Degraded membership [0, 1]
    UntrustedMembership   float64   // Untrusted membership [0, 1]
    CollapseMembership    float64   // Collapse membership [0, 1]
    CurrentState          string    // dominant state
    StateVector           [4]float64 // normalized state vector
}
```

## 13.6 Inference Layer Output: Future Risk Report

```go
type FutureRiskReport struct {
    HostID         string
    HorizonDays    int
    StableProb     float64 // P(Stable) at t+HorizonDays
    DegradedProb   float64 // P(Degraded) at t+HorizonDays
    UntrustedProb  float64 // P(Untrusted) at t+HorizonDays
    CollapseProb   float64 // P(Collapse) at t+HorizonDays
    Confidence     float64 // prediction confidence [0, 1], based on model suitability and input quality
    Trend          string  // "improving" / "stable" / "degrading" / "collapsing"
    CollapseRisk   float64 // collapse risk summary: P(Untrusted) + P(Collapse)
}
```

## 13.7 Path Search Result

```go
type PathResult struct {
    Path           []string  // node sequence
    CumulativeRisk float64   // cumulative risk
}
```

---

# 14. Formulas

## 14.1 Node External Risk (Core Layer)

Given a node $v$ with SSAM score $S_{ssam}(v) \in [0, 100]$, its **external risk** (the threat it poses to other nodes as an attack stepping stone) is:

$$E(v) = \frac{100 - S_{ssam}(v)}{100}$$

**Orthogonality guarantee**: the propagation penalty depends only on **upstream nodes'** external risk and is fully independent of the current node's own SSAM score.

## 14.2 Propagation Risk and Hop Decay (Core Layer)

For an edge $e: u \to v$, the risk spillover from $u$ to $v$ is:

$$\text{spillover}(u \to v) = E(u) \times \lambda_{trans}(e)$$

Node $v$'s total propagation risk $R_{prop}(v)$ is the **root of the sum of squares** of all incoming-edge spillovers:

$$R_{prop}(v) = \min\left(1.0,\ \sqrt{ \sum_{e: \cdot \to v} \text{spillover}(e)^2 }\right)$$

**Hop decay**: in path search, the risk contribution of the $n$-th hop is multiplied by the decay factor $\gamma^{n-1}$ (default $\gamma = 0.8$):

$$\text{spillover}_n = \text{spillover} \times \gamma^{\,n-1}$$

## 14.3 Security Debt — Day Normalization (Core Layer)

When the caller records the first failure time $t_{fail}$ of a check item, the debt function is expressed in **days**:

$$D(c, t) = |\Delta(c)| \times \left( \frac{t - t_{fail}}{86400} \right)^{\alpha}$$

**Why days**: Unix second-scale timestamps risk numeric overflow. Using days, 30 days yields a value on the order of $30^{1.2} \approx 59$, which is numerically stable and intuitively interpretable.

$\alpha > 1$ ensures that risk grows superlinearly with exposure time. The debt is zeroed immediately once the check item passes again.

## 14.4 Orthogonalized Dynamic Score (Core Layer)

$$S_{prism}(v, t) = \max\left(S_{ssam}(v) \times \mathsf{Floor},\ S_{ssam}(v) \times (1 - P_{prop}(v)) \times (1 - P_{debt}(v, t))\right)$$

where:

$$P_{prop}(v) = \min(Cap_{prop},\ R_{prop}(v))$$

$$P_{debt}(v, t) = \min\left(Cap_{debt},\ \frac{\sum_c D(c, t)}{Norm_{debt}}\right)$$

**Orthogonality analysis**:

| Dimension | Source | Independent of this node's SSAM score? |
|------|------|:---:|
| $S_{ssam}$ | SSAM output | — (baseline) |
| $P_{prop}$ | upstream node SSAM × λ | ✅ fully independent (depends on upstream, not this node) |
| $P_{debt}$ | time × Δ | ✅ fully independent (time dimension, not score dimension) |

## 14.5 Risk Velocity (Core Layer)

Risk velocity $V_{risk}$ measures the instantaneous rate of change of the score, in "score/day". It is computed by differencing the score over a time window:

$$V_{risk}(v, t) = \frac{S_{prism}(v, t) - S_{prism}(v, t - \Delta t)}{\Delta t}$$

When no historical snapshot exists, it can be approximated from the debt growth rate and the propagation change rate. A negative value indicates worsening risk. The value is emitted to `RawRiskReport.RiskVelocity`.

---

## 14.6 Collapse Correction (Core Layer)

The CollapseModifier is derived from the superlinear aggregation of concurrent debts:

$$CollapseModifier(v, t) = \min\left(1.0,\ \left(\frac{\sum_c D(c, t)}{Norm_{debt} \times Cap_{debt}}\right)^{\beta}\right)$$

where $\beta > 1$ (default $\beta = 1.5$), ensuring that the collapse effect grows superlinearly when multiple debts are concurrent.

## 14.7 Four-State Membership Computation (Semantic Layer)

Given the normalized PrismScore $S_{norm} = S_{prism} / 100$, parameterized trapezoidal membership functions are used:

**Stable membership**:
$$\mu_{Stable}(S_{norm}) = \max\left(0,\ \min\left(1,\ \frac{S_{norm} - T_{degraded}}{T_{stable} - T_{degraded}}\right)\right)$$

**Degraded membership**:
$$\mu_{Degraded}(S_{norm}) = \max\left(0,\ \min\left(\frac{S_{norm} - T_{untrusted}}{T_{degraded} - T_{untrusted}},\ \frac{T_{stable} - S_{norm}}{T_{stable} - T_{degraded}}\right)\right)$$

**Untrusted membership**:
$$\mu_{Untrusted}(S_{norm}) = \max\left(0,\ \min\left(\frac{S_{norm} - T_{collapse}}{T_{untrusted} - T_{collapse}},\ \frac{T_{degraded} - S_{norm}}{T_{degraded} - T_{untrusted}}\right)\right)$$

**Collapse membership**:
$$\mu_{Collapse}(S_{norm}) = \max\left(0,\ \min\left(1,\ \frac{T_{untrusted} - S_{norm}}{T_{untrusted} - T_{collapse}}\right)\right)$$

where $T_{stable} = 0.90$, $T_{degraded} = 0.70$, $T_{untrusted} = 0.50$, $T_{collapse} = 0.0$ (defaults, adjustable through PrismConfig).

**Output normalization**: the membership vector is normalized so that $\sum \mu_i = 1.0$ and is emitted as the StateVector.

## 14.8 Future State Inference (Inference Layer)

The Inference Layer supports **any state inference model**; the caller can inject models through a standard interface. The built-in default implementation is a **Markov chain model**.

Given the current state vector $S_t$ and the state transition matrix $\mathbf{T}$, the future state probability distribution is:

$$S_{t+k} = S_t \times \mathbf{T}^k$$

**Default state transition matrix** (based on an expert-knowledge prior, one-day step):

$$\mathbf{T} = \begin{bmatrix}
0.95 & 0.04 & 0.01 & 0.00 \\
0.02 & 0.90 & 0.07 & 0.01 \\
0.00 & 0.03 & 0.85 & 0.12 \\
0.00 & 0.00 & 0.05 & 0.95
\end{bmatrix}$$

State order: Stable, Degraded, Untrusted, Collapse.

**Confidence computation**: confidence reflects the reliability of the prediction and combines the following factors:
- concentration of the input state vector (the lower the entropy, the higher the confidence)
- the degree to which the inference model matches the current scenario (configurable)
- the prediction time span (confidence decreases as the span grows)

In the default implementation, confidence is the product of the state vector's maximum membership and a time decay factor: $Confidence = \max(StateVector) \times e^{-k/K}$, where $K$ is the time decay constant.

**Trend classification**:
- if $P(Collapse) + P(Untrusted)$ grows by $> 0.1$, classify as `"collapsing"`
- if $P(Degraded) + P(Untrusted)$ grows by $> 0.1$, classify as `"degrading"`
- if $P(Stable)$ grows by $> 0.1$, classify as `"improving"`
- otherwise classify as `"stable"`

---

# 15. Parameter Summary

| Parameter | Default | Meaning | Layer |
|------|:---:|------|:---:|
| `DebtAlpha` | 1.2 | debt superlinearity exponent | Core |
| `PropCap` | 0.25 | propagation penalty cap | Core |
| `DebtCap` | 0.30 | debt penalty cap | Core |
| `DebtNormDays` | 1500 | debt normalization denominator | Core |
| `PathDecay` | 0.80 | path decay factor | Core |
| `MaxPathDepth` | 5 | maximum search depth | Core |
| `ScoreFloor` | 0.40 | lower-bound floor term | Core |
| `CollapseBeta` | 1.5 | collapse superlinearity exponent | Core |
| `StableThreshold` | 0.90 | Stable upper threshold | Semantic |
| `DegradedThreshold` | 0.70 | Degraded upper threshold | Semantic |
| `UntrustedThreshold` | 0.50 | Untrusted upper threshold | Semantic |
| `HorizonDays` | 7 | default prediction window | Inference |

**No free parameters**: all parameters are set through orthogonality constraints, calibration against benchmark scenarios, or expert knowledge.

---

# 16. ScoreFloor — Preventing Permanent Collapse

The multiplicative structure $S_{ssam} \times (1-P_{prop}) \times (1-P_{debt})$ carries an **unbounded decay** risk over long-term operation: each evaluation stacks new penalties, the system's score keeps declining, and eventually every system approaches 0 — a state from which recovery is impossible.

Solution: introduce a **lower-bound floor term** $\mathsf{Floor}$ so that the score never falls below a fixed proportion of the raw SSAM score:

$$S_{prism}(v, t) \geq S_{ssam}(v) \times \mathsf{Floor}$$

Default $\mathsf{Floor} = 0.40$. Even in the worst case (propagation saturation + debt saturation), the system retains 40% of its raw SSAM score. This is equivalent to a "recoverability guarantee" — the system cannot collapse permanently under multiple independent penalty factors.

---

# 17. Pure-Function Interfaces

## 17.1 Core Layer Interface

```go
// ComputeRawRisk computes a node's raw risk report.
// allNodes is used to look up the SSAM scores of upstream nodes.
// previousScore is optional, for computing risk velocity; when nil, velocity is estimated.
func ComputeRawRisk(
    node *NodeState,
    incomingEdges []EdgeState,
    allNodes map[string]*NodeState,
    cfg PrismConfig,
    nowUnix int64,
    previousScore *float64, // optional previous score, used for velocity computation
) RawRiskReport

// FindPropagationPaths finds the top-N highest-risk paths from source to target.
func FindPropagationPaths(
    source, target string,
    nodes map[string]*NodeState,
    edges []EdgeState,
    cfg PrismConfig,
    nowUnix int64,
    maxDepth int,
    limit int,
) []PathResult
```

## 17.2 Semantic Layer Interface

```go
// ComputeSemanticRisk computes the four-state memberships from a raw risk report.
func ComputeSemanticRisk(
    raw RawRiskReport,
    cfg PrismConfig,
) SemanticRiskReport
```

## 17.3 Inference Layer Interface

```go
// StateInferenceModel defines the interface of a state inference model.
// Any model satisfying this interface can be injected into the Inference Layer.
type StateInferenceModel interface {
    // Predict returns the future state probability distribution for the given
    // current state vector and number of prediction days.
    Predict(currentState [4]float64, horizonDays int) [4]float64
    // Confidence returns the confidence of a given prediction.
    Confidence(currentState [4]float64, horizonDays int) float64
}

// InferFutureRisk derives the future state probability distribution from the
// current semantic state and an inference model.
// model is optional: when nil, the default Markov chain model is used.
func InferFutureRisk(
    current SemanticRiskReport,
    horizonDays int,
    model StateInferenceModel, // nil = use the default model
    cfg PrismConfig,
) FutureRiskReport
```

**Complete evaluation pipeline** (caller's perspective):
```go
raw := ComputeRawRisk(node, edges, allNodes, cfg, now, &previousScore)
semantic := ComputeSemanticRisk(raw, cfg)
future := InferFutureRisk(semantic, cfg.HorizonDays, nil, cfg)
```

**The principle is unchanged**: all functions are pure functions. The caller passes data in; Prism returns results. No side effects, no state.

---

# 18. State Attribution: Prism Only Ever Consumes Snapshots

Prism is a pure-function library. It does not manage state. Concretely:

| Data | Owner | Notes |
|------|------|------|
| `NodeState.SSAMScore` | ASSCOR cache | from the most recent SSAM evaluation |
| `CheckFailure.FailUnix` | ASSCOR `failTracker` | first-failure timestamps are recorded and updated by ASSCOR |
| `EdgeState.RiskTransmission` | ASSCOR topology manager | read by the caller from CMDB or configuration |
| historical score series | ASSCOR persistence layer | Prism Core receives it through the `previousScore` parameter; it does not store it |
| historical state series | ASSCOR persistence layer | used to train custom inference models; managed by the caller |

**Prism merely "consumes snapshots and emits reports."**

---

# 19. Full-Graph Recalculation and Incremental Propagation (Future Direction)

In the current implementation, each `ComputeRawRisk` call evaluates one node by walking all of its incoming edges — complexity $O(|E_{in}|)$. In a multi-host deployment (N nodes, each with N−1 incoming edges), a single call has complexity $O(N)$.

When N grows past 100k+, an **incremental propagation model** will be needed:

- **dirty-marking propagation**: recompute only the affected subgraph
- **topology partitioning**: partition by TrustZone / ServiceType
- **batch scheduling**: compute in batches after each batch
- **online learning for inference models**: once ASSCOR's persistence layer has accumulated state transition sequences, train custom models and inject them into Prism

**But not now.** What matters most at this stage is keeping the architecture pure:
- Prism remains pure-functional
- ASSCOR controls call frequency and scope through its scheduling layer
- decide only after `N > 100` yields real performance data

---

# 20. Integration with SSAM and ASSCOR

## 20.1 Data Flow

1. The ASSCOR agent collects data → the Kernel performs the SSAM evaluation → generates the SSAM IR
2. ASSCOR's state manager updates NodeState, records FailUnix, and retains the previous score for velocity computation
3. ASSCOR syncs topology from CMDB → builds the EdgeState list
4. On each state change or scheduled trigger → ASSCOR invokes Prism's three-layer pipeline: Raw → Semantic → Future
5. ASSCOR exposes the three reports via its API / writes them to persistence
6. ASSCOR's persistence layer accumulates state sequences, periodically trains custom inference models, and injects them into the Prism Inference Layer

## 20.2 Project Layout

```
prism/
├── types.go              # data structure definitions (incl. the inference model interface)
├── core.go               # Core Layer
├── semantic.go           # Semantic Layer
├── inference.go          # Inference Layer (default Markov chain implementation)
├── config.go             # DefaultConfig
├── core_test.go
├── semantic_test.go
├── inference_test.go
├── go.mod                # standalone module, zero external dependencies
```

---

# 21. Features Cut or Relocated

| Feature | Status | Reason |
|------|------|------|
| ServiceType enumeration | cut | CMDB data; defined by the caller |
| HazardType enumeration | cut | implied by SSAM |
| ImpactScope enumeration | cut | implied by the topology graph |
| TrustZone enumeration | cut | transmission rate set directly on edges |
| standalone CollapseModifier | cut | emerges naturally from debt + CollapseBeta |
| hard-coded RiskTransmission | cut | set by the caller |
| SystemWeight coefficient | cut | implied by the topology |
| PersistenceLevel coefficient | cut | implied by Delta |
| FuzzyMembership | relocated to the Semantic Layer (v3.1) | state semantics are the core of risk perception |
| FutureState prediction | relocated to the Inference Layer (v3.1) | a natural extension of dynamics |
| hard-coded Bayesian model | relocated to a pluggable interface (v3.1-R2) | supports any inference model |

---

# 22. Algorithmic Limitations

- propagation risk considers only legitimate business connections; illicit lateral movement requires a "potential attack edge" extension
- security debt assumes monotonic growth and does not account for the decline in exploit probability after mitigation
- depends on the accuracy of SSAM evaluation
- parameter calibration needs production data to refine
- the membership functions are trapezoidal approximations
- the default transition matrix is an expert prior; prediction accuracy can improve as data accumulates
- the Markov assumption may mask path-dependent effects
- confidence computation is heuristic and needs calibration against real verification feedback

---

# 23. Future Directions

- **domain-specific inference models** — injection and evaluation of Bayesian networks, HMMs, survival analysis, statistical regression, etc.
- **confidence calibration** — dynamic confidence adjustment based on historical prediction accuracy
- **nonlinear collapse models** — multiplicative interaction of multiple debts
- **dynamic weights** — real-time threat intelligence adjusts λ
- **cluster-level aggregate scoring** — risk over node sets
- **Prism IR standardization** — structured output for the three-layer reports

---

# 24. Version History

| Version | Date | Changes |
|------|------|------|
| v1.0 | before 2026-06-01 | initial concept design |
| v2.0 | 2026-05-28 | SRD + Prism merged; complete types/enumerations/coefficients |
| v3.0 | 2026-05-28 | MVP slimming: 4 types, 6 parameters, 2 functions, 0 hard-coded coefficients |
| v3.1 | 2026-05-30 | orthogonality fix, multiplicative form, day normalization, hop decay |
| v3.2 | 2026-05-30 | ScoreFloor lower bound, FailUnix attribution, incremental-propagation record |
| v3.1-R1 | 2026-06-08 | three-layer architecture: Core/Semantic/Inference; triad R=(S,D,F) |
| **v3.1-R2** | **2026-06-08** | **pluggable inference model interface; native Bayesian claim removed; confidence output added; triad upgraded to R=(State, Velocity, Forecast); Core Layer outputs risk velocity** |

---

# 25. Conclusion

SRD's claim: system risk is neither a vulnerability count nor a score.

**Risk is the continuous evolution of system state in time and space.**

Prism v3.1-R2 is the **risk dynamics engine implementation** of this theory. It does not classify, enumerate, manage data, or visualize. It does exactly three things:

1. **Core Layer**: computes propagation risk, temporal debt, collapse correction, and the rate of risk change — answering "what happened to the system and how fast is it changing"
2. **Semantic Layer**: converts numbers into risk-state memberships — answering "what state is the system currently in"
3. **Inference Layer**: derives future state probabilities and confidence from pluggable inference models — answering "what states the system may become, and how reliable that prediction is"

While SSAM answers "how safe is this machine right now," Prism answers:

- "across the dynamics of the whole network, where is risk flowing and how fast is it worsening"
- "what state is the system in now — stable, degraded, untrusted, or already collapsed"
- "if things continue as they are, which state is most likely next, and how much can this prediction be trusted"

All questions about "what type it is," "how important it is," "which zone it belongs to," or "what color it should be displayed as" are the caller's responsibility.

Prism's boundary ends here. This is all it can do. This is all it should do.

---

# Appendix A: Core Terminology

| Term | Meaning |
|---|---|
| Systemic Risk | systemic risk |
| Risk State | risk state (Stable / Degraded / Untrusted / Collapse) |
| Risk Dynamics | risk dynamics — the laws of risk evolution in time and space |
| Risk Velocity | risk velocity — the instantaneous rate of change of the risk score; measurable |
| Risk Triad | risk triad: $R = (State, Velocity, Forecast)$ |
| Trust Drift | trust drift |
| Collapse Potential | the collapse potential of a system |
| Security Debt | security debt — the cumulative risk of unfixed defects over time |
| Spillover | risk spillover — risk transmitted from an upstream node to a downstream node |
| Fuzzy Membership | fuzzy membership — the degree to which a system belongs to several risk states at once |
| State Inference Model | state inference model — the pluggable interface for predicting future states |
| Confidence | confidence — a measure of prediction reliability |
| Prism | Prism — the risk dynamics engine of SRD theory |

---

# Appendix B: Core Formulas

## Core Layer formulas

**Self risk**:
$$E(v) = \frac{100 - S_{ssam}(v)}{100}$$

**Risk spillover**:
$$\text{spillover}(u \to v) = E(u) \times \lambda_{trans}(e)$$

**Propagation risk aggregation**:
$$R_{prop}(v) = \min\left(1.0,\ \sqrt{ \sum_{e: \cdot \to v} (E(src_e) \times \lambda_e)^2 }\right)$$

**Hop decay**:
$$\text{spillover}_n = \text{spillover} \times \gamma^{\,n-1},\quad \gamma = 0.8$$

**Security debt (day normalization)**:
$$D(c, t) = |\Delta(c)| \times \left( \frac{t - t_{fail}}{86400} \right)^{\alpha}$$

**Orthogonalized dynamic score**:
$$S_{prism}(v, t) = \max\left(S_{ssam}(v) \times \mathsf{Floor},\ S_{ssam}(v) \times (1 - \min(Cap_{prop}, R_{prop}(v))) \times \left(1 - \min\left(Cap_{debt}, \frac{\sum D(c,t)}{Norm_{debt}}\right)\right)\right)$$

**Risk velocity**:
$$V_{risk}(v, t) \approx \frac{S_{prism}(v, t) - S_{prism}(v, t - \Delta t)}{\Delta t}$$

**Collapse correction**:
$$CollapseModifier(v, t) = \min\left(1.0,\ \left(\frac{\sum_c D(c, t)}{Norm_{debt} \times Cap_{debt}}\right)^{\beta}\right),\quad \beta = 1.5$$

## Semantic Layer formulas

**Stable membership**:
$$\mu_{Stable}(S_{norm}) = \max\left(0,\ \min\left(1,\ \frac{S_{norm} - T_{degraded}}{T_{stable} - T_{degraded}}\right)\right)$$

**State vector normalization**:
$$StateVector_i = \frac{\mu_i}{\sum_{j} \mu_j}$$

## Inference Layer formulas

**Future state prediction (default Markov chain)**:
$$S_{t+k} = S_t \times \mathbf{T}^k$$

**Confidence (default heuristic)**:
$$Confidence = \max(StateVector) \times e^{-k/K}$$

**Default transition matrix**:
$$\mathbf{T} = \begin{bmatrix}
0.95 & 0.04 & 0.01 & 0.00 \\
0.02 & 0.90 & 0.07 & 0.01 \\
0.00 & 0.03 & 0.85 & 0.12 \\
0.00 & 0.00 & 0.05 & 0.95
\end{bmatrix}$$

## The risk dynamics triad

$$R = (State, Velocity, Forecast)$$

- $State$ = Current State Vector (Semantic Layer)
- $Velocity$ = RiskVelocity (Core Layer)
- $Forecast$ = FutureRiskReport (Inference Layer)

---

# Appendix C: Output Model Overview

| Report | Layer | Core question | Nature |
|---|---|---|---|
| RawRiskReport | Core Layer | What happened to the system? How fast is it changing? | deterministic, auditable |
| SemanticRiskReport | Semantic Layer | What state is the system currently in? | fuzzy reasoning, interpretable |
| FutureRiskReport | Inference Layer | What may the future look like? How reliable is the prediction? | probabilistic reasoning, verifiable |

---

## State Feedback (caller's responsibility)

Prism does not spontaneously adjust transmission rates or inference models. The caller can implement:

- **transmission-rate feedback**: dynamically adjust the `RiskTransmission` on edges according to upstream states
- **inference-model feedback**: accumulate historical state sequences and train custom models (Bayesian networks, HMMs, survival analysis, etc.), injected through the `StateInferenceModel` interface

This way Prism keeps its pure-function nature, while dynamic behavior is managed by the caller.
