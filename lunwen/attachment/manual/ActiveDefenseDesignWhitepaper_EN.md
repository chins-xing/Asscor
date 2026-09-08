# ASSCOR v0.3.0 Active Defense Design Whitepaper

> Version: 2026-08-14 (v0.3.0 draft)
> Status: design proposal, pending review
> Principle: strictly distinguish **theory/phenomena supported by existing
> evidence**, **methodological support**, and **inferences still requiring
> direct validation**; never present hypotheses as conclusions.

---

## Abstract

The strategic positioning of v0.3.0 is to **upgrade ASSCOR from
"blocking-oriented passive defense" to "guidance-oriented active defense"**.
The core idea is to promote the attacker model from a functional module in
the pipeline to the **cognitive core** of the entire automated chain —
continuously estimating the attacker's state, predicting the probability
distribution of the next action, actively changing observability through
observation/deception/guidance, and re-updating the attacker model from new
intelligence, forming an adaptive "attacker-defender" closed loop.

This whitepaper integrates three kinds of material:

1. **Theoretical foundation** (5 papers): decision-theoretic planning
   (I-POMDP²), game theory, three-domain deception review
   (honeypot/honeytoken/MTD), MTD survey, attack-graph games;
2. **Attacker behavior model**
   (`attacker_model_theory_and_hypotheses_v2.md`, H1–H10 hypotheses with
   evidence ratings);
3. **Automated attack-defense chain**
   (`automated_attack_defense_chain_improvement.md`, dual closed loop +
   evidence fusion + state engine + engagement planning).

It ultimately answers one research question:

> **How do AI, shared tools/code, and individual experience jointly shape the
> attacker's action probability distribution, and can defenders actively
> reshape this distribution through observation, deception, and guidance?**

---

## 1. Strategic Positioning: From Blocking to Guidance

### 1.1 Why shift to guidance

Traditional defense (firewalls, IPS, antivirus, patching) is
**block-embedded defense**: it makes undesirable states unreachable through
access control/isolation. It has two inherent weaknesses (argued by the MTD
survey):

- **Cognitive limitation**: defenders cannot enumerate all potential attacker
  paths and all vulnerabilities; the attacker's information advantage from
  prolonged left-of-exploitation reconnaissance cannot be eliminated;
- **Temporal asymmetry**: attackers can plan long-term, defenders must
  respond in real time, and patch lag leaves a window of opportunity.

Guided active defense does not seek to "block everything"; it **creates
information asymmetry**: decoys/fake intelligence mislead the attacker about
the environment, forcing them to abandon slow stealth and switch to rapid
verification, thereby **exposing TTPs and intent earlier**. The intelligence
collected feeds back into the next, more precise round of decoys, forming a
positive-feedback loop:

```text
guide → collect → analyze → decide → guide again
```

**In this system, MITRE Engage is a guidance tool, not a blocking tool.**
Host isolation (isolate_host) is demoted to a fallback when guidance fails
or confirms high risk.

### 1.2 Lightweight deception principle ("good-enough" principle)

Intent-driven lightweight deception needs no high-fidelity honeypot
credentials. Once attacker intent is recognized, lightweight honeypots
actively expose suspicious services or drop fake intelligence. The attacker's
threshold for taking the bait is low — merely creating a "breach-point
illusion" induces exposure. This directly lowers deception deployment cost,
making deception feasible at single-host scale.

---

## 2. Theoretical Foundation

### 2.1 Decision theory vs game theory: why decision-theoretic planning

Game theory (Zhu tutorial; Anwar & Kamhoua attack-graph games) provides a
quantitative framework for deception: signaling games, dynamic games,
mechanism design, hypergames, POSG. But game-theoretic methods have inherent
difficulties:

- **Equilibrium computation complexity**: pure-strategy Nash equilibrium in
  general-sum stochastic games is PSPACE-hard; POSG is even less tractable;
- **Symmetric rationality assumption**: equilibrium concepts assume both
  parties respond symmetrically optimally, poorly capturing the attacker's
  **subjective rationality** (information asymmetry, bounded nested modeling,
  cognitive biases).

Decision-theoretic methods (Shinde & Doshi's I-POMDP²) fit this system
better because they:

- **Explicitly model attacker beliefs**: the defender maintains a subjective
  model of the attacker's beliefs/capabilities/preferences (models are part
  of the state space);
- **Finite nested recursive reasoning**: can simulate both "attacker unaware
  of defender" (level 0) and "attacker reasons about defender behavior"
  (level ≥2) scenarios;
- **Cognitive bias modeling**: exploits FAE (fundamental attribution error)
  and confirmation bias to deceive **sophisticated** attackers — something
  game-theoretic equilibrium frameworks cannot provide.

**Key insight** (directly supporting the §1 guidance strategy): I-POMDP²
experiments observed the refined strategy of level-3 defenders — **first
mislead the attacker into believing the defense is passive (inducing deep
commitment), then deploy decoys to deceive them**. This is the
decision-theoretic justification for "guidance rather than blocking".

### 2.2 Deception taxonomy and the four-layer deception stack

The three-domain review (Zhang & Thing) establishes a two-dimensional
taxonomy:

- **Three technique families**: honeypot, honeytoken, MTD — complementary,
  composable into orchestrated deception;
- **Four-layer deception stack**: network / system / software / data layers;
- **Kill-chain mapping**: answers "which techniques disrupt which attack
  stage, at which stack layer".

honeypot/honeytoken are **false targets** (introduce false information); MTD
is **dynamic transformation** (removes deterministic information without
actively misleading). This system uses honeypot/honeytoken as primary
(active guidance), with MTD as an optional deterministic-weakening measure.

### 2.3 MTD design principles (optional component)

The MTD survey distills five design principles, as constraints for future MTD
components:

1. **Coverage**: dynamically and randomly transform all exploitable
   vulnerabilities, prioritizing critical resources;
2. **Unpredictability**: enough heterogeneous redundant components to
   guarantee transformation space;
3. **Timeliness**: transformation must be triggered before attack execution;
4. **Superstability**: multiple cooperating mechanisms equivalent to a
   single more complex one, and synergistic with existing defense;
5. **Functional equivalence**: business functions remain available during
   transformation.

### 2.4 Empirical threat landscape (2026 DBIR)

The attacker model must anchor to the real landscape, not prior guesses.
2026 DBIR (31,000+ incidents, 22,000+ breaches, 145 countries) key data:

| Metric | 2026 value | Trend |
|--------|:---:|------|
| Exploitation as top initial access | 31% | +55% vs 20% prior year |
| Credential abuse | 13% | down from 22% (partly due to Pretexting separated) |
| Ransomware share of breaches | 48% | up from 44% |
| Third-party involvement | 48% | +60% vs 30% |
| KEV full remediation rate | 26% | down from 38% |
| KEV remediation median time | 43 days | worse vs 32 days |
| Human element involvement | 62% | vs 60% |
| Social engineering pattern | 16% | third most common breach pattern |
| Pretexting as initial access | 6% | voice/SMS, synchronous social engineering |
| GenAI-assisted attacks | median 15 techniques | up to 40-50 |

---

## 3. Attacker Model (H1–H10)

### 3.1 Model objective

Build a **cognitive** attacker model that is (a) continuously updated from
evidence, (b) predicts a probability distribution over next actions rather
than a deterministic TTP, and (c) is falsifiable — every hypothesis carries
an explicit evidence rating.

### 3.2 Attacker State structure

```
AttackerState = (
  Capability, Experience, Intent,
  TTP_Repertoire, SharedCapability, IndividualCapability,
  AI_Dependence, TargetKnowledge, BeliefState, Objective
)
```

Intent ∈ {recon, credential, lateral, data_theft, web_attack}; AI_Dependence
∈ [0,1] measures reliance on AI for decision/execution.

### 3.3 Hypotheses and evidence ratings

| ID | Hypothesis | Status | Evidence |
|----|-----------|--------|----------|
| H1 | Successful experience raises reuse probability of related TTPs | To be validated | ★★★☆☆ |
| H2a | IT skill positively correlates with hacking efficiency | Empirically supported | ★★★★★ |
| H2b | Capability/experience raise reliance on validated TTPs | Inference | ★★★☆☆ |
| H3 | Attackers seek initial advantage (identity/trust/information gain) | Multi-source support | ★★★★☆ |
| H4 | Social-engineering strategic value cannot be measured by frequency alone | Methodological | ★★★★☆ |
| H5 | A shared capability layer exists (common tools/code/AI) | Direct evidence | ★★★★★ |
| H6 | AI expands accessibility of shared capability | Strong support | ★★★★★ |
| H7 | AI leads to attacker strategy convergence | Core unvalidated | ★★☆☆☆ |
| H8 | Effective capability and strategy diversity are independent | Theoretical inference | ★★★☆☆ |
| H9 | High experience can offset AI convergence | To be validated | ★★☆☆☆ |
| H10 | Should predict action distributions, not next TTP | Methodological support | ★★★★☆ |

### 3.4 Key mechanisms

- **Shared capability (H5/H6)**: attacks increasingly share tools, code,
  and AI-generated strategy; observed similarity does not imply the same
  actor — attribution must first exclude shared tooling.
- **AI convergence (H7)**: if AI dependence raises cross-attacker similarity,
  defenders can exploit the resulting predictability (the core research
  question).
- **Experience offset (H9)**: experienced attackers may compensate for AI
  convergence with more diverse strategies.

### 3.5 What must NOT be written as conclusions prematurely

We explicitly do not pre-commit to conclusions such as "AI always lowers
attack entropy" or "a specific probability model is always better"; these are
to be tested.

---

## 4. Prediction Model: From Next TTP to Action Distribution

### 4.1 Why no deterministic prediction

A deterministic next-TTP prediction conflates uncertainty with certainty:
when evidence is ambiguous, the honest output is a flat distribution, not a
forced single pick. Deterministic predictions also break the engagement
planner's need for ranked, utility-scored alternatives.

### 4.2 Prediction target

```
P(A_{t+1} | AttackerState_t, TargetState_t, Observation_t)
```

with multi-outputs: most likely / most dangerous / most observable actions
and a ranked list.

### 4.3 Two-layer model (preserving ATT&CK)

Action distribution is projected onto the ATT&CK TTP layer:
P(TTP_i) = Σ_j P(TTP_i | Action_j) · P(Action_j). ATT&CK remains the
behavioral semantic layer rather than being replaced.

---

## 5. Automated Attack-Defense Chain

### 5.1 Dual closed loop

- **Outer loop** (evidence): observations/alerts/CTI → evidence fusion →
  attacker state update;
- **Inner loop** (engagement): state → prediction → engagement selection →
  decoy deployment → new evidence.

### 5.2 Evidence Fusion

Heterogeneous evidence (logs, decoy triggers, CTI) is normalized to
Evidence{Source, TTP, Intent, Target, Outcome, Confidence} and merged with
confidence-weighted priority.

### 5.3 Multi-layer Temporal Graph

Six semantic layers — Network, Dependency, Identity, Attacker, Capability,
Evidence — over a shared temporal graph with FirstSeen/LastSeen timestamps,
lifecycle status, and per-node event streams.

### 5.4 Attacker State Engine

OldState + Evidence → NewState via explicit, interpretable rules: intent
inference (TTP→intent table, explicit intent overrides, higher-confidence
wins), target knowledge accumulation, TTP repertoire dedup, experience
update, capability set growth, belief-state update.

### 5.5 Engagement Planner (IntentGuider upgrade)

From "deploy decoys by intent" to "select interventions maximizing new
intelligence":

```
Utility(E) = α·IG(E) + β·DP(E) + γ·AV(E) − δ·Risk(E)
```

### 5.6 Decoys as sensors

Interaction chains (connect → credential attempt → command → system
discovery → follow-up) are recorded as DeceptionRecord and converted to
Evidence, closing the loop.

### 5.7 Post-validation repositioning

Any deployed decoy is ephemeral, air-gapped from production, and resets on
outbound connection — preventing pivot.

### 5.8 Prediction-sharpness-driven strategy

Confidence (normalized entropy of the action distribution) drives a
three-way strategy: contain (unknown intent/unknown TTP) / collect (low
sharpness: highest-IG only) / engage (high sharpness: all positive-utility).

---

## 6. Data Requirements (supporting H1–H10 validation)

- Red-team exercise logs with TTP sequences conditioned on
  success/failure (H1/H9);
- Controlled human-subject studies correlating IT skill with efficiency
  (H2a/H2b);
- AI-assisted vs human-only attack traces: TTP entropy, sequence diversity,
  behavioral distance, strategy clustering (H7);
- Ablation of next-TTP vs action-distribution prediction (H10).

---

## 7. Cognitive Modeling: FAE and Confirmation Bias in Practice

- **FAE (fundamental attribution error)**: attackers over-attribute observed
  events to stable attacker characteristics; decoys exploit this by making
  the environment look intentional.
- **Confirmation bias**: attackers seek evidence confirming their current
  hypothesis; a well-placed decoy that "confirms" a wrong hypothesis
  prolongs the attacker's commitment.

Both biases are modeled at the belief-state level: the defender's decoy
selection can deliberately feed the attacker's biased inference to increase
information gain.

---

## 8. System Architecture Mapping

The attacker model, evidence fusion, state engine, and engagement planner
map onto ASSCOR's microkernel: optional build-tag modules consuming topology
and assessment data through existing interfaces, publishing evidence back.

### Minimal viable upgrade path

1. Attacker State Engine (module) consuming existing evidence;
2. Action Distribution Predictor (module);
3. Engagement Planner with the lightweight decoy catalog;
4. Closed-loop controller wiring the three.

---

## 9. Theoretical Core and Open Questions

### 9.1 Most solid theoretical core

- H5/H6 (shared capability layer) — direct empirical support;
- H3 (initial advantage seeking) — multi-source support;
- H10 (distribution prediction) — methodological support from the
  uncertainty argument.

### 9.2 Most original, most needing empirical validation

- H7 (AI convergence) — the core, currently unvalidated, hypothesis;
- H9 (experience offset) — dependent on H7.

### 9.3 Final research question

> How do AI, shared tooling/code, and individual experience jointly shape the
> attacker's action probability distribution, and can defenders actively
> reshape it through observation, deception, and guidance?

---

## 10. Appendix: Material Index

- `attacker_model_theory_and_hypotheses_v2.md` — H1–H10 with evidence ratings
- `automated_attack_defense_chain_improvement.md` — dual closed loop
- References: Shinde & Doshi (I-POMDP²), Zhu (game theory tutorial), Zhang &
  Thing (deception survey), Lei et al. (MTD survey), Anwar & Kamhoua
  (attack-graph games), Verizon DBIR 2026
