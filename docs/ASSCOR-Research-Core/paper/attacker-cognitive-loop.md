# Attacker Cognitive Loop: An Interpretable Rule-Based Engine for Estimating, Predicting, and Engaging Adaptive Attackers

**Draft v0.1** — for arXiv (cs.CR)

---

## Abstract

Block-embedded defense (firewalls, IPS, patching) suffers from two structural
asymmetries: defenders cannot enumerate all attacker paths, and attackers plan
long-term while defenders must react in real time. This paper argues for a
*guided* rather than *blocking* active-defense paradigm, and presents the
**Attacker Cognitive Loop (ACL)** — an interpretable, rule-based engine that
continuously estimates attacker state, predicts the attacker's next action as
a probability distribution, and selects deceptive interventions by an explicit
utility function. The system comprises five components: a multi-layer temporal
topology graph, an attacker state engine, an action prediction engine, an
engagement planner, and a closed-loop controller that switches between
information-gathering and active-engagement strategies based on prediction
confidence. We formulate the research question — *how AI, shared tooling, and
individual experience jointly shape the attacker's action distribution, and
whether defenders can actively reshape it through observation, deception, and
guidance* — and state ten falsifiable hypotheses (H1–H10) with evidence
ratings. The engine is fully implemented as a modular, pure-function library;
empirical validation is planned. We deliberately do not claim predictive
accuracy or deception success without direct evidence.

## 1. Introduction

Classical defense embeds blocking controls: access control and isolation make
undesirable states unreachable. Surveys of moving-target defense (MTD) have
documented two inherent weaknesses of this paradigm. First, a *cognitive
limitation*: defenders cannot enumerate all latent attacker paths, and
attackers enjoy an information advantage during prolonged reconnaissance.
Second, a *temporal asymmetry*: attackers can plan over long horizons while
defenders must respond in real time, and patch lag leaves a window of
opportunity.

Guided active defense does not aim to block everything; it aims to create an
*information asymmetry* in the defender's favor. By deploying lightweight
decoy targets and fabricated intelligence, the defender induces the attacker
to abandon slow, patient operation in favor of rapid verification — exposing
tactics, techniques, and procedures (TTPs) and intent earlier than they would
otherwise be revealed. Intelligence collected from each interaction feeds the
next, more accurate round of deception, forming a positive feedback loop:
*guide → collect → analyze → decide → guide again*.

In the MITRE Engage taxonomy, engagement is used here as a guidance tool, not
a blocking tool; host isolation is demoted to a fallback when guidance fails
or confirms high risk.

This work makes the following contributions:

1. We formulate the attacker-cognitive-loop research question (§9.3 of our
   design whitepaper) that connects attacker modeling with adaptive deception.
2. We present an interpretable, rule-based engine (ACL) that realizes the
   loop: state estimation, action-distribution prediction, utility-driven
   engagement selection, and confidence-driven strategy switching.
3. We state ten falsifiable hypotheses (H1–H10) about attacker behavior in the
   AI era, each with an evidence rating, and a validation plan.
4. We are transparent about what is implemented (the engine) versus what
   remains to be validated (the hypotheses). No assumption is presented as a
   conclusion.

## 2. Related Work

**Decision-theoretic planning.** Shinde and Doshi's I-POMDP² extends
partially observable Markov decision processes to model the defender's beliefs
about the attacker's beliefs, capabilities, and preferences, with finite
nested recursive reasoning. Their experiments observe level-3 defenders who
first mislead the attacker into believing the defense is passive, then deploy
decoys — a decision-theoretic justification for guidance over blocking. A full
I-POMDP² solver is computationally prohibitive; our engine is a transparent
rule-based approximation that can be replaced by richer models without
changing the loop architecture.

**Game-theoretic deception.** Zhu's tutorial and Anwar & Kamhoua's
attack-graph games formalize signaling games, dynamic games, mechanism design,
and hypergames for deception. General-sum stochastic games make pure-strategy
Nash equilibrium computation PSPACE-hard, and equilibrium concepts assume
symmetric optimality that poorly models the attacker's *bounded rationality*.
We therefore prefer the decision-theoretic view.

**Deception taxonomy and MTD.** Zhang & Thing survey honeypots, honeytokens,
and MTD across a four-layer stack (network/system/software/data) mapped to the
kill chain. MTD surveys contribute five design principles (coverage,
unpredictability, timeliness, superstability, functional equivalence) that
constrain any future MTD component. We adopt honeypot/honeytoken as the
primary guidance mechanism and treat MTD as an optional deterministic-weakening
component.

**Behavior standardization.** MITRE ATT&CK provides the semantic layer for
attack behavior. Our prediction engine maps action distributions onto TTP
distributions rather than replacing ATT&CK.

**Risk propagation.** SRD (Systemic Risk Dynamics) models risk diffusion over
a network graph; we reuse its substrate for the topology layer and as the
dynamic state-evolution layer of the cognitive loop.

## 3. Problem Formulation

### 3.1 Attacker State

We model the attacker's cognitive state as:

```
AttackerState = (Capability, Experience, Intent, TTP_Repertoire,
                 SharedCapability, IndividualCapability, AI_Dependence,
                 TargetKnowledge, BeliefState, Objective)
```

where `Intent` ∈ {recon, credential, lateral, data_theft, web_attack},
`AI_Dependence ∈ [0,1]` measures reliance on AI for decision/execution, and
`BeliefState` captures the attacker's subjective perception of the target
environment.

### 3.2 Prediction Target

Rather than a deterministic next-TTP, we predict:

```
P(A_{t+1} | AttackerState_t, TargetState_t, Observation_t)
```

and additionally output *most likely*, *most dangerous*, *most observable*
actions (and a ranked list), feeding both risk prioritization and engagement
selection.

### 3.3 The Cognitive Loop

The closed loop is:

```
Observation → State Estimation → Behavior Prediction
  → Guidance/Deception → Attacker Response
  → New Evidence → State Update → Predict Again
```

## 4. System Design: The Attacker Cognitive Loop

ACL is implemented as a modular, pure-function Go library (no external
dependencies per component), designed so each component can be independently
tested and replaced. It follows a microkernel architecture: the core kernel
remains untouched; these components are optional, build-tag modules.

### 4.1 Multi-Layer Temporal Graph

A single `Host–connects–Host` graph cannot express attackers, identities,
tools, code, TTPs, and evidence. We maintain six semantic layers — Network,
Dependency, Identity, Attacker, Capability, Evidence — over a shared
temporal graph: nodes and edges carry `FirstSeen`/`LastSeen` timestamps,
edges carry lifecycle status (up/down) and attributes (latency, bandwidth,
ACL), and nodes carry an event stream (observations, alerts, decoy triggers)
with confidence. Reachability queries (shortest path, bounded-hop traversal)
support multi-hop analysis. The layer/type/edge-type vocabularies are open
strings: predefined constants cover the common semantics, and any model can
introduce new values without engine changes.

### 4.2 Attacker State Engine

The state engine implements `OldState + Evidence → NewState` with explicit,
interpretable rules:

- **Intent inference**: evidence TTP maps to intent via a technique→intent
  table; an explicit intent in the evidence overrides TTP inference; higher
  confidence overrides lower.
- **Target knowledge**: each observation with a target raises
  `TargetKnowledge` by `0.1 × Confidence`, capped at 1.
- **TTP repertoire**: observed TTPs are added to the known set (deduplicated).
- **Experience**: successful outcomes `+0.05`, failures `−0.03`, clamped to
  [0,1].
- **Capability**: each TTP's required capability is added to the attacker's
  capability set.
- **Belief state**: target-specific belief is updated by
  `+0.15 × Confidence` per observation, capped at 1 (Algorithm 1, line 11).

Updates are pure: the input state is never mutated. Intent inference is
deliberately conservative — unknown TTPs remain `unknown` rather than being
guessed (see §10).

### 4.3 Prediction Engine

The prediction engine converts state plus target state into a normalized
action distribution over six actions (five intents plus maintain). Raw scores
are a sum of interpretable terms:

1. **Baseline prior** — common-path prevalence (`base[a]`, 0.5–1.2; see
   Algorithm 2).
2. **Intent continuity** — the current intent's action receives a strong
   additive weight `+3.0` (the current stage is a strong signal).
3. **Experience** — experienced attackers favor execution actions:
   `+Experience` for lateral and data_theft, `−0.5 × Experience` for recon.
4. **Target knowledge** — higher knowledge biases toward execution:
   `+TargetKnowledge` for credential, lateral, and data_theft.
5. **AI dependence** — higher AI reliance biases toward common attack vectors:
   `+AIDependence` for credential and web_attack, `−0.5 × AIDependence` for
   recon.
6. **Target vulnerability** — low SSAM score / high exposure biases toward
   execution actions: `+0.8 × vulnerability` for credential, lateral,
   data_theft, and web_attack, where
   `vulnerability = (100 − SSAMScore)/100 + Exposure`.

Scores are normalized by temperature-controlled softmax (Algorithm 2). The
distribution is then projected onto the ATT&CK TTP layer:
`P(TTP_i) = Σ_j P(TTP_i | Action_j) P(Action_j)`, keeping ATT&CK as the
behavioral semantic layer rather than replacing it.

### 4.4 Engagement Planner

The engagement planner selects deceptive interventions by an explicit utility
function:

```
Utility(E) = α·IG(E) + β·DP(E) + γ·AV(E) − δ·Risk(E)
```

- **Information Gain IG** — the predicted probability of the action the decoy
  targets, scaled by a target-coverage factor
  `coverage = 0.5 + 0.5 × ((100 − SSAMScore)/100 + Exposure)/2` (Algorithm 3).
- **Detection Probability DP** — the decoy's intrinsic detection capability.
- **Attribution Value AV** — the attribution information a decoy type can
  capture.
- **Risk** — deployment cost × exposure (being detected as fake, or collateral
  impact on business).

The default decoy catalog maps actions to decoys (fake SSH → lateral movement,
fake credentials → credential theft, fake documents → data theft, fake web →
web attack, scan ports → reconnaissance). Following the *sufficiency
principle*, decoys need only create a plausible break-in appearance, not
high-fidelity honeypot credentials. Decoys are treated as sensors: an
interaction chain (connect → credential attempt → command → system discovery →
follow-up) is recorded and converted into evidence that feeds the state engine.

### 4.5 Closed-Loop Controller

The controller orchestrates the loop:

1. **State update**: `OldState + Observations → NewState`.
2. **Prediction**: compute the action distribution.
3. **Confidence**: normalized entropy of the distribution — sharp
   distributions have high confidence, flat ones low.
4. **Strategy** (confidence-driven): below the threshold, *collect* — keep
   only the highest-IG intervention (maximize intelligence gathering); above
   the threshold, *engage* — select all positive-utility interventions (active
   guidance).
5. **Observe**: evidence from deployed interventions (decoy triggers) feeds
   the next round.

This realizes the information-gain closed loop: predict → select →
observe → update → re-predict.

## 5. Design Rationale

This section documents the concrete design choices and the trade-offs they
entail, so that the system can be evaluated and modified by others.

### 5.1 Rule-Based over Learned or Game-Theoretic Models

The state engine and predictor use hand-crafted rules and weights. This is a
deliberate choice for three reasons:

1. **Explainability.** In security operations, decisions must be auditable.
   Every component emits interpretable intermediate values (rule terms,
   confidence, utility decomposition), which an operator can inspect.
2. **No training data.** The hypotheses H1–H10 are not yet validated; there
   is no labeled dataset of attacker behavior from which to learn. Rules are
   the only honest starting point.
3. **Cost.** Full I-POMDP² or general-sum stochastic-game solution is
   computationally prohibitive. A transparent approximation is acceptable as
   a first implementation, and the loop architecture is deliberately
   model-agnostic so the rule-based predictor can be replaced by a learned
   model or a solver without touching the other layers (§6.3).

### 5.2 Intent-Continuity Weight

The action whose intent equals the current `AttackerState.Intent` receives a
strong additive weight (3.0, versus baseline 0.5–1.2). Rationale: the current
stage is the strongest single predictor of the next action — an attacker
currently harvesting credentials tends to continue credential actions. The
magnitude was tuned so that, under a clear intent, the distribution becomes
sharp enough for the confidence-driven controller to switch to active
engagement, while remaining responsive to new contradictory evidence.

### 5.3 Entropy-Based Confidence

Prediction confidence is defined as the normalized entropy of the action
distribution: sharp distributions have high confidence, flat ones low. This
is a *certainty proxy*, not calibrated accuracy — we state this explicitly in
§10. The default threshold (0.3) separates the collect strategy (flat
distributions: prefer intelligence gathering) from the engage strategy (sharp
distributions: allow active guidance). Both the threshold and the temperature
are configuration parameters.

### 5.4 Utility Weights

The engagement utility `U = α·IG + β·DP + γ·AV − δ·Risk` uses default weights
α=1.0, β=0.8, γ=0.6, δ=1.2. Information gain dominates because intelligence
acquisition is the primary objective of the loop (§3.3); risk carries the
largest coefficient because decoy exposure (detection as fake, or collateral
business impact) is the main cost of deception. These weights are tunable per
deployment.

### 5.5 Open Semantic Vocabulary

`Layer`, `NodeType`, and `EdgeType` are plain strings. Predefined constants
cover the common semantics (six graph layers, 23 node types, nine edge types),
but any model can introduce new values without changing the engine. This
decouples the graph engine from any specific domain vocabulary — the same
engine serves network topology, identity, attacker, capability, and evidence
layers.

### 5.6 Pure-Function, Immutable Updates

`Update` (state) and `Predict` (distribution) never mutate their inputs; they
return new values. This yields three properties: components are trivially
unit-testable; concurrent evaluation is safe; and the full state/prediction
trajectory can be retained for audit and replay.

### 5.7 Decoy Mapping Reuse

The default catalog reuses the existing intent→decoy mapping of the platform:
lateral movement → fake SSH, credential theft → fake credentials, data theft →
fake documents, web attack → fake web, scanning → decoy ports. This follows
the *sufficiency principle* (§1.2 of our design whitepaper): decoys need only
present a plausible break-in appearance, not high-fidelity honeypot
credentials, which keeps deployment cost low enough for single-host-scale
operation.

## 6. Model Integration

### 6.1 Microkernel, Optional Modules

ACL follows the host platform's microkernel architecture: the kernel retains
only the extension framework and interface contracts; every ACL component is an
optional, independently compiled module (build-tag gated). The kernel is not
modified — the loop consumes data through existing interfaces (topology
registry, assessment results) and publishes evidence back.

### 6.2 Data-Flow Wiring

```
Evidence sources (logs, decoys, CTI, alerts)
        │  (normalized to Evidence)
        ▼
State Engine ──► Prediction Engine ──► Engagement Planner
        ▲                                   │
        │        (decoy interactions →      │
        └──────────── Evidence) ◄───────────┘
        ▲
        │  (target state: SSAM scores, exposure, topology)
Topology Graph / Assessment pipeline
```

Three data paths feed the loop:

- **Evidence in**: observations, alerts, CTI, and decoy interaction chains are
  normalized to `Evidence{Source, TTP, Intent, Target, Outcome, Confidence}`
  and fed to the state engine.
- **Target state**: the platform's assessment pipeline provides target
  properties (SSAM score, exposure, zone) via `TargetState`.
- **Evidence out**: decoy interaction chains are recorded as
  `DeceptionRecord` (connect → credential attempt → command → system
  discovery → follow-up) and converted to `Evidence`, closing the loop.

### 6.3 Model Replacement Points

The loop is model-agnostic at three narrow seams. Each seam is a single Go
interface with one method; the graph layer and the closed-loop controller
depend only on these interfaces, never on the internal choices of any engine.

**Seam 1 — StateEngine.** The rule-based belief update can be replaced by any
model exposing:

```go
type StateUpdater interface {
    Update(state attackerstate.AttackerState, evs []attackerstate.Evidence) attackerstate.AttackerState
}
```

Replacement examples:
- a Bayesian belief-update model (e.g., Beta-Bernoulli per technique) that
  maintains posteriors over intent conditioned on evidence, then collapses
  them into the same `AttackerState` fields;
- a wrapper around an I-POMDP² solver that projects its belief tree onto the
  `AttackerState` structure after each update.

**Seam 2 — Predictor.** The rule-based scorer can be replaced by any
calibrated probabilistic model:

```go
type ActionPredictor interface {
    Predict(state attackerstate.AttackerState, target predictor.TargetState) predictor.ActionDistribution
}
```

Replacement examples:
- a logistic-regression or gradient-boosted classifier over engineered state
  features, calibrated (e.g., Platt scaling) so the output is a genuine
  probability distribution over the six actions;
- a neural sequence model conditioned on the evidence history, with the
  two-layer ATT&CK projection (§4.3) retained downstream.

**Seam 3 — Planner.** The utility function and decoy catalog are
configuration; richer planners can be swapped in behind:

```go
type EngagementSelector interface {
    Select(dist predictor.ActionDistribution, target predictor.TargetState) []engagement.ScoredIntervention
}
```

Replacement examples:
- an information-theoretic optimal experimental design that selects the decoy
  minimizing expected posterior entropy of the attacker state;
- a reinforcement-learning planner whose reward is evidence gain minus
  deployment cost.

In every case the controller calls the same three methods
(`Update` → `Predict` → `Select`) and the loop contract (§3.3) is preserved.
The reference implementation ships the rule-based engines as the default
implementations of these interfaces.

### 6.4 Open Vocabulary Integration

Because the graph semantics are open strings (§5.5), a new model (e.g., an
identity layer feeding an ID-theft detection model) can register its own
layers and edge types and immediately participate in temporal queries and
reachability analysis without forking the engine.

## 7. Key Implementations

The engine is implemented in Go as pure-function libraries. The following
condensed pseudocode captures the core of each component.

### 7.1 State Update (AttackerState → NewState)

```
Algorithm 1: Update(state, evidence list) → newState
  for each ev in evidence:
    if ev.TTP is known: add ev.TTP to state.TTPRepertoire
    if ev.Target != "": state.TargetKnowledge += 0.1 × clamp01(ev.Confidence)
    switch ev.Outcome:
      case "success": state.Experience += 0.05
      case "failure": state.Experience -= 0.03
    intent := ev.Intent if set, else IntentFromTTP(ev.TTP)   // mapping table
    if intent known and ev.Confidence ≥ bestConf:            // high-conf wins
        state.Intent, bestConf = intent, ev.Confidence
    if capability = CapabilityForTTP(ev.TTP): add to state.Capability
    if ev.Target != "": state.BeliefState[ev.Target] += 0.15 × conf
  clamp Experience, TargetKnowledge, BeliefState to [0,1]
  return state
```

Key property: no mutation of the input — the new state is a fresh value.

### 7.2 Action Distribution (Predict)

```
Algorithm 2: Predict(state, target) → distribution
  for each action a in {recon, credential, lateral, data_theft, web, maintain}:
    score[a] = base[a]
             + 3.0 if intentOf(a) == state.Intent          // continuity
             + (a in {lateral,data_theft}) × state.Experience
             - (a == recon) × 0.5 × state.Experience
             + (a in {credential,lateral,data_theft}) × state.TargetKnowledge
             + (a in {credential,web}) × state.AIDependence
             - (a == recon) × 0.5 × state.AIDependence
             + (a in {credential,lateral,data_theft,web}) × vulnerability × 0.8
  distribution = softmax(score, temperature)
  mostDangerous = argmax_a distribution[a] × dangerWeight[a]
  return distribution with multi-outputs
```

### 7.3 Engagement Utility

```
Algorithm 3: Select(distribution, target) → scored interventions
  for each intervention E (decoy type, target action):
    IG  = distribution[E.targetAction] × coverage(target)
    DP  = detectionRate[E.decoy]        // intrinsic decoy capability
    AV  = attributionValue[E.decoy]
    Risk = E.cost × E.exposure
    utility = α·IG + β·DP + γ·AV − δ·Risk
  return interventions sorted by utility (descending), utility > 0
```

### 7.4 Closed-Loop Step

```
Algorithm 4: Step(state, observations, target) → result
  newState    = StateEngine.Update(state, observations)
  distribution = Predictor.Predict(newState, target)
  confidence  = 1 − entropy(distribution) / log(|actions|)   // §5.3
  strategy    = "collect" if confidence < threshold else "engage"
  candidates  = Planner.Select(distribution, target)
  interventions = strategy == "collect"
                    ? [argmax_IG(candidates)]                  // intelligence first
                    : candidates                                // active guidance
  return {newState, distribution, confidence, strategy, interventions}
```

All four algorithms are deterministic and side-effect free; the reference
implementation ships with unit tests covering intent inference, distribution
normalization, utility decomposition, and multi-round convergence to a
credential intent with the strategy switching to engage.

## 8. Hypotheses and Evidence
We state ten falsifiable hypotheses about attacker behavior. Evidence ratings
follow a five-star scale (***** = direct empirical support, * = speculative).
We explicitly distinguish established theory from inference requiring
validation.

| ID | Hypothesis | Status | Evidence |
|----|-----------|--------|----------|
| H1 | Successful experience raises the reuse probability of related TTPs | To be validated | ★★★☆☆ |
| H2a | IT skill positively correlates with hacking efficiency | Empirically supported | ★★★★★ |
| H2b | Capability/experience raise reliance on validated TTPs | Inference | ★★★☆☆ |
| H3 | Attackers seek initial advantage (identity/trust/information gain) | Multi-source support | ★★★★☆ |
| H4 | Social-engineering strategic value cannot be measured by frequency alone | Methodological | ★★★★☆ |
| H5 | A shared capability layer exists (common tools/code/AI) | Direct evidence | ★★★★★ |
| H6 | AI expands the accessibility of shared capability | Strong support | ★★★★★ |
| H7 | AI leads to attacker strategy convergence | Core unvalidated hypothesis | ★★☆☆☆ |
| H8 | Effective capability and strategy diversity are independent | Theoretical inference | ★★★☆☆ |
| H9 | High experience can offset AI convergence | To be validated | ★★☆☆☆ |
| H10 | One should predict action distributions, not next TTP | Methodological support | ★★★★☆ |

**Implications.** H3 implies attackers first reduce target uncertainty rather
than directly exploiting vulnerabilities — guiding through decoys that appear
to reduce that uncertainty is therefore aligned with attacker incentives.
H5/H6 imply that observed similarity does not imply the same actor: attribution
must first exclude shared tooling, shared code, common TTPs, shared
infrastructure, and AI-generated strategy. H7 is the core research question —
if AI dependence raises cross-attacker similarity, defenders can exploit the
resulting predictability.

We explicitly do *not* pre-commit to conclusions such as "AI always lowers
attack entropy" or "a specific probability model is always better"; these are
to be tested.

## 9. Validation Plan

Validation is planned in two phases.

**Phase 1 — engine validation (in progress).** The engine is implemented and
unit-tested (intent inference, distribution normalization, utility
decomposition, loop convergence in simulation). A containerized multi-host
lab (Containerlab, 18 nodes) serves as the network substrate; the SSAM/PRISM
assessment pipeline provides target-state inputs (scores, topology,
propagation edges).

**Phase 2 — hypothesis validation (planned).** Each hypothesis maps to a
measurable experiment:

- **H1/H9**: longitudinal study of a red-team exercise — measure TTP reuse
  conditioned on prior success/failure and operator experience.
- **H2a/H2b**: controlled human-subject study correlating IT skill with
  efficiency and TTP reliance.
- **H7**: comparative analysis of AI-assisted vs. human-only attackers —
  TTP entropy, sequence diversity, behavioral distance, strategy cluster
  distribution (this is the core, currently unvalidated, hypothesis).
- **H10**: ablation comparing next-TTP prediction vs. action-distribution
  prediction on the same dataset.

We note that the 2026 DBIR provides empirical grounding for the threat
landscape (exploitation as top initial-access vector at 31%, credential abuse,
ransomware prevalence 48%, GenAI-assisted attacks with a median of 15
techniques), but dataset sampling/reporting biases require preserving source
and provenance metadata rather than treating frequency as ground truth.

## 10. Discussion

**Limitations.** ACL currently uses hand-crafted rules and weights; it is a
transparent approximation, not a full I-POMDP² solver. Confidence is defined
as distribution sharpness, not calibrated accuracy. Deception utility weights
(α, β, γ, δ) require tuning. The hypotheses H1, H2b, H7, H9 are not yet
validated; the paper does not claim predictive accuracy or deception success
without direct evidence.

**Relationship to richer models.** The loop architecture is model-agnostic:
the rule-based state engine and predictor can be replaced by learned models or
an I-POMDP² solver without changing the graph, engagement, or controller
layers. This modularity is a deliberate design property.

**The AI convergence question.** If H7 holds, defenders face both a threat and
an opportunity: convergent strategies are easier to predict and to guide;
diverse strategies (H8/H9) resist convergence and require broader engagement
portfolios.

## 11. Conclusion

We presented the Attacker Cognitive Loop, an interpretable rule-based engine
for guided active defense that estimates attacker state, predicts action
distributions, and selects utility-driven deceptive interventions within a
closed loop that switches between information gathering and active engagement
by prediction confidence. The engine is fully implemented as a modular,
pure-function library with unit-tested components. We stated ten falsifiable
hypotheses with evidence ratings and a validation plan, and we were explicit
about the boundary between implementation and unvalidated assumption. The
central open question — whether AI, shared tooling, and individual experience
shape attacker action distributions in ways defenders can actively reshape —
remains a testable research agenda, not a claimed result.

## References

1. P. Shinde and P. Doshi. "Network Security as a Partially Observable
   Stochastic Game with a Partially Observable Attacker and Defender."
   *Artificial Intelligence*, 2026. ScienceDirect article PII
   S0004370226000664. *(author to confirm volume/pages/DOI)*
2. Q. Zhu. "Game Theoretic Deception for Cyber Defense." Tutorial,
   arXiv:1903.01442, 2019. https://arxiv.org/abs/1903.01442
3. L. Zhang and V. L. L. Thing. "Three Decades of Deception Techniques in
   Active Cyber Defense." *Computers & Security*, vol. 106, 2021.
   arXiv:2104.03594. https://arxiv.org/abs/2104.03594
4. "Moving Target Defense Techniques: A Survey." *(author to confirm full
   citation — survey on MTD design principles; companion material in the
   ASSCOR whitepaper's reference pack)*
5. A. Anwar and M. Kamhoua. "Game Theoretic Approaches to Attack Graph
   Games." *(author to confirm full citation — companion material in the
   ASSCOR whitepaper's reference pack)*
6. MITRE. "MITRE ATT&CK." https://attack.mitre.org (accessed 2026)
7. Verizon. *2026 Data Breach Investigations Report.* 2026.
   https://www.verizon.com/business/resources/reports/dbir/
8. ASSCOR Project. "Active Defense Design Whitepaper" (v0.3.0 draft),
   2026. Internal document: attacker model (H1–H10), automated
   attack/defense chain, deception taxonomy and MTD survey summaries.

---

*Status: draft v0.1. Implementation complete; hypothesis validation planned. Preprint intended for arXiv cs.CR.*
