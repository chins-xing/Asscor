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
- **Belief state**: target-specific belief is updated by confidence-weighted
  accumulation.

Updates are pure: the input state is never mutated. Intent inference is
deliberately conservative — unknown TTPs remain `unknown` rather than being
guessed (see §7).

### 4.3 Prediction Engine

The prediction engine converts state plus target state into a normalized
action distribution over six actions (five intents plus maintain). Raw scores
are a sum of interpretable terms:

1. **Baseline prior** — common-path prevalence.
2. **Intent continuity** — the current intent's action receives a strong
   additive weight (the current stage is a strong signal).
3. **Experience** — experienced attackers favor execution actions (lateral,
   data theft) over reconnaissance.
4. **Target knowledge** — higher knowledge biases toward execution.
5. **AI dependence** — higher AI reliance biases toward common attack vectors
   (credential, web).
6. **Target vulnerability** — low SSAM score / high exposure biases toward
   execution actions.

Scores are normalized by temperature-controlled softmax. The distribution is
then projected onto the ATT&CK TTP layer:
`P(TTP_i) = Σ_j P(TTP_i | Action_j) P(Action_j)`, keeping ATT&CK as the
behavioral semantic layer rather than replacing it.

### 4.4 Engagement Planner

The engagement planner selects deceptive interventions by an explicit utility
function:

```
Utility(E) = α·IG(E) + β·DP(E) + γ·AV(E) − δ·Risk(E)
```

- **Information Gain IG** — proportional to the predicted probability of the
  action the decoy targets (and target coverage).
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

## 5. Hypotheses and Evidence

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

## 6. Validation Plan

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

## 7. Discussion

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

## 8. Conclusion

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

1. D. Shinde and P. Doshi. "Network security as a partially observable stochastic game with a partially observable attacker and defender." (I-POMDP², decision-theoretic planning).
2. Q. Zhu. Tutorial on game-theoretic deceptive cyber-deception.
3. L. Zhang and V. L. L. Thing. "Three decades of deception techniques in active cyber defense." Computers & Security (deception taxonomy, four-layer stack).
4. "Moving Target Defense Techniques: A Survey" (MTD design principles).
5. A. Anwar and M. Kamhoua. Attack-graph games and POSG complexity.
6. MITRE ATT&CK — behavior standardization.
7. 2026 Verizon Data Breach Investigations Report (DBIR) — empirical threat landscape.
8. ASSCOR Whitepaper: *Active Defense Design* (v0.3.0 draft) — attacker model, hypotheses, and automated attack/defense chain.

---

*Status: draft v0.1. Implementation complete; hypothesis validation planned. Preprint intended for arXiv cs.CR.*
