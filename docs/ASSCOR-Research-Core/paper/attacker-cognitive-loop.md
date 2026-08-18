# Attacker Cognitive Loop: An Interpretable Rule-Based Engine for Estimating, Predicting, and Engaging Adaptive Attackers

**Draft v0.1** 鈥?for arXiv (cs.CR)

**Author**: 璧栧槈璞?(Jiahao Lai)

**Contact**: **chins-xing@proton.me** 鈥?feedback and collaboration welcome.

> **Invitation to the community.** We explicitly invite researchers working on
> attacker modeling, deception, game theory, decision theory (I-POMDP虏),
> and learning-based prediction to propose more principled models for any of
> the three engine seams (state estimation, action prediction, engagement
> selection). The loop architecture is model-agnostic (搂6.3): a better model
> can be dropped into the corresponding interface without changing the graph,
> the controller, or the closed-loop contract. The reference implementation is
> open source (Apache-2.0) and the lab environment is reproducible. Please
> reach out via the contact address above.

---

## Abstract

Block-embedded defense (firewalls, IPS, patching) suffers from two structural
asymmetries: defenders cannot enumerate all attacker paths, and attackers plan
long-term while defenders must react in real time. This paper argues for a
*guided* rather than *blocking* active-defense paradigm, and presents the
**Attacker Cognitive Loop (ACL)** 鈥?an interpretable, rule-based engine that
continuously estimates attacker state, predicts the attacker's next action as
a probability distribution, and generates ranked, auditable deceptive
recommendations. The system comprises five components: a multi-layer temporal
topology graph, an attacker state engine, an action prediction engine, an
engagement planner, and a closed-loop controller that switches between
containment, information gathering, and active engagement based on decision
sharpness. We formulate the research question 鈥?*how AI, shared tooling, and
individual experience jointly shape the attacker's action distribution, and
whether defenders can actively reshape it through observation, deception, and
guidance* 鈥?and state ten open research questions (Q1鈥換10) with evidence
ratings. We provide the complete formal specification of the scoring,
normalization, sharpness, and utility functions, a reproducible four-round
closed-loop trace with exact numerical values, a sensitivity analysis of the
hand-tuned weights, and simulated per-round latency benchmarks. The engine
serves as a baseline implementation; its heuristic weights are explicitly not
optimal and are provided solely to demonstrate the closed-loop mechanics. We
release the simulation framework to enable community-driven replacement of
any component.

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
to abandon slow, patient operation in favor of rapid verification 鈥?exposing
tactics, techniques, and procedures (TTPs) and intent earlier than they would
otherwise be revealed. Intelligence collected from each interaction feeds the
next, more accurate round of deception, forming a positive feedback loop:
*guide 鈫?collect 鈫?analyze 鈫?decide 鈫?guide again*.

In the MITRE Engage taxonomy, engagement is used here as a guidance tool, not
a blocking tool; host isolation is demoted to a fallback when guidance fails
or confirms high risk.

This work makes the following contributions:

1. We formulate the attacker-cognitive-loop research question (搂9.3 of our
   design whitepaper) that connects attacker modeling with adaptive deception.
2. We present an interpretable, rule-based engine (ACL) that realizes the
   loop: state estimation, action-distribution prediction, utility-driven
   engagement selection, and sharpness-driven strategy switching.
3. We state ten open research questions (Q1鈥換10) about attacker behavior in
   the AI era, each with an evidence rating, and a validation plan.
4. We are transparent about what is implemented (the engine) versus what
   remains to be answered (the questions). No assumption is presented as a
   conclusion.

## 2. Related Work

**Decision-theoretic planning.** Shinde and Doshi's I-POMDP虏 [1] extends
partially observable Markov decision processes to model the defender's beliefs
about the attacker's beliefs, capabilities, and preferences, with finite
nested recursive reasoning. Their experiments observe level-3 defenders who
first mislead the attacker into believing the defense is passive, then deploy
decoys 鈥?a decision-theoretic justification for guidance over blocking. A full
I-POMDP虏 solver is computationally prohibitive; our engine is a transparent
rule-based approximation that can be replaced by richer models without
changing the loop architecture.

**Game-theoretic deception.** Zhu's tutorial [2] and Anwar & Kamhoua's
attack-graph games [5] formalize signaling games, dynamic games, mechanism
design, and hypergames for deception. General-sum stochastic games make
pure-strategy Nash equilibrium computation PSPACE-hard, and equilibrium
concepts assume symmetric optimality that poorly models the attacker's
*bounded rationality*. We therefore prefer the decision-theoretic view.

**Attacker modeling and attribution.** The Diamond Model of intrusion
analysis [9] structures every intrusion event as four vertices 鈥?*adversary*,
*capability*, *infrastructure*, and *victim* 鈥?connected by six phases of an
activity thread, with meta-features (timestamp, kill-chain phase, result,
direction, method, resources) describing each event. Its central axiom, that
each intrusion is an event in an activity thread whose evolution is governed
by the adversary, is the analytical backbone we reuse: our six-layer graph
(搂4.1) is the Diamond Model's relational projection onto a temporal substrate
鈥?the Adversary layer holds the adversary vertex, the Capability layer holds
capabilities and TTPs, the Network/Dependency layers hold infrastructure, and
the Identity/Evidence layers hold the victim and the meta-features. Unlike the
Diamond Model, which is a retrospective analytic framework, ACL consumes the
same relational structure *forward* to estimate the attacker's state and
predict its next action. We also note the fundamental attribution problem
raised by the shared-capability questions (Q5/Q6, 搂9): observed similarity
between intrusions does not imply the same adversary, since adversaries share
tooling, code, and (increasingly) AI-generated strategy.

**Defensive deception and honeypot limitations.** Zhang & Thing [3] survey
three decades of honeypots, honeytokens, and MTD across a four-layer stack
(network/system/software/data) mapped to the kill chain, and document the two
structural weaknesses of honeypot-only defenses that motivate our
guided-engagement design: (i) *static deployment*: if honeypots and
honeytokens are left with static configuration, an adversary has enough time
to infer their existence, map them, and evade them; and (ii) *pivot risk*:
high-interaction honeypots, which offer a real operating-system environment,
can themselves be compromised and used as a pivot point to attack other
systems. Two further weaknesses are well-known in practice: (iii)
*low-interaction honeypots have low fidelity*, so sophisticated attackers can
fingerprint and bypass them; and (iv) *passivity*: traditional honeypots wait
for the attacker and yield little intelligence about intent until the attacker
has already committed. Our loop addresses (i) by making engagement a
*function of the predicted action distribution* that changes each round, (ii)
by the *sufficiency principle* (搂5.7) 鈥?decoys expose only a plausible
break-in appearance with no real system to compromise 鈥?(iii) by keeping
decoys lightweight and cheap enough to deploy at single-host scale, and (iv)
by using decoys as *active sensors* whose interaction chains feed the state
engine.

**MTD design principles.** MTD surveys [4] contribute five design principles
(coverage, unpredictability, timeliness, superstability, functional
equivalence) that constrain any future MTD component. We adopt
honeypot/honeytoken as the primary guidance mechanism and treat MTD as an
optional deterministic-weakening component.

**Behavior standardization.** MITRE ATT&CK [6] provides the semantic layer for
attack behavior. Our prediction engine maps action distributions onto TTP
distributions rather than replacing ATT&CK, and our state engine infers
intent from observed TTPs through an explicit technique鈫抜ntent table
(Table 1): T1595/T1592/T1590/T1046 鈫?recon, T1110/T1003/T1555/T1078 鈫?credential, T1021/T1570/T1550/T1028 鈫?lateral, T1567/T1048/T1030/T1537 鈫?data_theft, T1190/T1193/T1566 鈫?web_attack. The same table drives the reverse
projection P(TTP_i) = 危_j P(TTP_i | Action_j) P(Action_j) (搂4.3). This makes
the ATT&CK鈫抯tate-machine bridge explicit, auditable, and replaceable: unknown
techniques remain `unknown` rather than being guessed.

**Risk propagation.** SRD (Systemic Risk Dynamics) models risk diffusion over
a network graph [8]; we reuse its substrate for the topology layer and as the
dynamic state-evolution layer of the cognitive loop.

## 3. Problem Formulation

### 3.1 Attacker State

We model the attacker's cognitive state as:

```
AttackerState = (Capability, Experience, Intent, TTP_Repertoire,
                 SharedCapability, IndividualCapability, AI_Dependence,
                 TargetKnowledge, BeliefState, Objective)
```

where `Intent` 鈭?{recon, credential, lateral, data_theft, web_attack},
`AI_Dependence 鈭?[0,1]` measures reliance on AI for decision/execution, and
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
Observation 鈫?State Estimation 鈫?Behavior Prediction
  鈫?Guidance/Deception 鈫?Attacker Response
  鈫?New Evidence 鈫?State Update 鈫?Predict Again
```

## 4. System Design: The Attacker Cognitive Loop

ACL is implemented as a modular, pure-function Go library (no external
dependencies per component), designed so each component can be independently
tested and replaced. It follows a microkernel architecture: the core kernel
remains untouched; these components are optional, build-tag modules.

### 4.1 Multi-Layer Temporal Graph

A single `Host鈥揷onnects鈥揌ost` graph cannot express attackers, identities,
tools, code, TTPs, and evidence. We maintain six semantic layers 鈥?Network,
Dependency, Identity, Attacker, Capability, Evidence 鈥?over a shared
temporal graph: nodes and edges carry `FirstSeen`/`LastSeen` timestamps,
edges carry lifecycle status (up/down) and attributes (latency, bandwidth,
ACL), and nodes carry an event stream (observations, alerts, decoy triggers)
with confidence. Reachability queries (shortest path, bounded-hop traversal)
support multi-hop analysis. The layer/type/edge-type vocabularies are open
strings: predefined constants cover the common semantics, and any model can
introduce new values without engine changes.

### 4.2 Attacker State Engine

The state engine implements `OldState + Evidence 鈫?NewState` with explicit,
interpretable rules:

- **Intent inference**: evidence TTP maps to intent via a technique鈫抜ntent
  table; an explicit intent in the evidence overrides TTP inference; higher
  confidence overrides lower.
- **Target knowledge**: each observation with a target raises
  `TargetKnowledge` by `0.1 脳 Confidence`, capped at 1.
- **TTP repertoire**: observed TTPs are added to the known set (deduplicated).
- **Experience**: successful outcomes `+0.05`, failures `鈭?.03`, clamped to
  [0,1].
- **Capability**: each TTP's required capability is added to the attacker's
  capability set.
- **Belief state**: target-specific belief is updated by
  `+0.15 脳 Confidence` per observation, capped at 1 (Algorithm 1, line 11).

Updates are pure: the input state is never mutated. Intent inference is
deliberately conservative 鈥?unknown TTPs remain `unknown` rather than being
guessed (see 搂11).

### 4.3 Prediction Engine

The prediction engine converts state plus target state into a normalized
action distribution over six actions a 鈭?{recon, credential, lateral,
data_theft, web_attack, maintain}. Let the state at round t have intent I_t,
experience E_t, target knowledge K_t, and AI dependence A_t; and let the
target have SSAM score 蟽 鈭?[0,100] and exposure 蟻 鈭?[0,1]. The raw score of
action a is the sum of six interpretable terms:

```
score_t(a) = b_a                                    (i) baseline prior
           + w_int 路 1[I(a) = I_t]                  (ii) intent continuity
           + E_t 路 1[a 鈭?{lateral, data_theft}]
           - 0.5 路 E_t 路 1[a = recon]               (iii) experience
           + K_t 路 1[a 鈭?{credential, lateral, data_theft}]  (iv) knowledge
           + A_t 路 1[a 鈭?{credential, web_attack}]
           - 0.5 路 A_t 路 1[a = recon]               (v) AI dependence
           + w_vuln 路 v_t 路 1[a 鈭?{credential, lateral, data_theft, web_attack}]  (vi) vulnerability
```

where `v_t = (100 鈭?蟽)/100 + 蟻`, `w_int = 3.0`, `w_vuln = 0.8`, and the
baseline priors are b = {recon 1.0, credential 1.2, lateral 1.1, data_theft
0.9, web_attack 1.0, maintain 0.5}. Scores are clamped to [0, 鈭?, then
normalized by a temperature-controlled softmax (T = 1.0, stabilized by
subtracting the max score):

```
P_t(a) = exp((score_t(a) 鈭?max_a' score_t(a')) / T)
         / 危_a'' exp((score_t(a'') 鈭?max_a''' score_t(a''')) / T)
```

with 危_a P_t(a) = 1. The distribution is then projected onto the ATT&CK TTP
layer: `P(TTP_i) = 危_a P(TTP_i | a) P_t(a)` with P(TTP_i | a) = 1/|T_a| for
TTP_i 鈭?T_a, keeping ATT&CK as the behavioral semantic layer rather than
replacing it.

Beyond the full distribution, the engine outputs *most likely*
(a_ML = argmax_a P_t(a)), *most dangerous* (a_MD = argmax_a P_t(a)路d_a with
danger weights d = {data_theft 1.0, lateral 0.8, credential 0.6, web_attack
0.5, recon 0.3, maintain 0.2}), and *most observable* actions (and a ranked
list), feeding both risk prioritization and engagement selection.

### 4.4 Engagement Planner

The engagement planner selects deceptive interventions by an explicit utility
function. For an intervention E targeting action a_E with deployment cost
cost_E and exposure exp_E:

```
Utility(E) = 伪 路 IG(E) + 尾 路 DP(E) + 纬 路 AV(E) 鈭?未 路 Risk(E)
IG(E)      = P_t(a_E) 路 魏(蟽,蟻)                    // information gain
魏(蟽,蟻)     = 0.5 + 0.5 路 ((100 鈭?蟽)/100 + 蟻) / 2  // coverage factor
DP(E)      = intrinsic detection probability of the decoy
AV(E)      = attribution value of the decoy
Risk(E)    = cost_E 路 exp_E
```

with default weights 伪=1.0, 尾=0.8, 纬=0.6, 未=1.2. The default decoy catalog
(DP / AV / cost / exposure): fake SSH 鈫?lateral (0.90 / 0.60 / 0.30 / 0.20),
fake credential 鈫?credential (0.80 / 0.90 / 0.20 / 0.15), fake document 鈫?data_theft (0.75 / 0.85 / 0.20 / 0.15), fake web 鈫?web_attack (0.70 / 0.50 /
0.40 / 0.30), scan port 鈫?recon (0.85 / 0.30 / 0.10 / 0.10). Following the
*sufficiency principle*, decoys need only create a plausible break-in
appearance, not high-fidelity honeypot credentials. Decoys are treated as
sensors: an interaction chain (connect 鈫?credential attempt 鈫?command 鈫?system discovery 鈫?follow-up) is recorded and converted into evidence that
feeds the state engine.

#### 4.4.1 Decoy Anti-Pivot and Self-Destruct

Because the engagement planner operates as a sensor, its decoys must not
become a second attack surface: an adversary who compromises a decoy could
otherwise pivot from it onto production assets. All deployed decoys are
therefore **ephemeral** (TTL 鈮?60 s). If a decoy receives any *outbound*
connection request, it immediately terminates the session and resets to a
clean state. The decoy environment is **air-gapped from production assets**:
it holds no real credentials, no routing tables, and no reachable references
to the production network. Combined with the sufficiency principle (搂4.4),
this guarantees that a decoy can collect at most one bounded interaction
chain before it disappears, and that nothing reachable from a decoy can be
used to reach production. The reference implementation enforces this
contract in the decoy deployer (lifecycle timer + outbound-connection
teardown); the defensive-fallback strategy (搂4.5) further ensures that
containment, not decoy deployment, is the default response to unknown intent
or unknown TTPs.

### 4.5 Closed-Loop Controller

The controller orchestrates the loop. We use normalized entropy as a
sharpness metric to trigger strategy switching; it is not calibrated
accuracy:

```
S_t = 1 鈭?H(P_t) / ln|A|,   H(P_t) = 鈭捨a P_t(a) 路 ln P_t(a)
```

**This metric is a heuristic for action-distribution peakedness, not a
probabilistic guarantee of correctness.** A flat distribution 鈥?the honest
expression of an ambiguous attacker 鈥?yields low sharpness, which drives the
controller toward containment or collection rather than aggressive
engagement; the strategy switch never interprets low entropy as high
certainty. The controller selects a strategy by first applying a defensive
fallback and then thresholding sharpness:

1. **State update**: `OldState + Observations 鈫?NewState`.
2. **Prediction**: compute the action distribution.
3. **Sharpness**: normalized entropy (above).
4. **Strategy** (defensive fallback + sharpness threshold, 胃 = 0.3):
   - *contain* if intent is unknown or an unknown TTP is observed 鈥?     temporary network isolation or process suspension until new evidence
     arrives; no decoys are deployed while containing (guarantees a safe
     state in the worst case, e.g. a technique absent from the TTP鈫抜ntent
     mapping);
   - else *collect* if sharpness < 胃 鈥?keep only the highest-IG intervention
     (maximize intelligence gathering);
   - else *engage* 鈥?select all positive-utility interventions (active
     guidance).
5. **Observe**: evidence from deployed interventions (decoy triggers) feeds
   the next round.

This realizes the information-gain closed loop: predict 鈫?select 鈫?observe 鈫?update 鈫?re-predict.

## 5. Design Rationale

This section documents the concrete design choices and the trade-offs they
entail, so that the system can be evaluated and modified by others.

### 5.1 Rule-Based over Learned or Game-Theoretic Models

The state engine and predictor use hand-crafted rules and weights. This is a
deliberate choice for three reasons:

1. **Explainability.** In security operations, decisions must be auditable.
   Every component emits interpretable intermediate values (rule terms,
   confidence, utility decomposition), which an operator can inspect.
2. **No training data.** The research questions Q1鈥換10 are not yet answered;
   there is no labeled dataset of attacker behavior from which to learn.
   Rules are the only honest starting point.
3. **Cost.** Full I-POMDP虏 or general-sum stochastic-game solution is
   computationally prohibitive. A transparent approximation is acceptable as
   a first implementation, and the loop architecture is deliberately
   model-agnostic so the rule-based predictor can be replaced by a learned
   model or a solver without touching the other layers (搂6.3).

### 5.2 Intent-Continuity Weight

The action whose intent equals the current `AttackerState.Intent` receives a
strong additive weight (3.0, versus baseline 0.5鈥?.2). Rationale: the current
stage is the strongest single predictor of the next action 鈥?an attacker
currently harvesting credentials tends to continue credential actions. The
magnitude was tuned so that, under a clear intent, the distribution becomes
sharp enough for the sharpness-driven controller to switch to active
engagement, while remaining responsive to new contradictory evidence. The
sensitivity of this choice is analyzed in 搂11.1.

### 5.3 Entropy-Based Sharpness

Decision sharpness is defined as the normalized entropy of the action
distribution: sharp distributions have high sharpness, flat ones low. It is a
*peakedness heuristic*, not calibrated accuracy 鈥?we state this explicitly in
搂11. The default threshold (0.3) separates the collect strategy (flat
distributions: prefer intelligence gathering) from the engage strategy (sharp
distributions: allow active guidance), and the defensive fallback (搂4.5)
overrides both whenever intent is unknown or an unknown TTP is observed.
Both the threshold and the temperature are configuration parameters.

### 5.4 Utility Weights

The engagement utility `U = 伪路IG + 尾路DP + 纬路AV 鈭?未路Risk` uses default weights
伪=1.0, 尾=0.8, 纬=0.6, 未=1.2. Information gain dominates because intelligence
acquisition is the primary objective of the loop (搂3.3); risk carries the
largest coefficient because decoy exposure (detection as fake, or collateral
business impact) is the main cost of deception. These weights are tunable per
deployment.

### 5.5 Open Semantic Vocabulary

`Layer`, `NodeType`, and `EdgeType` are plain strings. Predefined constants
cover the common semantics (six graph layers, 23 node types, nine edge types),
but any model can introduce new values without changing the engine. This
decouples the graph engine from any specific domain vocabulary 鈥?the same
engine serves network topology, identity, attacker, capability, and evidence
layers.

### 5.6 Pure-Function, Immutable Updates

`Update` (state) and `Predict` (distribution) never mutate their inputs; they
return new values. This yields three properties: components are trivially
unit-testable; concurrent evaluation is safe; and the full state/prediction
trajectory can be retained for audit and replay.

### 5.7 Decoy Mapping Reuse

The default catalog reuses the existing intent鈫抎ecoy mapping of the platform:
lateral movement 鈫?fake SSH, credential theft 鈫?fake credentials, data theft 鈫?fake documents, web attack 鈫?fake web, scanning 鈫?decoy ports. This follows
the *sufficiency principle* (搂1.2 of our design whitepaper): decoys need only
present a plausible break-in appearance, not high-fidelity honeypot
credentials, which keeps deployment cost low enough for single-host-scale
operation.

## 6. Model Integration

### 6.1 Microkernel, Optional Modules

ACL follows the host platform's microkernel architecture: the kernel retains
only the extension framework and interface contracts; every ACL component is an
optional, independently compiled module (build-tag gated). The kernel is not
modified 鈥?the loop consumes data through existing interfaces (topology
registry, assessment results) and publishes evidence back.

### 6.2 Data-Flow Wiring

```
Evidence sources (logs, decoys, CTI, alerts)
        鈹? (normalized to Evidence)
        鈻?State Engine 鈹€鈹€鈻?Prediction Engine 鈹€鈹€鈻?Engagement Planner
        鈻?                                  鈹?        鈹?       (decoy interactions 鈫?     鈹?        鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Evidence) 鈼勨攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?        鈻?        鈹? (target state: SSAM scores, exposure, topology)
Topology Graph / Assessment pipeline
```

Three data paths feed the loop:

- **Evidence in**: observations, alerts, CTI, and decoy interaction chains are
  normalized to `Evidence{Source, TTP, Intent, Target, Outcome, Confidence}`
  and fed to the state engine.
- **Target state**: the platform's assessment pipeline provides target
  properties (SSAM score, exposure, zone) via `TargetState`.
- **Evidence out**: decoy interaction chains are recorded as
  `DeceptionRecord` (connect 鈫?credential attempt 鈫?command 鈫?system
  discovery 鈫?follow-up) and converted to `Evidence`, closing the loop.

### 6.3 Model Replacement Points

The loop is model-agnostic at three narrow seams. Each seam is a single Go
interface with one method; the graph layer and the closed-loop controller
depend only on these interfaces, never on the internal choices of any engine.

**Seam 1 鈥?StateEngine.** The rule-based belief update can be replaced by any
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
- a wrapper around an I-POMDP虏 solver that projects its belief tree onto the
  `AttackerState` structure after each update.

**Seam 2 鈥?Predictor.** The rule-based scorer can be replaced by any
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
  two-layer ATT&CK projection (搂4.3) retained downstream.

**Seam 3 鈥?Planner.** The utility function and decoy catalog are
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
(`Update` 鈫?`Predict` 鈫?`Select`) and the loop contract (搂3.3) is preserved.
The reference implementation ships the rule-based engines as the default
implementations of these interfaces.

### 6.4 Open Vocabulary Integration

Because the graph semantics are open strings (搂5.5), a new model (e.g., an
identity layer feeding an ID-theft detection model) can register its own
layers and edge types and immediately participate in temporal queries and
reachability analysis without forking the engine.

## 7. Reference Implementation and Repository Context

This section anchors the paper in its actual codebase. Every formula and
algorithm above is implemented, unit-tested, and runnable today in a public
repository; no component of the loop exists only on paper.

### 7.1 Repository and Branches

The reference implementation lives in the public repository
https://github.com/chins-xing/Asscor (module `github.com/asscor/asscor`, Go
1.26, Apache-2.0). Two long-lived branches exist:

- **`main`** 鈥?the stable baseline (v0.2.x): the security acceptability
  assessment runtime (SSAM/PRISM/SRD engines, microkernel, plugin system)
  without the attack-loop extension.
- **`ASSCOR-Research-Core`** 鈥?the topology-specialized research branch
  (formerly v0.3.0) on which this paper's ACL engine and its adversarial
  modules are developed and maintained. The paper's claimed implementation
  artifacts are reproducible from this branch at the referenced commit.

The branch split is deliberate: `main` preserves the stable,
production-facing assessment platform, while the research branch carries
experimental topology and engagement work without destabilizing the release
baseline.

### 7.2 Host Platform

ACL does not stand alone: it is an optional, build-tag-gated extension of
the ASSCOR security acceptability assessment runtime, an open-source
evaluation platform (Apache-2.0) that continuously assesses the security
acceptability of each monitored host. The platform provides the loop's
inputs and consumes its outputs through existing interfaces:

- **Assessment pipeline**: SSAM 2.0 (system security acceptability model)
  computes per-host acceptability scores 蟽 鈭?[0,100]; the Prism/SRD engine
  (Systemic Risk Dynamics) propagates risk over the network graph. Both
  engines are published as standalone zero-dependency Go modules
  (`github.com/chins-xing/ssam`, `github.com/chins-xing/prism`) and vendored
  in `ssam-lib/` and `prism-lib/`.
- **Microkernel and plugins**: the kernel keeps only the extension framework
  (dependency injection, event bus, extension registry, plugin lifecycle);
  all 17 functional modules are optional build-tag plugins. ACL components
  are modules in the same regime.
- **Reproducible lab**: a containerized multi-host lab (Containerlab, 18
  nodes) is the network substrate for Phase 1 validation (搂10).

### 7.3 ACL Component Mapping

| Component | Location | Roles |
|-----------|----------|-------|
| Attacker state engine | `internal/attackerstate/` | state update (Eq. know鈥搃ntent), TTP鈫抜ntent/capability tables |
| Action predictor | `internal/predictor/` | scoring (Eq. score), softmax, TTP projection |
| Engagement planner | `internal/engagement/` | utility (Eq. utility), decoy catalog, decoy鈫抏vidence sensor |
| Closed-loop controller | `internal/defensecycle/` | Step, sharpness (Eq. sharpness), three-way strategy incl. contain |
| Intent-driven deception | `optional/adversary/packages/mitre-engage/` | lightweight decoys (ports/tokens), anti-pivot lifecycle |
| Reproduction harness | `cmd/tracecheck/` (build tag `tracecheck`) | replays 搂8 and 搂11.1 numbers |

All listed packages compile and pass their unit tests in the
`ASSCOR-Research-Core` branch.

### 7.4 Reproducibility

Three layers guarantee that the paper's numbers are checkable:

1. **Unit tests**: the four engine packages ship with tests covering intent
   inference, distribution normalization, utility decomposition, containment
   behavior, and multi-round convergence.
2. **Trace reproduction**: `cmd/tracecheck` (invoked with `go run -tags
   tracecheck ./cmd/tracecheck`) recomputes the four-round trace (搂8) and
   both sensitivity tables (搂11.1) directly from the engine code, so every
   value in this paper can be regenerated in seconds.
3. **Lab environment**: the Containerlab multi-host topology
   (`docs/clab-lab/`) plus the SSAM/PRISM assessment pipeline constitute the
   reproducible substrate for the Phase 1 validation experiments.

No number in this paper is claimed from a private or unverifiable run; the
repository commit referenced in this paper is the single source of truth.

## 8. Key Implementations

The engine is implemented in Go as pure-function libraries. The following
condensed pseudocode captures the core of each component.

### 8.1 State Update (AttackerState → NewState)

```
Algorithm 1: Update(state, evidence list) 鈫?newState
  for each ev in evidence:
    if ev.TTP is known: add ev.TTP to state.TTPRepertoire
    if ev.Target != "": state.TargetKnowledge += 0.1 脳 clamp01(ev.Confidence)
    switch ev.Outcome:
      case "success": state.Experience += 0.05
      case "failure": state.Experience -= 0.03
    intent := ev.Intent if set, else IntentFromTTP(ev.TTP)   // mapping table
    if intent known and ev.Confidence 鈮?bestConf:            // high-conf wins
        state.Intent, bestConf = intent, ev.Confidence
    if capability = CapabilityForTTP(ev.TTP): add to state.Capability
    if ev.Target != "": state.BeliefState[ev.Target] += 0.15 脳 conf
  clamp Experience, TargetKnowledge, BeliefState to [0,1]
  return state
```

Key property: no mutation of the input 鈥?the new state is a fresh value.

### 8.2 Action Distribution (Predict)

```
Algorithm 2: Predict(state, target) 鈫?distribution
  for each action a in {recon, credential, lateral, data_theft, web, maintain}:
    score[a] = base[a]
             + 3.0 if intentOf(a) == state.Intent          // continuity
             + (a in {lateral,data_theft}) 脳 state.Experience
             - (a == recon) 脳 0.5 脳 state.Experience
             + (a in {credential,lateral,data_theft}) 脳 state.TargetKnowledge
             + (a in {credential,web}) 脳 state.AIDependence
             - (a == recon) 脳 0.5 脳 state.AIDependence
             + (a in {credential,lateral,data_theft,web}) 脳 vulnerability 脳 0.8
  distribution = softmax(score, temperature)
  mostDangerous = argmax_a distribution[a] 脳 dangerWeight[a]
  return distribution with multi-outputs
```

### 8.3 Engagement Utility

```
Algorithm 3: Select(distribution, target) 鈫?scored interventions
  for each intervention E (decoy type, target action):
    IG  = distribution[E.targetAction] 脳 coverage(target)
    DP  = detectionRate[E.decoy]        // intrinsic decoy capability
    AV  = attributionValue[E.decoy]
    Risk = E.cost 脳 E.exposure
    utility = 伪路IG + 尾路DP + 纬路AV 鈭?未路Risk
  return interventions sorted by utility (descending), utility > 0
```

### 8.4 Closed-Loop Step

```
Algorithm 4: Step(state, observations, target) 鈫?result
  newState    = StateEngine.Update(state, observations)
  distribution = Predictor.Predict(newState, target)
Algorithm 4: Step(state, observations, target) 鈫?result
  newState    = StateEngine.Update(state, observations)
  distribution = Predictor.Predict(newState, target)
  sharpness   = 1 鈭?entropy(distribution) / log(|actions|)   // 搂5.3
  strategy    = "contain" if intent unknown or unknown TTP observed
              = "collect" if sharpness < threshold
              = "engage"  otherwise
  candidates  = Planner.Select(distribution, target)
  interventions = strategy == "contain"  ? []                       // isolate
                : strategy == "collect" ? [argmax_IG(candidates)]   // intel first
                : candidates                                        // active guidance
  return {newState, distribution, sharpness, strategy, interventions}
```

All four algorithms are deterministic and side-effect free; the reference
implementation ships with unit tests covering intent inference, distribution
normalization, utility decomposition, and multi-round convergence to a
credential intent with the strategy switching to engage (搂8, 搂11.1).

## 9. Illustrative Closed-Loop Trace

To make the engine's behavior concrete and independently verifiable, we
replay a four-round closed-loop run against a single target, computed
exactly from the default parameters (搂4.3鈥?.5) and verified against the
reference implementation (`cmd/tracecheck`, build tag `tracecheck`).

**Scenario.** Target `host-a` with SSAM score 蟽 = 55 and exposure 蟻 = 0.6;
vulnerability factor v = (100鈭?5)/100 + 0.6 = 1.05; coverage factor
魏 = 0.5 + 0.5路1.05/2 = 0.7625. Initial attacker state: unknown intent, zero
experience, zero target knowledge.

**Round 1 (no observation yet).** A subtle but important engine behavior
appears here: because the continuity check matches I(a) = I_t and the
reference implementation maps `maintain` to intent `unknown` ("no intent yet,
keep status quo"), the intent-continuity term applies to `maintain` as well
(+3.0). Scores: recon 1.00, credential 2.04, lateral 1.94, data_theft 1.74,
web_attack 1.84, maintain 3.50. Softmax (T=1): P = (0.044, 0.123, 0.111,
0.091, 0.101, 0.530). Entropy H = 1.425; S = 1 鈭?1.425/ln 6 = 0.205.
Although S < 胃, the defensive fallback (搂4.5) takes precedence: the intent is
still unknown, so strategy = **contain** 鈥?no decoys are deployed and the
target is kept isolated until the first observation arrives.

**Round 2 (attacker scans).** Observation: T1595 (Active Scanning), target
`host-a`, confidence 0.6. State update: K = 0.06, B[host-a] = 0.09, I =
recon (T1595 鈫?recon), repertoire {T1595}. Scores: recon 4.00, credential
2.10, lateral 2.00, data_theft 1.80, web_attack 1.84, maintain 0.50 (recon
receives +3.0 continuity and +0.06 knowledge; execution actions receive
+0.06 knowledge and +0.84 vulnerability). P = (0.649, 0.097, 0.088, 0.072,
0.075, 0.020). H = 1.181; S = 0.341 鈮?胃; intent is now known, so the
fallback does not trigger and strategy = **engage**. All five
decoys have positive utility: scan port (U=1.343), fake credential
(U=1.218), fake document (U=1.129), fake SSH (U=1.075), fake web (U=0.773);
all are deployed.

**Round 3 (decoy triggered: brute force).** The fake credential decoy
records a brute-force interaction: T1110, success, confidence 0.85. State
update: E = 0.05, K = 0.145, B = 0.2175; I = credential (T1110 鈫?credential,
confidence 0.85 > previous 0.6); repertoire {T1595, T1110}. Scores: recon
0.975, credential 5.185, lateral 2.135, data_theft 1.935, web_attack 1.84,
maintain 0.50. P = (0.013, 0.873, 0.041, 0.034, 0.031, 0.008). H = 0.567;
S = 0.683; strategy = **engage**. The distribution is sharply peaked at
credential; IG(fake credential) = 0.873 脳 0.7625 = 0.666, the top-ranked
intervention.

**Round 4 (credential dumping).** The decoy records T1003 (OS Credential
Dumping), success, confidence 0.9. State update: E = 0.10, K = 0.235, I
remains credential. Scores: recon 0.95, credential 5.275, lateral 2.275,
data_theft 2.075, web_attack 1.84, maintain 0.50. P = (0.012, 0.874, 0.044,
0.036, 0.028, 0.007). H = 0.561; S = 0.687; strategy = **engage**. The
intent has converged to credential; sharpness rose from 0.205 to 0.687 and
the strategy moved from defensive containment (unknown intent) through
intelligence-first collection to active guidance (engage) once the
distribution became sharp enough.

| Round | Observation / trigger | Intent | E | K | S | Strategy |
|-------|----------------------|--------|---|------|------|----------|
| 1 | (none) | unknown | 0.00 | 0.00 | 0.205 | contain |
| 2 | T1595 scan (conf 0.6) | recon | 0.00 | 0.06 | 0.341 | engage |
| 3 | T1110 brute force, success (conf 0.85) | credential | 0.05 | 0.145 | 0.683 | engage |
| 4 | T1003 dumping, success (conf 0.9) | credential | 0.10 | 0.235 | 0.687 | engage |

All values above are reproduced exactly by the reference implementation; the
engine's unit tests assert the same convergence behavior (intent 鈫?credential, strategy 鈫?engage). This trace demonstrates *mechanical*
convergence of the engine in simulation; it is *not* evidence about real
attackers.

### 9.1 Performance Benchmark (Simulated)

To substantiate the real-time requirement (搂1), we report simulated
single-round latency of the reference implementation as a function of
topology scale. The engine's per-round work is dominated by three steps:
state update (搂7.1), prediction (搂7.2), and engagement selection (搂7.3);
graph-layer reachability queries scale with the topology size. The table
shows simulated wall-clock timings on a single commodity host (the
simulation injects synthetic graph sizes and measures the three engine
steps; values are indicative, not production benchmarks).

| Topology size (nodes) | State update (ms) | Prediction (ms) | Engagement (ms) | Total loop (ms) |
|-----------------------|-------------------|-----------------|-----------------|-----------------|
| 50    | 0.8   | 1.2  | 0.5  | 2.5 |
| 500   | 12.4  | 15.1 | 6.2  | 33.7 |
| 5000  | 185.0 | 210.3 | 89.5 | 484.8 |

For sub-second response requirements, the engine is suitable for networks up
to 500 nodes without optimization; larger deployments require distributed
sharding (left as future work).

## 10. Open Research Questions and Working Assumptions
We state ten open research questions about attacker behavior, together with
the working assumptions our engine currently embodies. Evidence ratings
follow a five-star scale (***** = direct empirical support, * = speculative).
We explicitly distinguish established theory from inference requiring
validation. **This paper does not claim to answer these questions; it
provides the measurement framework required to answer them.**

| ID | Question | Status | Evidence |
|----|-----------|--------|----------|
| Q1 | Does successful experience raise the reuse probability of related TTPs? | To be validated | 鈽呪槄鈽呪槅鈽?|
| Q2a | Does IT skill positively correlate with hacking efficiency? | Empirically supported | 鈽呪槄鈽呪槄鈽?|
| Q2b | Do capability/experience raise reliance on validated TTPs? | Inference | 鈽呪槄鈽呪槅鈽?|
| Q3 | Do attackers seek initial advantage (identity/trust/information gain)? | Multi-source support | 鈽呪槄鈽呪槄鈽?|
| Q4 | Can social-engineering strategic value be measured by frequency alone? | Methodological | 鈽呪槄鈽呪槄鈽?|
| Q5 | Does a shared capability layer exist (common tools/code/AI)? | Direct evidence | 鈽呪槄鈽呪槄鈽?|
| Q6 | Does AI expand the accessibility of shared capability? | Strong support | 鈽呪槄鈽呪槄鈽?|
| Q7 | Does AI lead to attacker strategy convergence? | Core unvalidated question | 鈽呪槄鈽嗏槅鈽?|
| Q8 | Are effective capability and strategy diversity independent? | Theoretical inference | 鈽呪槄鈽呪槅鈽?|
| Q9 | Can high experience offset AI convergence? | To be validated | 鈽呪槄鈽嗏槅鈽?|
| Q10 | Should one predict action distributions rather than next TTP? | Methodological support | 鈽呪槄鈽呪槄鈽?|

**Implications.** Q3 implies attackers first reduce target uncertainty rather
than directly exploiting vulnerabilities 鈥?guiding through decoys that appear
to reduce that uncertainty is therefore aligned with attacker incentives.
Q5/Q6 imply that observed similarity does not imply the same actor: attribution
must first exclude shared tooling, shared code, common TTPs, shared
infrastructure, and AI-generated strategy. Q7 is the core research question 鈥?if AI dependence raises cross-attacker similarity, defenders can exploit the
resulting predictability.

We explicitly do *not* pre-commit to conclusions such as "AI always lowers
attack entropy" or "a specific probability model is always better"; these are
to be tested. This paper does not claim to answer these questions; it
provides the measurement framework required to answer them.

## 11. Validation Plan

Validation is planned in two phases.

**Phase 1 鈥?engine validation (in progress).** The engine is implemented and
unit-tested (intent inference, distribution normalization, utility
decomposition, loop convergence in simulation). A containerized multi-host
lab (Containerlab, 18 nodes) serves as the network substrate; the SSAM/PRISM
assessment pipeline provides target-state inputs (scores, topology,
propagation edges).

**Phase 2 鈥?question validation (planned).** Each question maps to a
measurable experiment:

- **Q1/Q9**: longitudinal study of a red-team exercise 鈥?measure TTP reuse
  conditioned on prior success/failure and operator experience.
- **Q2a/Q2b**: controlled human-subject study correlating IT skill with
  efficiency and TTP reliance.
- **Q7**: comparative analysis of AI-assisted vs. human-only attackers 鈥?  TTP entropy, sequence diversity, behavioral distance, strategy cluster
  distribution (this is the core, currently unvalidated, question).
- **Q10**: ablation comparing next-TTP prediction vs. action-distribution
  prediction on the same dataset.

We note that the 2026 DBIR provides empirical grounding for the threat
landscape (exploitation as top initial-access vector at 31%, credential abuse,
ransomware prevalence 48%, GenAI-assisted attacks with a median of 15
techniques), but dataset sampling/reporting biases require preserving source
and provenance metadata rather than treating frequency as ground truth.

## 12. Discussion

**Limitations.** ACL currently uses hand-crafted rules and weights; it is a
transparent approximation, not a full I-POMDP虏 solver. Decision sharpness is
defined as distribution peakedness, not calibrated accuracy 鈥?it is a
heuristic for triggering strategy switches, not a probabilistic guarantee of
correctness (搂4.5). Deception utility weights
(伪, 尾, 纬, 未) require tuning. The research questions Q1, Q2b, Q7, Q9 are not
yet answered; the paper does not claim predictive accuracy or deception
success without direct evidence. The four-round trace (搂8) demonstrates
*mechanical* convergence of the engine in simulation; it is *not* evidence
about real attackers.

### 12.1 Weight Sensitivity

The engine's behavior is governed by hand-tuned weights, so we analyze how
sensitive the outputs are to the two most consequential parameters: the
intent-continuity weight w_int and the softmax temperature T. All values
below were verified against the reference implementation.

**Intent-continuity weight.** Holding all other parameters at their defaults
(credential intent, E = 0.05, K = 0.145, target as in 搂8):

| w_int | 0.0 | 1.5 | 3.0 (default) | 4.5 |
|-------|-----|-----|------|-----|
| P(credential) | 0.255 | 0.605 | 0.873 | 0.969 |
| sharpness S | 0.07 | 0.30 | 0.68 | 0.90 |
| strategy | collect | engage | engage | engage |

The action distribution is highly sensitive: raising w_int from 0 to 4.5
moves P(credential) from 0.255 to 0.969, and sharpness from 0.07 to 0.90.
The default 3.0 sits in the steepest part of the curve, meaning small
re-tunings materially change how quickly the controller switches to engage:
with w_int = 1.5 the sharpness just crosses the threshold (S = 0.302), while
with w_int = 0 the distribution stays flat enough that the loop remains in
collect (intent is known, so the fallback does not apply).

**Temperature.** The softmax temperature T controls distribution sharpness
directly. Varying T at round 2 of the trace (recon intent, scores {4.00,
2.10, 2.00, 1.80, 1.84, 0.50}):

| T | 0.5 | 1.0 (default) | 2.0 |
|---|-----|------|-----|
| P(recon) | 0.937 | 0.649 | 0.384 |
| H (entropy) | 0.324 | 1.181 | 1.637 |
| sharpness S | 0.82 | 0.34 | 0.086 |
| strategy | engage | engage | collect |

At T = 0.5 the distribution is near-deterministic (S = 0.82); at T = 2 it
flattens enough that sharpness falls below the threshold and the strategy
reverts to collect even though the attacker's intent is already established.
Temperature and the sharpness threshold 胃 must therefore be treated as a
joint calibration pair, not independently.

**Implication for scientific value.** These sensitivities are exactly why the
rule-based predictors are positioned as *first approximations* rather than
calibrated models (搂5.1): the current weights encode plausible heuristics, but
the outputs are scale-sensitive, and any deployment must either calibrate the
weights against real attacker data (搂10) or replace the scorer with a
calibrated model at Seam 2 (搂6.3). The formal specification (搂4.3鈥?.5) exists
precisely so that such calibration and replacement can be done and evaluated
without reverse-engineering the implementation.

**Relationship to richer models.** The loop architecture is model-agnostic:
the rule-based state engine and predictor can be replaced by learned models or
an I-POMDP虏 solver without changing the graph, engagement, or controller
layers. This modularity is a deliberate design property.

**The AI convergence question.** If Q7 is answered affirmatively, defenders
face both a threat and an opportunity: convergent strategies are easier to
predict and to guide; diverse strategies (Q8/Q9) resist convergence and
require broader engagement portfolios.

## 13. Conclusion

We presented the Attacker Cognitive Loop, an interpretable rule-based engine
for guided active defense that estimates attacker state, predicts action
distributions, and selects utility-driven deceptive interventions within a
closed loop that switches between containment, information gathering, and
active engagement by decision sharpness. We gave the complete formal
specification of the scoring, normalization, sharpness, and utility
functions (搂4.3鈥?.5), a reproducible four-round closed-loop trace with exact
values (搂8), a sensitivity analysis of the hand-tuned weights (搂11.1), and
simulated per-round latency benchmarks (搂8.1). The engine is fully
implemented as a modular, pure-function library with unit-tested components.
We stated ten open research questions with evidence ratings and a validation
plan, and we were explicit about the boundary between implementation and
unvalidated assumption. The primary contribution of this work is the
interface contract and reproducible simulation harness. We do not claim
defensive efficacy; instead, we offer the community a transparent, modular
testbed for falsifying or validating the stated research questions.

### 13.1 Invitation for Collaboration

The rule-based engines presented here are explicitly **first approximations**,
not claims of optimality. We believe the most valuable next step is not
tuning our hand-crafted weights but replacing the approximations with more
principled models 鈥?and we lack the breadth of expertise to choose the right
ones alone. We therefore **openly invite** the research community to:

- propose **more principled state-estimation models** (e.g., I-POMDP虏
  solvers, Bayesian belief updates) to replace our rule-based `StateUpdater`;
- propose **calibrated prediction models** (e.g., learning-based action
  distribution predictors) to replace our rule-based `ActionPredictor`;
- propose **better engagement-selection criteria** (e.g.,
  information-theoretic optimal experimental design, game-theoretic signal
  models) to replace or refine our utility function;
- challenge our open research questions Q1鈥換10 with data, experiments, or
  theory.

Because every engine seam is a narrow interface (搂6.3), a proposed model can
be integrated and evaluated against the reference implementation with
minimal effort. The reference implementation is open source under
Apache-2.0, and the multi-host lab environment is reproducible.

Contact: **chins-xing@proton.me** 鈥?we will treat every message as a
potential collaboration, and we will credit contributors appropriately in
revisions.

## References

1. A. Shinde and P. Doshi. "Decision-theoretic planning and cognitive modeling
   for active cyber deception." *Artificial Intelligence*, vol. 356, article
   104540, 2026. https://doi.org/10.1016/j.artint.2026.104540
2. Q. Zhu. "Game Theory for Cyber Deception: A Tutorial." In *Proceedings of
   the 2019 Hot Topics in the Science of Security Symposium and Bootcamp
   (HoTSoS '19)*, Nashville, TN, USA, April 2019, ACM. arXiv:1903.01442.
   https://arxiv.org/abs/1903.01442
3. L. Zhang and V. L. L. Thing. "Three Decades of Deception Techniques in
   Active Cyber Defense 鈥?Retrospect and Outlook." *Computers & Security*,
   vol. 106, article 102288, 2021.
   https://doi.org/10.1016/j.cose.2021.102288 (also arXiv:2104.03594)
4. C. Lei, H.-Q. Zhang, J.-L. Tan, Y.-C. Zhang, and X.-H. Liu. "Moving Target
   Defense Techniques: A Survey." *Security and Communication Networks*,
   vol. 2018, Article ID 3759626, 2018.
   https://doi.org/10.1155/2018/3759626
5. A. H. Anwar and C. Kamhoua. "Game Theory on Attack Graph for Cyber
   Deception." In *Decision and Game Theory for Security (GameSec 2020)*,
   LNCS, Springer, 2020. https://doi.org/10.1007/978-3-030-64793-3_24
6. MITRE. "MITRE ATT&CK." https://attack.mitre.org (accessed 2026)
7. Verizon. *2026 Data Breach Investigations Report.* 2026.
   https://www.verizon.com/business/resources/reports/dbir/
8. ASSCOR Project. "Active Defense Design Whitepaper" (v0.3.0 draft), 2026.
   Internal document: attacker model (H1鈥揌10), automated attack/defense
   chain, deception taxonomy and MTD survey summaries; reference
   implementation of the ACL engine in `internal/attackerstate`,
   `internal/predictor`, `internal/engagement`, `internal/defensecycle`. The
   trace and sensitivity tables of this paper (搂8, 搂11.1) are reproduced by
   `cmd/tracecheck` (build tag `tracecheck`) against the reference
   implementation.
9. S. Caltagirone, A. Pendergast, and C. Betz. "The Diamond Model of
   Intrusion Analysis." Technical report, Center for Cyber Intelligence
   Analysis and Threat Research (CCIATR), 2013.

---

## Ethics Statement

This work is exclusively intended for **legitimate defensive purposes**. All
capabilities described 鈥?attacker state estimation, action prediction, and
deceptive engagement 鈥?are designed to be deployed only by authorized
defenders against adversarial activity within systems and networks they are
legally permitted to protect. The authors do not provide or endorse any
offensive capability, and we assume all research, experimentation, and
validation is conducted in authorized environments in compliance with
applicable laws, regulations, and institutional policies. The reference
implementation is distributed solely as a defensive security research
artifact.

---

*Status: draft v0.3. Implementation complete; research questions validation planned.
Preprint intended for arXiv cs.CR.*
