# Chapter 4 — Assessment Engine

## 4.1 Introduction

The previous chapter introduced the conceptual model of Asscor.

The assessment process was defined as a transformation from evidence into operational decisions through context-aware reasoning and policy evaluation.

This chapter introduces the mechanism responsible for performing that transformation.

Within the current implementation, this mechanism is provided by the Security State Assessment Model (SSAM).

SSAM represents the first assessment engine implemented within the Asscor ecosystem.

It should be viewed as an implementation of the assessment model rather than the model itself.

---

# 4.2 Assessment Objectives

The primary objective of an assessment engine is to transform heterogeneous evidence into a consistent operational judgment.

The engine is not responsible for:

- collecting evidence
- defining policy
- generating threat intelligence
- discovering vulnerabilities

Instead, it performs reasoning.

Conceptually:

```
Evidence

↓

Assessment Engine

↓

Decision
```

---

# 4.3 Assessment Inputs

The assessment engine operates on three categories of input.

## Evidence

Observable security facts.

Examples:

- insecure configuration
- missing backup
- weak authentication
- excessive exposure

---

## Context

Operational environment information.

Examples:

- internet exposure
- trust zone
- business criticality
- asset importance

---

## Policy

Organizational expectations.

Examples:

- minimum password length
- backup requirements
- authentication standards
- operational requirements

---

# 4.4 Domain-Based Assessment

The current implementation organizes assessment into domains.

Examples include:

- Attack Surface
- Operation Trust
- Resilience
- Business Continuity

Each domain evaluates a specific aspect of operational security.

This decomposition improves explainability.

Instead of producing a single opaque score,

the system can explain which operational characteristics contributed to the final assessment result.

---

# 4.5 Assessment Process

The assessment workflow can be summarized as:

```
Evidence

↓

Domain Evaluation

↓

Domain Scores

↓

Aggregation

↓

Final Assessment

↓

Decision
```

This structure allows individual domains to evolve independently while preserving a stable overall process.

---

# 4.6 Aggregation

Domain results are aggregated into an overall assessment outcome.

The aggregation mechanism combines multiple dimensions of operational security into a unified result.

Examples include:

- exposure
- resilience
- trust
- continuity

The purpose of aggregation is not mathematical precision.

Its purpose is operational consistency.

The resulting assessment should support decision-making rather than produce theoretically perfect scores.

---

# 4.7 Explainability

One of the most important design goals of the assessment engine is explainability.

Every assessment result should be traceable.

Operators should be able to answer:

```
Why was this system considered unacceptable?
```

or

```
Which evidence contributed to this decision?
```

Without explainability,

assessment results become difficult to trust.

---

# 4.8 Deterministic Assessment

The current implementation follows a deterministic model.

Given:

- identical evidence
- identical context
- identical policy

The engine should produce the same result.

This property improves reproducibility and simplifies operational adoption.

---

# 4.9 Engine Independence

Although SSAM is currently the primary assessment engine,

the architectural model intentionally separates assessment concepts from assessment algorithms.

Future implementations may include:

- Bayesian assessment engines
- graph-based inference engines
- probabilistic models
- AI-assisted assessment engines

As long as they accept the same conceptual inputs and produce comparable operational decisions,

they remain compatible with the Asscor assessment model.

---

# 4.10 Assessment Boundaries

The assessment engine intentionally avoids several responsibilities.

It does not:

- predict future attacks
- estimate attacker behavior
- forecast risk propagation
- replace threat intelligence

These concerns belong to other systems.

The engine focuses exclusively on evaluating the current operational state.

Conceptually:

```
Current State

↓

Assessment

↓

Decision
```

Rather than:

```
Future State

↓

Prediction

↓

Forecast
```

This distinction becomes important when integrating future models such as SRD.

---

# 4.11 Relationship to SRD

Assessment and prediction are separate concerns.

SSAM answers:

```
What is the current operational acceptability?
```

SRD is expected to answer:

```
How may acceptability evolve over time?
```

Therefore:

```
SSAM

↓

Present
```

and

```
SRD

↓

Future
```

should be viewed as complementary rather than hierarchical.

Neither replaces the other.

---

# 4.12 Design Principles

The assessment engine follows several principles.

## Evidence Driven

Assessment begins with observable facts.

---

## Explainable

Results must be traceable.

---

## Deterministic

Identical inputs produce identical outputs.

---

## Modular

Assessment domains remain independently maintainable.

---

## Replaceable

Assessment algorithms may evolve without changing the assessment model.

---

# 4.13 Current Limitations

Several limitations remain.

Examples include:

- domain interactions are simplified
- evidence confidence is not explicitly modeled
- conflicting evidence handling remains limited
- organizational policy modeling can be expanded

These limitations do not invalidate the model but identify future areas for improvement.

---

# 4.14 Chapter Summary

This chapter introduced the assessment engine responsible for transforming evidence into operational decisions.

Within the current implementation, this role is fulfilled by SSAM.

However, SSAM should be understood as an implementation of the broader assessment model rather than the model itself.

The long-term value of Asscor therefore lies not in a specific scoring algorithm, but in the ability to consistently transform security evidence into operationally meaningful decisions.