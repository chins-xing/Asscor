# Chapter 3 — Conceptual Model

## 3.1 Introduction

The previous chapter introduced the problem addressed by Asscor.

This chapter defines the conceptual model that guides the entire assessment process.

Rather than viewing security assessment as vulnerability counting, Asscor models assessment as a reasoning process over operational evidence.

The goal is not to determine whether vulnerabilities exist.

The goal is to determine whether the current operational state remains acceptable.

---

# 3.2 Core Concepts

Asscor is built upon five fundamental concepts.

```
Evidence

↓

Context

↓

Policy

↓

Assessment

↓

Decision
```

Each concept represents a distinct responsibility within the assessment process.

---

# 3.3 Evidence

Evidence represents observable security facts.

Evidence does not contain decisions.

Evidence does not contain recommendations.

Evidence simply describes reality.

Examples include:

- Open network ports
- Disabled SELinux
- Missing backups
- Weak password policy
- Failed integrity checks
- Missing audit logs
- Exposed management interfaces

Evidence is therefore objective.

It answers:

```
What is happening?
```

---

# 3.4 Context

Evidence alone is insufficient.

The same evidence may produce different conclusions under different environments.

For example,

SSH exposed to the Internet.

```
Internet-facing server
```

may be unacceptable.

While the same configuration inside an isolated laboratory network may be acceptable.

Context therefore modifies the interpretation of evidence.

It answers:

```
Where does the evidence exist?
```

Typical context includes:

- Business environment
- Network exposure
- Asset criticality
- Trust boundary
- Organizational role

---

# 3.5 Policy

Policy defines organizational expectations.

Unlike evidence,

policy is normative rather than descriptive.

For example,

Evidence:

```
Password length = 8
```

Policy:

```
Minimum password length = 12
```

Policy therefore determines whether evidence satisfies organizational requirements.

Different organizations may define different policies.

Consequently,

Acceptability becomes organization-dependent rather than universally fixed.

---

# 3.6 Assessment

Assessment represents the reasoning process.

It transforms evidence, context, and policy into an operational judgment.

Conceptually,

```
Assessment

=

f(

Evidence,

Context,

Policy

)
```

The assessment process itself remains independent from any specific assessment algorithm.

This abstraction allows future assessment engines to coexist.

Examples include:

- SSAM
- Future probabilistic models
- Bayesian engines
- Rule-based engines

---

# 3.7 Decision

Decision is the final output of the assessment process.

Unlike raw scores,

decision represents an operational recommendation.

Examples include:

```
Acceptable

Restricted

Unacceptable
```

Scores are implementation details.

Operational decisions represent the true objective.

---

# 3.8 Separation of Responsibilities

The conceptual model deliberately separates responsibilities.

```
Evidence

↓

collect reality

Context

↓

describe environment

Policy

↓

define expectations

Assessment

↓

reason

Decision

↓

support operation
```

Each layer has a single responsibility.

This separation simplifies future evolution.

---

# 3.9 Assessment Pipeline

The complete assessment workflow can be summarized as:

```
Evidence Collection

↓

Evidence Normalization

↓

Context Resolution

↓

Policy Matching

↓

Assessment

↓

Decision

↓

Recommendation
```

Each stage may evolve independently.

Assessment engines therefore remain decoupled from evidence providers.

---

# 3.10 Engineering Mapping

Although this chapter focuses on concepts rather than implementation,

the conceptual model naturally maps onto the project architecture.

```
Evidence

↓

Collectors
Plugins
Adapters

↓

Assessment

↓

SSAM

↓

Decision

↓

Reports
API
CLI
```

The engineering implementation should remain a realization of the conceptual model rather than defining the model itself.

---

# 3.11 Design Principles

The conceptual model follows several design principles.

## Evidence First

Assessment begins with evidence rather than assumptions.

---

## Context Aware

Evidence must always be interpreted within operational context.

---

## Policy Driven

Organizational policy determines acceptability.

---

## Engine Independent

Assessment algorithms may evolve without changing the conceptual model.

---

## Decision Oriented

The final objective is operational decision support rather than score generation.

---

# 3.12 Chapter Summary

This chapter introduced the conceptual foundation of Asscor.

The assessment process is modeled as a transformation from observable evidence into operational decisions through context-aware reasoning and policy evaluation.

Subsequent chapters will describe how this conceptual model is realized by the assessment engine and runtime architecture.