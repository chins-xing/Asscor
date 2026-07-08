# Chapter 7 — Evidence Architecture

## 7.1 Introduction

Security assessment begins with evidence.

Every assessment result ultimately depends on the quality, completeness, and consistency of the evidence available.

Therefore, Asscor treats evidence as the foundation of the entire assessment process.

Rather than tightly coupling assessment engines to individual scanners or data sources, Asscor introduces an evidence-oriented architecture that separates data acquisition from security reasoning.

This separation allows assessment engines to evolve independently from evidence providers.

---

# 7.2 Why Evidence Matters

Modern security environments produce information from many independent systems.

Examples include:

- Vulnerability scanners
- Configuration inspectors
- Asset inventories
- SIEM platforms
- EDR systems
- Cloud security services
- Threat intelligence feeds
- Compliance auditing tools

Each system provides observations.

None of them directly provides operational decisions.

Asscor therefore treats every observation as evidence rather than as a final conclusion.

---

# 7.3 Definition of Evidence

Within Asscor,

Evidence is defined as:

> An observable security fact describing the current state of an information system.

Evidence must satisfy several characteristics.

It should be:

- Observable
- Reproducible
- Traceable
- Explainable

Evidence should never contain operational decisions.

Instead,

it provides factual inputs for later reasoning.

---

# 7.4 Evidence Model

Conceptually,

every evidence object contains four logical elements.

```
Evidence

├── Subject
├── Observation
├── Metadata
└── Source
```

Where:

Subject

describes the assessment target.

Observation

describes the observed security fact.

Metadata

provides timestamps, confidence, and contextual information.

Source

identifies where the evidence originated.

---

# 7.5 Evidence Lifecycle

Evidence follows its own lifecycle inside the runtime.

```
Collection

↓

Normalization

↓

Validation

↓

Storage

↓

Assessment

↓

Archiving
```

Each stage performs a distinct responsibility.

Assessment engines should consume normalized evidence rather than interacting directly with collectors.

---

# 7.6 Evidence Normalization

Different tools describe similar observations differently.

For example,

```
OpenSSH Enabled

SSH Running

Port 22 Listening
```

may all describe related operational characteristics.

Normalization converts heterogeneous outputs into a consistent internal representation.

This greatly simplifies downstream reasoning.

---

# 7.7 Evidence Independence

Evidence should remain independent from assessment engines.

The same evidence may be consumed by:

- SSAM
- SRD
- Future probabilistic models
- AI-assisted reasoning engines

This separation allows multiple assessment models to coexist without modifying evidence providers.

---

# 7.8 Evidence Categories

Evidence naturally falls into several categories.

## Configuration Evidence

Examples:

- password policy
- firewall configuration
- authentication settings

---

## Exposure Evidence

Examples:

- exposed services
- internet accessibility
- attack surface

---

## Operational Evidence

Examples:

- backup status
- monitoring
- logging
- availability

---

## Threat Evidence

Examples:

- known exploitation
- active campaigns
- threat intelligence

---

## Trust Evidence

Examples:

- integrity validation
- signature verification
- software provenance

---

# 7.9 Evidence Quality

Not all evidence has equal quality.

Future implementations may consider:

- Confidence
- Freshness
- Completeness
- Reliability

These attributes influence how evidence participates in assessment.

Evidence quality should not be confused with evidence content.

---

# 7.10 Evidence Traceability

Every assessment result should be explainable.

Therefore,

every decision should be traceable back to the evidence that produced it.

Conceptually,

```
Decision

↓

Assessment

↓

Evidence
```

This traceability improves transparency,

supports auditing,

and simplifies debugging.

---

# 7.11 Evidence Graph

Although the current implementation primarily processes evidence independently,

future versions may organize evidence as interconnected relationships.

Conceptually,

```
Evidence A

↓

Evidence B

↓

Evidence C

↓

Assessment
```

An evidence graph allows complex relationships between observations to be represented explicitly.

This becomes particularly valuable when modeling cascading failures or systemic security conditions.

---

# 7.12 Relationship to Runtime

The runtime manages evidence.

Assessment engines interpret evidence.

This distinction separates infrastructure from reasoning.

Conceptually,

```
Runtime

↓

Evidence

↓

Assessment Engine

↓

Decision
```

---

# 7.13 Relationship to Plugins

Plugins generate evidence.

They should not directly produce operational decisions.

Examples include:

- host inspection plugins
- cloud collectors
- compliance parsers
- CTI adapters

Regardless of implementation,

their responsibility remains identical.

Produce reliable evidence.

---

# 7.14 Design Principles

The evidence architecture follows several principles.

## Evidence First

Assessment begins with facts rather than assumptions.

---

## Source Independent

Evidence remains independent of individual tools.

---

## Engine Independent

Evidence can be consumed by multiple assessment engines.

---

## Traceable

Every assessment result should reference supporting evidence.

---

## Explainable

Operators should understand which observations influenced every decision.

---

# 7.15 Long-Term Vision

As Asscor evolves,

evidence may become a shared language across the ecosystem.

Rather than exchanging scanner-specific outputs,

components exchange standardized evidence objects.

Conceptually,

```
Collectors

↓

Evidence

↓

Assessment

↓

Decision

↓

Recommendation
```

This architecture enables interoperability between independent components while preserving a consistent assessment model.

---

# 7.16 Chapter Summary

Evidence represents the foundation of the Asscor assessment model.

By separating evidence collection from assessment reasoning,

the architecture achieves greater modularity,

improved explainability,

and long-term extensibility.

Future assessment engines may evolve,

but evidence remains the stable foundation upon which operational decisions are built.