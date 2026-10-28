# Chapter 1 — Project Overview

## 1.1 Introduction

Asscor is an open-source security assessment runtime designed to evaluate the operational acceptability of information systems.

Unlike traditional vulnerability scanners or compliance auditing tools, Asscor does not attempt to answer whether a system contains vulnerabilities or whether it satisfies a specific security baseline.

Instead, it attempts to answer a different question:

> **Can this system still be considered acceptable for continued operation under its current state?**

This distinction fundamentally changes the assessment objective.

Rather than measuring vulnerability severity, Asscor evaluates the security acceptability of an operational system by integrating multiple categories of evidence into a unified assessment process.

---

# 1.2 Project Positioning

During this review, it became increasingly clear that Asscor should not be categorized as a conventional security scanner.

Instead, it is better understood as an assessment runtime.

Traditional security products generally follow a pipeline similar to:

```
Scanner
    ↓
Findings
    ↓
Report
```

Asscor instead follows a reasoning-oriented workflow:

```
Evidence
    ↓
Assessment
    ↓
Decision
```

The assessment engine therefore becomes the central component rather than the scanner itself.

Scanners, plugins, CTI feeds, compliance profiles, and ATT&CK mappings all become evidence providers instead of decision makers.

---

# 1.3 Design Philosophy

Several engineering principles consistently appear throughout the repository.

## Runtime-Oriented

Assessment is treated as a continuous runtime activity instead of a one-time execution.

This is reflected in the project's lifecycle management, plugin architecture, service registration, event system, and long-running kernel.

---

## Extensibility First

Almost every subsystem is designed around interfaces rather than implementations.

Provider registration.

Plugin loading.

Assessment engines.

Output adapters.

This significantly improves long-term maintainability.

---

## Separation of Responsibility

The project attempts to separate:

- Assessment
- Runtime
- Plugin
- Adapter
- Reporting
- Knowledge

Although some responsibilities are beginning to converge inside the Kernel, the overall architectural direction remains consistent.

---

# 1.4 Architectural Characteristics

From an architectural perspective, Asscor already exhibits characteristics commonly found in mature infrastructure software.

Examples include:

- Dependency Injection
- Provider Pattern
- Hook System
- Event Bus
- Plugin Runtime
- Service Registry
- Lifecycle Management
- Configuration Watching
- Circuit Breaking
- Rate Limiting

These components indicate that Asscor is evolving beyond a simple command-line scanner.

---

# 1.5 What Asscor Is NOT

One of the most important observations during this review is defining what Asscor should not become.

Asscor should not attempt to become:

- another vulnerability scanner
- another compliance checker
- another CVSS calculator
- another Linux benchmark tool

Competing on the number of rules or supported checks would place the project in direct competition with mature ecosystems that have accumulated knowledge over decades.

Instead, Asscor should focus on its own assessment model.

---

# 1.6 Core Innovation

The review identified three primary innovations.

## Assessment Target

Traditional systems evaluate vulnerabilities.

Asscor evaluates operational acceptability.

Changing the assessment target represents the most significant conceptual contribution of the project.

---

## Runtime Assessment

Assessment is modeled as an ongoing runtime process rather than a static scan.

This design enables future integration with continuously changing evidence.

---

## Context-Aware Evaluation

The same security evidence may lead to different assessment results depending on organizational policy and operational context.

This moves beyond purely rule-based scoring.

---

# 1.7 Current Maturity

From an engineering perspective, the implementation demonstrates characteristics usually associated with production-oriented open-source infrastructure.

Strengths include:

- clean modularization
- interface-driven architecture
- extensibility
- maintainability
- consistent engineering style

The project has already moved beyond the stage of a typical student assignment.

---

# 1.8 Current Limitations

Despite its engineering maturity, the theoretical model remains less mature than the implementation.

Several concepts still require formal definition.

These include:

- Acceptability
- Evidence
- Context
- Policy
- Decision Boundary

Without precise definitions, future theoretical expansion may become increasingly difficult.

---

# 1.9 Overall Assessment

The review concludes that Asscor should be viewed as a security assessment runtime rather than a security scanning tool.

Its long-term value does not primarily originate from the number of implemented checks.

Instead, its value lies in establishing a new assessment objective centered around operational acceptability.

If the theoretical framework continues to mature alongside the engineering implementation, Asscor has the potential to evolve from an engineering project into a reusable assessment methodology.