# Chapter 2 — Problem Statement

## 2.1 Background

Modern security assessment has become increasingly fragmented.

Different tools focus on different objectives.

Some identify vulnerabilities.

Some verify compliance.

Some analyze attack techniques.

Some collect threat intelligence.

Each tool solves a specific problem.

However, security operation decisions rarely depend on a single source of information.

Instead, they require combining multiple forms of evidence into a single operational judgment.

This gap motivates the design of Asscor.

---

# 2.2 Existing Assessment Paradigms

Current security assessment methods can generally be categorized into several groups.

## Vulnerability Assessment

Examples include:

- CVE
- CVSS
- Vulnerability Scanners

Primary objective:

```
How severe is this vulnerability?
```

These approaches focus on individual weaknesses.

They do not directly evaluate whether the overall system remains suitable for continued operation.

---

## Compliance Assessment

Examples include:

- CIS Benchmark
- NIST SP 800-53
- ISO 27001
- OpenSCAP

Primary objective:

```
Does the system comply with predefined requirements?
```

Compliance determines conformance to standards.

It does not necessarily represent operational security.

A fully compliant system may still become operationally unacceptable.

---

## Threat Intelligence

Threat intelligence attempts to answer:

```
What threats currently exist?
```

Its output is valuable evidence.

However, threat intelligence itself does not provide operational decisions.

---

## Attack Knowledge

Frameworks such as MITRE ATT&CK describe attacker behavior.

They answer:

```
How does an attacker operate?
```

Again, this provides context rather than assessment.

---

# 2.3 The Missing Question

Throughout this review, one observation repeatedly emerged.

Existing approaches answer many questions.

For example:

```
How serious is the vulnerability?

How many weaknesses exist?

Which controls are missing?

Which attack techniques are applicable?
```

Yet one question is often left unanswered.

```
Can this system still be considered acceptable for operation?
```

This question becomes increasingly important for operational environments where shutting down every vulnerable system is unrealistic.

---

# 2.4 Why Vulnerability Severity Is Not Enough

Vulnerability severity and operational acceptability are different concepts.

A system containing high-severity vulnerabilities may remain acceptable under certain operational conditions.

Conversely, a system with relatively few vulnerabilities may become unacceptable because of poor operational resilience, trust degradation, or business constraints.

Therefore,

```
Severity ≠ Acceptability
```

The assessment objective itself changes.

---

# 2.5 Why Compliance Is Not Enough

Compliance verifies implementation against predefined controls.

Operational acceptability evaluates whether the current system state satisfies organizational operational expectations.

Compliance is therefore an important evidence source.

It is not the final assessment result.

This distinction prevents Asscor from competing directly with compliance frameworks.

Instead,

Compliance becomes one possible input.

Acceptability becomes the final output.

---

# 2.6 Operational Decision Gap

Modern security teams continuously receive information from multiple systems.

Examples include:

- vulnerability scanners
- EDR
- SIEM
- CTI
- compliance reports
- cloud security platforms
- asset inventories

These systems produce evidence.

However, security operators must still answer a practical question.

```
Should this system continue operating?
```

Existing tools rarely provide a unified answer.

This creates an operational decision gap.

---

# 2.7 Assessment Objective

Based on the observations above, Asscor defines a different assessment objective.

Instead of evaluating vulnerabilities,

Asscor evaluates operational acceptability.

The assessment target therefore shifts from individual weaknesses toward the operational state of an information system.

Conceptually,

```
Vulnerability
        ↓
Evidence
        ↓
System State
        ↓
Operational Decision
```

---

# 2.8 Scope

Asscor intentionally limits its scope.

It does not attempt to replace:

- vulnerability management
- compliance auditing
- threat intelligence
- attack knowledge bases

Instead,

it integrates outputs from these systems into a unified assessment process.

Therefore,

Asscor should be viewed as an assessment runtime rather than another security scanner.

---

# 2.9 Problem Definition

This review summarizes the research problem addressed by Asscor as follows.

> How can heterogeneous security evidence be transformed into a consistent operational assessment describing whether an information system remains acceptable for continued operation?

This question becomes the foundation for all subsequent architectural decisions.

---

# 2.10 Chapter Summary

Current security assessment methods focus on vulnerabilities, compliance, or threat intelligence individually.

Asscor proposes a different assessment objective.

Rather than asking whether a system is vulnerable,

it asks whether the current operational state remains acceptable.

This shift in assessment objective forms the conceptual foundation of the entire project and motivates the architectural design discussed in the following chapters.