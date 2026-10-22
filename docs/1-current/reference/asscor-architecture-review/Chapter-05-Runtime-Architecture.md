# Chapter 5 — Runtime Architecture

## 5.1 Introduction

Previous chapters introduced the assessment model and the assessment engine.

However, an assessment engine alone is insufficient for building a production-oriented security platform.

Asscor therefore introduces a runtime architecture responsible for orchestrating assessment activities throughout the system lifecycle.

Unlike traditional command-line scanners that execute once and terminate, Asscor treats assessment as a continuously managed runtime.

This distinction significantly influences the overall system architecture.

---

# 5.2 Runtime Philosophy

The runtime exists to coordinate rather than perform assessment.

Assessment engines answer:

```
How should evidence be evaluated?
```

The runtime answers:

```
When should assessment occur?

Which components participate?

How are services managed?

How are plugins coordinated?
```

Therefore,

the runtime becomes the operating environment of the assessment model.

---

# 5.3 Runtime Responsibilities

The runtime is responsible for infrastructure rather than business logic.

Its primary responsibilities include:

- lifecycle management
- service registration
- dependency coordination
- plugin loading
- event dispatching
- scheduler management
- configuration watching
- health monitoring

Importantly,

the runtime should never contain assessment rules.

---

# 5.4 Runtime Lifecycle

The runtime follows a structured lifecycle.

```
Initialization

↓

Configuration Loading

↓

Service Registration

↓

Plugin Discovery

↓

Dependency Resolution

↓

Runtime Start

↓

Assessment Execution

↓

Graceful Shutdown
```

Each stage has a clearly defined responsibility.

This improves maintainability and simplifies debugging.

---

# 5.5 Service Registry

Services within the runtime communicate through registration rather than direct coupling.

Conceptually,

```
Service

↓

Registry

↓

Consumer
```

Instead of hardcoding dependencies,

components discover services through the runtime registry.

This approach reduces compile-time coupling and improves extensibility.

---

# 5.6 Event-Driven Coordination

The runtime coordinates components using events.

Typical events include:

- startup
- shutdown
- assessment completed
- plugin loaded
- configuration changed
- health status updated

Rather than invoking components directly,

events enable loose coupling between subsystems.

Future extensions therefore require minimal modification of existing components.

---

# 5.7 Plugin Runtime

Plugins execute inside the runtime rather than alongside it.

```
Runtime

├── Plugin A
├── Plugin B
├── Plugin C
└── ...
```

The runtime manages:

- loading
- initialization
- execution
- isolation
- shutdown

Plugins therefore become managed runtime objects instead of standalone executables.

---

# 5.8 Scheduler

Security assessment is inherently continuous.

The runtime scheduler determines:

- when assessments execute
- execution intervals
- retry strategies
- concurrent tasks

Separating scheduling from assessment logic keeps the engine deterministic while allowing flexible operational policies.

---

# 5.9 Configuration Management

Configuration is treated as a runtime resource.

Changes may trigger:

- service reload
- plugin refresh
- policy updates
- assessment recalculation

This design supports long-running deployments without requiring full process restarts.

---

# 5.10 Fault Isolation

The runtime should prevent individual failures from propagating throughout the system.

Examples include:

- plugin failures
- collector failures
- assessment failures
- adapter failures

Whenever possible,

components should fail independently.

The runtime remains responsible for maintaining overall system availability.

---

# 5.11 Architectural Characteristics

The runtime demonstrates several characteristics commonly found in infrastructure software.

Examples include:

- dependency inversion
- inversion of control
- lifecycle management
- event-driven architecture
- service discovery
- plugin orchestration

These patterns distinguish Asscor from conventional security scanners.

---

# 5.12 Runtime Boundary

The runtime deliberately excludes assessment semantics.

It should not determine:

- evidence weights
- scoring algorithms
- operational policies
- security rules

Instead,

its responsibility is execution management.

Conceptually,

```
Runtime

↓

Execution
```

while

```
Assessment Engine

↓

Reasoning
```

This separation preserves architectural clarity.

---

# 5.13 Architectural Risks

During the review,

one architectural concern became increasingly visible.

The Kernel is gradually accumulating responsibilities from multiple layers.

Potential symptoms include:

- business logic entering infrastructure
- plugin management mixed with assessment logic
- runtime services depending on engine internals

If this trend continues,

the Kernel may become a "God Object."

To avoid this,

the Kernel should remain an infrastructure coordinator rather than a business component.

---

# 5.14 Long-Term Evolution

As the project evolves,

the runtime may become capable of supporting multiple assessment engines simultaneously.

For example,

```
Runtime

├── SSAM
├── SRD
├── Future Engine
└── AI Reasoner
```

Each engine participates through a common runtime contract.

The runtime therefore remains stable while assessment technologies evolve independently.

---

# 5.15 Chapter Summary

Asscor's runtime architecture transforms the project from a command-line security tool into a continuously managed assessment platform.

Its primary responsibility is orchestration rather than assessment.

By separating runtime infrastructure from assessment reasoning,

the project achieves a modular architecture capable of supporting long-term evolution without coupling infrastructure to individual assessment algorithms.