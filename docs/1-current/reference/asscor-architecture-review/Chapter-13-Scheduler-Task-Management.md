# Chapter 13 — Scheduler & Task Management

## 13.1 Introduction

Continuous security assessment requires more than a single execution.

Evidence changes.

Policies evolve.

Threat intelligence updates.

Plugins become available.

Assessment therefore becomes a continuous runtime activity rather than a one-time task.

To support this execution model,

Asscor introduces a runtime scheduler responsible for coordinating assessment tasks throughout the system lifecycle.

The scheduler determines **when**, **how**, and **under what conditions** work should be performed.

---

# 13.2 Design Objectives

The scheduler is designed to achieve several engineering goals.

- Continuous assessment
- Predictable execution
- Resource efficiency
- Failure recovery
- Execution isolation

Unlike assessment engines,

the scheduler never evaluates security.

Its responsibility is execution management.

---

# 13.3 Task Model

Every executable activity is represented as a task.

Conceptually,

```
Task

├── ID
├── Name
├── Type
├── Status
├── Schedule
├── Priority
├── Retry Policy
└── Metadata
```

The scheduler operates on tasks rather than business logic.

---

# 13.4 Task Lifecycle

Every task follows a well-defined lifecycle.

```
Created

↓

Queued

↓

Scheduled

↓

Running

↓

Completed

↓

Archived
```

If failures occur,

additional transitions may include:

```
Failed

↓

Retry

↓

Running
```

or

```
Failed

↓

Cancelled
```

---

# 13.5 Scheduling Strategies

Different workloads require different scheduling policies.

Examples include:

## Periodic

```
Every 5 minutes
```

Suitable for:

- Host assessment
- Configuration inspection

---

## Event Driven

```
Configuration Changed

↓

Assessment
```

Suitable for:

- Policy updates
- Plugin installation

---

## Manual

Triggered directly by operators.

---

## One-Time

Executed once during runtime initialization.

---

# 13.6 Task Priorities

Not all tasks have equal importance.

Example:

```
Critical

↓

High

↓

Normal

↓

Low
```

The scheduler should prioritize runtime stability before background activities.

---

# 13.7 Concurrency

Multiple assessment tasks may execute simultaneously.

The scheduler should manage:

- worker pools
- concurrency limits
- resource allocation
- queue management

Business components should remain unaware of execution concurrency.

---

# 13.8 Retry Policy

Failures should not immediately terminate execution.

Typical retry strategies include:

- Fixed Retry
- Exponential Backoff
- Limited Retry Count
- Manual Recovery

Retry behavior belongs to the scheduler rather than individual tasks.

---

# 13.9 Dependency Scheduling

Some tasks require prerequisites.

Example:

```
Load Policy

↓

Collect Evidence

↓

Assessment

↓

Report Generation
```

The scheduler should enforce dependency ordering automatically.

---

# 13.10 Event Integration

The scheduler naturally integrates with the Event Bus.

For example,

```
PolicyUpdated

↓

Event Bus

↓

Scheduler

↓

Assessment Task
```

This architecture enables reactive assessment rather than fixed polling.

---

# 13.11 Failure Isolation

A failed task should not affect unrelated runtime activities.

Examples include:

- Plugin failure
- Collector timeout
- Report generation failure

The scheduler isolates execution failures while allowing the runtime to continue operating.

---

# 13.12 Monitoring

The scheduler should expose operational metrics such as:

- queued tasks
- running tasks
- failed tasks
- retry count
- execution latency

These metrics improve operational visibility.

---

# 13.13 Future Evolution

Future scheduler capabilities may include:

- distributed scheduling
- workflow orchestration
- dependency graphs
- task priorities
- cluster-wide execution

The scheduler should evolve independently from assessment engines.

---

# 13.14 Engineering Assessment

The scheduler represents one of the core infrastructure components of the Asscor runtime.

Its separation from assessment logic significantly improves modularity.

As the project expands,

the scheduler will become increasingly important for supporting continuous assessment across heterogeneous environments.

---

# 13.15 Chapter Summary

The scheduler transforms Asscor from a task-oriented application into a continuously operating assessment platform.

By separating execution management from security reasoning,

the architecture improves scalability,

fault isolation,

and long-term maintainability.