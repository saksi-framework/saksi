# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the Saksi framework.
ADRs document important architectural decisions so contributors can understand
what was decided, why it was decided, and what tradeoffs were accepted.

Link to this process at `docs/adr/README.md`.

## When to Write an ADR

Write an ADR when a decision meaningfully affects the architecture, operation,
security posture, data model, dependencies, contributor workflow, or long-term
maintenance of the project.

An ADR is usually appropriate for:

- Selecting or replacing a major framework, platform, protocol, or dependency.
- Changing how core data is stored, validated, shared, or secured.
- Defining project-wide engineering practices that affect future contributors.
- Accepting a notable tradeoff, limitation, or risk.
- Superseding a previous architectural decision.

Small implementation details, routine bug fixes, and local refactors usually do
not need ADRs unless they create a lasting project-level precedent.

## Numbering

ADRs use four-digit, zero-padded numbers and a short lowercase slug:

```text
0001-record-architecture-decisions.md
0002-example-future-decision.md
```

Numbers are assigned sequentially and never reused, even if an ADR is later
superseded. Keep filenames stable after review so other documents can link to
them reliably.

## Review Expectations

New ADRs should be opened for review before the decision is treated as final.
Review should focus on whether the context is accurate, whether the decision is
clear, and whether the consequences include the most important tradeoffs.

An ADR should be accepted only after the relevant maintainers and affected
contributors have had a reasonable opportunity to review it. If a decision is
urgent, record that urgency in the Context section and follow up with review as
soon as practical.

## Status Transitions

Each ADR must include a Status section. BalotaChain uses these statuses:

- Proposed: The ADR is under discussion and is not yet final.
- Accepted: The decision has been approved and should guide implementation.
- Superseded: A later ADR replaces this decision.

The normal transition is:

```text
Proposed -> Accepted -> Superseded
```

When an ADR becomes Superseded, update its Status section with a link to the ADR
that replaces it. Do not delete superseded ADRs; they preserve the history and
reasoning behind the project.
