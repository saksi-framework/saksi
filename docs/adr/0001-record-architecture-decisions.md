# ADR-0001: Record Architecture Decisions

## Status

Accepted

## Context

BalotaChain needs a lightweight, durable way to capture architectural decisions
that affect future contributors. Without a shared record, important reasoning can
be lost in issues, pull requests, chats, or commit history.

The project also needs a stable process that other contributor documentation can
link to without requiring issue #4 to edit files owned by other issues.

## Decision

BalotaChain will use Architecture Decision Records stored in `docs/adr/`.

Each ADR will follow the template in `docs/adr/template.md`, use sequential
four-digit numbering, and include the sections Status, Context, Decision, and
Consequences. The ADR process is documented in `docs/adr/README.md`, which is
the stable path other project documentation can reference.

## Consequences

Architectural decisions will have a consistent home in the repository, making the
project history easier to understand and review.

Contributors will need to decide when a change is significant enough to require
an ADR. This adds a small amount of process, but it should reduce ambiguity for
decisions with long-term impact.

Future ADRs can supersede earlier ones without deleting historical context.
