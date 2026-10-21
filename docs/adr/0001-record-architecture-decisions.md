# 1. Record architecture decisions

- Status: Accepted
- Date: 2026-10-21

## Context

AegisX9 is run like an enterprise product. Decisions about architecture, delivery and
security need to be traceable for reviewers, auditors and future maintainers.

## Decision

We record significant decisions as Architecture Decision Records (ADRs) in
`docs/adr/`, using the lightweight format described by Michael Nygard: title, status,
context, decision, consequences. ADRs are numbered sequentially and never deleted; a
reversed decision gets a new ADR that supersedes the old one. Long-form documentation
lives in the project's documentation site; ADRs stay in the repository next to the code
they govern.

## Consequences

- Every PR that changes architecture, delivery or a security control links or adds an ADR.
- Lowering a red-team threshold or relaxing an admission policy requires an ADR.
