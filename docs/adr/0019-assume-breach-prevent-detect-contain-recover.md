# 19. Assume breach: every control prevents, detects, contains and recovers

- Status: Accepted (owner decisions 2026-10-29)
- Date: 2026-10-29

## Context

The design so far is mostly about preventing misuse. The owner: "the system currently is
purely being designed to prevent security breaches, however we must also assume that systems
have been breached be it intentional or a exploit of some kind. We need to close those gaps as
well". Any component can be compromised: an agent, a host, a credential, an insider, or
AegisX9 itself.

## Decision

1. **Cross-cutting rule.** Every control answers four questions: how it **prevents**, how a
   failure or bypass is **detected**, how the damage is **contained**, and how the system
   **recovers**. From this ADR on, each ADR ends with an "Assume breach" section next to
   "Scalability" (ADR 0016).
2. **Tamper-evident audit.** Audit events ship outbound (ADR 0017) to append-only (WORM)
   storage the customer chooses. The approval chain's head is anchored externally on a
   schedule, and a gap, a rewrite or a missed anchor raises an alert.
3. **Misuse detection,** in addition to bypass detection (ADR 0011):
   - privilege used outside a job's window;
   - a credential or handle used from an unexpected source;
   - changes to guardrail, policy or protection files;
   - new listeners or new egress destinations on a governed host;
   - **honeytokens:** canary agent handles and credentials that nothing legitimate uses, so any
     use of one is a critical alert.
4. **One-action containment ("kill switch").** One signed action per agent, project, host or
   identity revokes every credential type it holds (handles, broker tokens, virtual keys,
   Vault leases, App tokens, cloud sessions) and pauses its execution. The action is audited
   and reversible only through the gate.
5. **Just-in-time privilege for automation.** No standing root or admin. Privilege is granted
   per job, scoped, and expires with the job. Artifacts are signed and carry an SBOM.
6. **Recovery.** Immutable backups, scheduled restore drills with recorded results, an incident
   response runbook, and tabletop exercises.

**Acceptance checklist** (every component, every release): the four questions answered;
audit events reach WORM storage; at least one honeytoken per tier; the kill switch is proven
against a test identity; no standing privileged credential exists.

## Scalability

Detection rules run on the shared event stream, so they scale with the log pipeline. The kill
switch writes revocations to the shared stores (ADR 0016), so every replica enforces them on
its next check. Anchoring is one scheduled job under a lease.

## Assume breach

This ADR is the assume-breach rule. If the audit pipeline itself is compromised, the external
anchor and WORM copy still show the gap or the rewrite.

## Consequences

- Detection rules D1-D19 (#113) grow to cover rule 3. Honeytokens need inventory and rotation.
- The kill switch is a Phase 2 deliverable alongside the gate, because the gate is what
  issues the credentials it revokes.
- Restore drills and tabletops are recurring operational work, tracked with dates.
