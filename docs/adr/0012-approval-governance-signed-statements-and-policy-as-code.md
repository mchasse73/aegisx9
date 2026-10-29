# 12. Approval governance: signed statements and policy-as-code

- Status: Proposed
- Date: 2026-10-29

## Context

The build and action gate (ADR 0011) holds a change until it is approved. Two things decide
whether that is worth anything: what an approval actually proves, and whether an organisation
can shape its approval process without weakening it.

The reference implementation in the homelab already has these properties:

- hardware-key signatures over a hash of the exact request;
- a fixed policy that decides gated against auto-approved;
- a rule that a relayed "yes" never counts.

Review found these gaps:

- keyword matching on free text, which was evaded once;
- a single approver;
- date-only freshness with no nonce;
- no re-check between approval and execution;
- user verification (the PIN) not enforced by the server, since fixed.

Organisations differ in who approves, how many, how emergencies work, who is told and where
logs go. All of it must be configurable, and none of it may become a way around the gate.

## Decision

**Typed requests.** A request carries typed fields:

- action
- resource
- environment
- exposure
- data class
- requester
- declared change, for example the commit range or plan hash

Policy decides on these fields, never on keywords in free text. A request that can't be typed
is gated at the highest risk tier.

**Approval statement.** An approval is a signature over a canonical statement containing:

- the request id and the hash of its canonical spec;
- the policy that applies (threshold N, eligible approver group);
- the requester;
- a single-use server nonce;
- an expiry;
- the decision.

The server keeps one record per signer: principal, credential id, user-verification flag,
signature counter, time and method (WebAuthn or SSH signature). Expiry and the spec hash are
checked when the approval is made, again when the executor starts, and before each
irreversible step. A spec that changes after review is not covered.

**Signing methods.** In the browser, WebAuthn uses `userVerification: "required"` and the
hardware key on the approver's own machine. The RP ID is the console's exact hostname, the
user handle is the approver principal, and each key gets its own credential. On the command
line, SSH signatures from resident hardware-backed keys are used, and the server checks the
user-verification flag. Enrolling an approver credential requires an existing
hardware-signed approval. A web session alone can never add a key.

**Configurable governance**, all as versioned policy-as-code:

- **Who:** roles and groups per project, environment and risk tier; code-owner mapping;
  time-boxed delegation.
- **How many:** N-of-M thresholds and separation of duties. The requester can never approve
  their own request. Two approvers from different groups can be required.
- **Emergency changes (break-glass):** time-boxed, with extra notifications and a mandatory
  retrospective review that is tracked to completion.
- **Notifications:** email, chat (Slack, Teams), paging, ticket updates and code-host checks,
  with routing rules and escalation timers. Notifications carry identifiers and links, never
  secrets or full request bodies.
- **Logging and routing:** tamper-evident (hash-chained, anchored in write-once storage), per
  tenant, exported to Loki/Grafana, CloudWatch or a SIEM.
- **Changing the policy:** every change to approval policy is itself a gated, multi-approver,
  signed policy-as-code change. It must not be able to approve itself.

**Rollout.** v1 carries the full statement format and enforces one approver plus separation of
duties. N-of-M is enabled by policy later, without a format change.

## Consequences

- The UI is for review only. The signature is the authority, so a compromised console
  session can't approve anything.
- Approval fatigue becomes a measured risk: approval latency, approve-without-open rates and
  canary requests are monitored (ADR 0011, bypass detection).
- The policy engine choice (for example Cedar or OPA) is an open question for the owner. The
  typed request model is engine-independent.
