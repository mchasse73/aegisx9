# 12. Approval governance: signed statements and policy-as-code

- Status: Accepted (owner decisions 2026-10-29)
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

**The signature is the only authority.** Ticket states, code-host reviews, chat messages, a
change-advisory board and the console session are workflow or mirrors. An approval recorded
anywhere else is a detection signal, never an authorization.

**Risk tiers T0-T4.** Every typed request is assigned a tier (T0 informational up to T4:
public exposure, destructive changes, identity, secrets and trading-adjacent systems). An
unknown or untyped request gets the most restrictive tier. Free text can only raise a tier,
never lower it.

**Approval statement (v2).** An approval is a signature over a canonical statement containing:

- the request id and the hash of its canonical spec;
- the policy lines: policy bundle version hash, risk tier, matching rule, threshold N and
  eligible approver group;
- the requester line: the requester, the agent's owner, and anyone else excluded from
  signing;
- a single-use server nonce, consumed when the threshold is met;
- an expiry;
- the decision.

The server keeps one record per signer: principal, credential id, user-presence and
user-verification flags, signature counter, time and method (WebAuthn or SSH signature).
Expiry and the spec hash are checked when the approval is made, again when the executor
starts, and before each irreversible step. A spec that changes after review is not covered.
A signature counter that goes backwards is rejected and raises an alert.

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
- **Emergency changes (break-glass):** still signed, but with a smaller quorum. They expire
  within one hour, need an incident id, page security, and require a retrospective review
  within 72 hours, tracked to completion. They auto-revert where that is safe. Break-glass can
  never change policy, signers or connector permissions. Recovering a dead control plane uses
  split physical custody.
- **Notifications:** email, chat (Slack, Teams), paging, ticket updates and code-host checks,
  with routing rules and escalation timers. Notifications carry identifiers and links, never
  secrets or full request bodies.
- **Logging and routing:** tamper-evident (hash-chained, anchored in write-once storage), per
  tenant, exported to Loki/Grafana, CloudWatch or a SIEM.
- **Changing the policy:** policy lives in git as signed bundles, and the engine loads only
  approved bundle hashes. A change goes through a stricter meta-policy: two policy admins and
  one security signer, with the change's authors excluded, a cooling-off delay, and a diff
  that shows which rules got tighter or looser. A policy change can never approve itself.
- **Inheritance only tightens:** organisation, then business unit, then project, then
  environment. A lower level can add requirements but never remove them. Relaxing a rule
  needs a signed, time-boxed exception at organisation level.

**Where the gate lives (owner, 2026-10-29).** AegisX9 builds its own approval service in this
repository. The homelab's existing build-request system stays its internal instance, and
becomes customer zero: it migrates onto the AegisX9 gate once Phase 2 is proven.

**Rollout.** v1 carries the full statement format and enforces one approver plus separation of
duties. N-of-M is enabled by policy later, without a format change.

**Single-approver tenant (owner, 2026-10-29).** Customer zero has one human approver, and agents
request on that person's behalf, so "requester ≠ approver" cannot fully hold. This is recorded
explicitly in policy as a declared single-approver tenant. T3 and T4 approvals add a
cooling-off delay and require the second, separately kept hardware key, so one stolen key
cannot approve alone. It is revisited when a second approver joins.

## Consequences

- The UI is for review only. The signature is the authority, so a compromised console
  session can't approve anything.
- Approval fatigue becomes a measured risk: approval latency, approve-without-open rates and
  canary requests are monitored (ADR 0011, bypass detection).
- Circumvention is detected by 19 rules (D1 to D19, epic #113). Each has a signal, source,
  detection and response, and needs a weekly known-positive test before it counts as working.
- The detailed design, with sourced vendor facts, is kept in the platform team's internal
  architecture documentation.
- The policy engine choice (for example Cedar or OPA) is an open question for the owner. The
  typed request model is engine-independent.
