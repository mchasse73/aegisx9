# 15. Brokered agent credentials and per-project identities

- Status: Accepted (owner decisions 2026-10-29)
- Date: 2026-10-29
- Amends: ADR 0013

## Context

ADR 0013 makes every credential short-lived and scoped to one approved action, but the
executor still holds that credential while it works. When the executor is an AI agent, design
as if it is fully hijacked (ADR 0011): anything it holds can be printed, pasted into a ticket,
committed or sent to a model. Even a short-lived credential can be misused inside its window.

Agents also need an identity of their own. If they run as a person's account, or as one
account that owns every repository, nobody can tell agent actions from human ones, and one
leaked session reaches everything.

The owner's goal: "by issuing a 'fake' or one time use token we never have to worry about
leaked tokens".

## Decision

**Agents never hold a real credential.**

1. **Bound handle.** An agent session gets an opaque handle. It works only from that session,
   on that host, for the calling process and user, and the host agent checks the caller's
   identity on every use. On its own, a copied handle is useless.
2. **Single-use broker token per request.** For each request, the host agent exchanges the
   handle for a single-use broker token. A replayed token is refused.
3. **The broker holds the only real login.** It authenticates with workload identity, so
   the broker itself needs no stored secret. For a vendor without short-lived credentials, the
   ADR 0013 fallback still applies: a narrowly scoped secret kept only in Vault and used only
   by the broker, never by an agent. For each request it obtains a single-use, least-privilege child credential
   (the ADR 0013 mechanisms) and uses it itself. That credential never leaves the broker.
4. **Detectable by design.** Handles carry a fixed prefix that secret scanners and log
   scanners recognise. A sighting anywhere (code, logs, tickets, chat, model traffic) revokes
   the handle at once and raises an alert.
5. **Logged from day one.** Every issue, use, denial, replay and wrong-caller attempt is a
   structured, tamper-evident audit event with alert rules. These events feed bypass detection.

**Per-project identities.**

6. Each project gets an application service identity and a project group, held in the identity
   provider. They are synced to hosts as local non-login users. Hosts use the synced copy, not a
   live lookup, so they keep working when the identity provider is down.
7. AI sessions run as the project's application identity. People join the groups of the
   projects they work on and work in those repositories as themselves. No single account owns
   every repository.

**Onboarding and one workflow.**

8. A new project is provisioned automatically from a template that includes only its own secret
   space and shared read access. Anything beyond the template waits for a hardware-key-signed
   approval through the gate (ADR 0012).
9. AegisX9 exposes this as one documented workflow: **register, grant, log in, use, request
   more**. One stable login command covers every login, and its backend can change without the
   workflow changing. There are no per-environment variants.

## Relationship to ADR 0013

ADR 0013 still governs how credentials are minted: dynamic, scoped, shortest lifetime,
single-use where the platform allows it. This ADR changes who holds them. For an AI agent,
the minted credential stays inside the broker, and the agent holds only a bound handle. 0013's
delivery mechanisms, such as response-wrapped tokens, apply between the broker and the
platform, never between the broker and an agent. A trusted, non-AI executor may still receive
a credential under 0013.

## Consequences

- The credential broker (#112) becomes a request broker for agents: it performs, or proxies,
  the action with the child credential, rather than handing the credential over.
- A host component (the host agent) is needed to bind handles to callers, and its trust in the
  host's process and user identity is part of the threat model.
- Leaked handles stop being an incident class in themselves. A sighting is an alert and an
  automatic revocation, not a rotation project.
- Secret scanning rules must include the handle prefix, both in AegisX9's own pipeline and in
  the customer guidance.
- The identity provider holds service identities and groups, so there is no per-seat directory
  product to buy. Host sync has to be monitored for drift.
- The reference deployment is customer zero. AegisX9's own gate issues agent credentials this
  way once the interface stabilises.
