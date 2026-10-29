# 13. Short-lived, single-use secrets and per-action credentials

- Status: Accepted (owner decisions 2026-10-29); amended by ADR 0015 (agents hold bound
  handles, never the credential)
- Date: 2026-10-29

## Context

The owner's standing rule is that every credential is short-lived (ADR 0010: JWTs at most 15
minutes, virtual keys at most 24 hours and rotated). The build and action gate (ADR 0011)
extends the question to every system an agent touches: code hosts, ticketing, clouds, CI.
Long-lived personal tokens in agents are the most common way an AI-driven pipeline leaks or
gets misused.

## Decision

AegisX9 issues credentials per action, for the shortest time the platform allows, and single
use where the platform supports it. All of them are brokered by Vault. Static secrets are
never handed to an agent.

| System | Mechanism |
|---|---|
| Vault | Dynamic secrets; response-wrapped, single-use tokens to deliver anything; AppRole `secret_id` with `num_uses=1`, bound to the executor's address range |
| GitHub | GitHub App installation tokens (1 hour, narrowed to the repositories and permissions of the request, revoked after use), never personal access tokens |
| Atlassian | Service-account OAuth 2.0 client credentials with scoped tokens (3LO where a user context is required) |
| AWS | STS (`AssumeRole` / web identity) with session policies and a permissions boundary |
| CI | OIDC federation (for example GitHub Actions to the cloud and to Vault), with claims bound to the environment and the reusable workflow, no stored cloud keys |
| Model providers | Workload identity federation (ADR 0009) |

Guardrails:

- **Scope:** a credential is scoped to the approved request's resources and actions. The
  executor can do only what that credential allows.
- **Lifetime:** at most the request's expiry. Where the platform allows it, the credential is
  revoked as soon as the action completes.
- **Handling:** secrets travel by stdin, environment or 0600 files, never argv. They are
  never logged, and are inspected by name and length only.
- **Monitoring:** token creation outside the broker is a bypass signal.

For a vendor that offers no short-lived credential, a per-vendor fallback is recorded: the
narrowest scope available, the shortest rotation the vendor allows, storage only in Vault, use
only through the broker, and extra bypass monitoring.

## Consequences

- Each connector (ADR 0014) must document how it gets short-lived credentials. A connector
  that needs a long-lived secret does not clear the trust bar until there is a compensating
  control.
- Vault becomes a hard dependency of the gate, so its degraded mode (fail closed for actions)
  is decided per decision type.
