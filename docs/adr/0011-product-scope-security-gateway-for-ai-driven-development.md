# 11. Product scope: the security gateway for AI-driven development

- Status: Accepted
- Date: 2026-10-29

## Context

AegisX9 began as a secure LLM gateway (ADR 0010 and earlier): one choke point for model calls,
with guards, budgets and an audit trail. Running the homelab estate showed where most of the
risk actually is. AI agents increasingly *act*: they open pull requests, run builds, deploy
and change infrastructure. A model call can leak data, but an agent action can change
production. Teams also lack one place to see what AI is doing across their delivery
pipeline.

The owner set the scope on 2026-10-29. AegisX9 is the security gateway for builds, designed
specifically to control AI development, and it gives DevOps, developers and security one view
of what is being done with AI: which builds, pull requests and other changes are happening or
have happened, for small, medium and large organisations.

## Decision

AegisX9 is two enforcement points and one authority:

1. **LLM gateway** (built, Phase 1): authenticates callers with short-lived tokens, applies
   input and output guards, model allowlists, budgets and rate limits, and audits every call.
2. **Build and action gate** (Phase 2 onwards, the core of the product): every change an agent
   or a person wants to make passes through it. Examples are a pull request merge, a build, a
   deployment and an infrastructure action. Typed policy classifies the request, and it either
   passes or waits for an approval bound to that exact change (ADR 0012).
3. **Approval and audit authority:** a signed approval is the only authority for a gated
   change. Tickets, chat messages and UI sessions are workflow, never authority. Every request,
   decision and outcome goes into a tamper-evident audit trail that the one view is built on.

Supporting principles that apply everywhere:

- Secrets are short-lived and, where the platform allows it, single-use (ADR 0013).
- Enforcement happens at the credential and network layer. Parsing command strings or free
  text is defence in depth only, never the control.
- Every ticket, tool output and retrieved document is untrusted input. Design as if the agent
  is fully hijacked; credentials, leases and the gate bound the damage.
- Integrations never require inbound exposure by default (ADR 0014).
- Bypass attempts are detected continuously: direct pushes, approvals made outside the
  system, protection or policy edits, token creation, rejected-signature bursts,
  rubber-stamping, guarded commands, disabled webhooks, and changes that don't match the
  declared request.

Integration order: GitHub first, then Jira, then a connector framework for other vendors.

## Consequences

- The roadmap is rebuilt around the gate: Phase 2 is the build gate for GitHub, Phase 3 Jira
  and change management, Phase 4 the tool/action gateway for agents (MCP), Phase 5 the
  connector framework, and Phase 6 the governance pack and dashboards.
- The admin console (#93) becomes the one view. Its first module is the approval console
  (#108).
- The LLM gateway stays a first-class component. Its audit events feed the same trail.
- The homelab estate is customer zero: the gate must govern this project's own builds and
  infrastructure changes before it is offered to anyone else.
