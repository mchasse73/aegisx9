# 14. Integrations without inbound exposure, and a connector trust bar

- Status: Proposed
- Date: 2026-10-29

## Context

The gate needs events and enforcement points in the systems where change happens. Most
vendors deliver events by webhook, which normally means a public inbound endpoint: one more
attack surface and a public-exposure decision every time. The owner's integration order is
GitHub first, Jira second, then an open plan for other vendors. Every new connector also
widens what AegisX9 can be tricked into doing.

## Decision

**No inbound exposure by default.** Connectors poll vendor APIs, or pull from an outbound-only
relay. An inbound route needs the owner's explicit public-exposure approval through the
platform team's process. Event payloads are untrusted input.

**GitHub first (Phase 2):**

- a GitHub App with installation tokens;
- a required check run that only AegisX9 can complete, enforced by rulesets;
- environments with deployment protection rules;
- Actions OIDC for workloads;
- CODEOWNERS mapped to approver groups.

The gate records the declared change (commit range, plan hash) and compares it with what
actually lands.

**Jira second (Phase 3):** issues, releases and fixVersions, and service-desk approvals and
change management, used as workflow only. A ticket in "Approved" proves only that a field
changed; the signature is the authority. Links: Jira issue ↔ pull request ↔ request ↔
approval ↔ deployment.

**Connector framework (Phase 5):** a connector interface with a capability matrix. The matrix
records which events it can observe, which enforcement points it controls, how it gets
short-lived credentials (ADR 0013), how bypass attempts are detected, and its rate limits and
failure modes.

A connector is trusted only when it clears this bar:

- short-lived credentials;
- least-privilege scopes;
- no inbound exposure, or an approved exception;
- event payloads treated as untrusted;
- a fail-closed enforcement path;
- bypass signals covered;
- a gated-access test that proves it from outside;
- documented vendor limits.

The candidates, in no fixed order after GitHub and Jira:

- **Code hosts:** GitLab, Bitbucket, Azure DevOps and Forgejo.
- **Ticketing:** ServiceNow and Linear.
- **Notifications:** Slack, Teams and PagerDuty.
- **Identity:** Okta, Entra and Authentik.
- **SIEMs:** Splunk, Sentinel, Datadog and Elastic.

## Consequences

- Polling adds latency and API cost. The capability matrix records each connector's
  freshness, so policy can require a fresh state check before an irreversible step.
- Hosting, namespaces, DNS, identity-provider apps and integration credentials for the homelab
  deployment are requested from the platform team, not created by this project.
