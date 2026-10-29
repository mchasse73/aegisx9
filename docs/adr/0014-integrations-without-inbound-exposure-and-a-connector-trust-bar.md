# 14. Integrations without inbound exposure, and a connector trust bar

- Status: Accepted (owner decisions 2026-10-29)
- Date: 2026-10-29

## Context

The gate needs events and enforcement points in the systems where change happens. Most
vendors deliver events by webhook, which normally means a public inbound endpoint: one more
attack surface and a public-exposure decision every time. The owner's integration order is
GitHub first, Jira second, then an open plan for other vendors. Every new connector also
widens what AegisX9 can be tricked into doing.

## Decision

**No inbound exposure: polling only (owner, 2026-10-29).** Connectors poll vendor APIs, using
conditional requests: GitHub ETag requests that return 304 don't count against the rate
limit. An event is only a hint, and the connector re-reads the object before acting on it.
A webhook relay that the gate pulls from is a later-phase option. It is built only with the
owner's explicit public-exposure approval through the platform team's process. Event payloads
are untrusted input.

**GitHub first (Phase 2):**

- a minimal GitHub App with installation tokens;
- a required check `aegisx9/approval` whose expected source is that App, enforced by rulesets
  with an empty bypass list;
- environments with a custom deployment protection rule, and self-review prevented;
- Actions OIDC for workloads;
- CODEOWNERS read from the base branch and mapped to approver groups.

This repository is public, so custom deployment protection rules and environment reviewers are
available on any plan. Private repositories need a higher plan for some of these.

The gate records the declared change (commit range, plan hash) and compares it with what
actually lands.

**Jira second (Phase 3):** issues, releases and fixVersions, and service-desk approvals and
change management, used as workflow only. A ticket in "Approved" proves only that a field
changed; the signature is the authority. Links: Jira issue ↔ pull request ↔ request ↔
approval ↔ deployment.

**Connector framework (Phase 5):** a connector interface with up to six capabilities (change
events, gate, approval mirror, notify, identity and groups, audit in and out) and a
manifest of the permissions, credential mechanism and data fields it uses, plus a capability
matrix per vendor. The matrix records which events a connector can observe,
which enforcement points it controls, how it gets short-lived credentials (ADR 0013), how
bypass attempts are detected, and its rate limits and failure modes. A connector is certified
against an 11-point checklist before it is trusted, including: the credential's real
permissions equal the manifest; revocation after use is proven; events only trigger re-reads;
the gate holds while pending or denied; approving in the vendor's UI changes nothing (a
mirror is not authority); no secrets leave in errors or notifications; a vendor outage
keeps the gate closed; tenants are isolated; and an upgrade that widens permissions is a
T4 change.

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
