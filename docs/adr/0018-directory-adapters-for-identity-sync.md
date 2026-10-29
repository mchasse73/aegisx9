# 18. Directory adapters for identity sync

- Status: Proposed (owner requirement 2026-10-29; awaiting the owner's confirmation)
- Date: 2026-10-29
- Extends: ADR 0015

## Context

ADR 0015 syncs project service identities and groups from the identity provider to hosts.
That sync reads a **directory** (users, groups and custom attributes such as a POSIX uid, a
Linux username and a service account's SSH key), not an SSO protocol. Organisations use
different directories, and two of the largest license directory users per seat.

## Decision

1. The identity sync reads the directory through pluggable adapters:
   - the Authentik API;
   - the Okta Users and Groups API (profile extension attributes);
   - Microsoft Graph for Entra ID (directory extension attributes);
   - generic SCIM 2.0, read by **pull** (ADR 0017: no SCIM push).
2. Human single sign-on (OIDC or SAML) is independent of the adapter, and works with any of
   them.
3. Adapters read only the groups a host is configured for. POSIX ids come from an allocated
   attribute, never from the directory's internal key (ADR 0015).
4. **Machine identities and per-seat licensing.** Okta and Entra ID license service *users*
   per seat. AegisX9 maps machine identities to service principals (or app registrations)
   plus groups, or to a small product-side registry, so only people sit in the paid directory.

## Scalability

Adapters are stateless readers with a cursor per directory, held under a lease (ADR 0016).
Large fleets read a centrally signed bundle instead of each host querying the directory.

## Consequences

- Each adapter is a connector, and has to clear the ADR 0014 trust bar (outbound only,
  short-lived credentials, least-privilege read scopes).
- A product-side registry for machine identities becomes a component that needs an HA store.
