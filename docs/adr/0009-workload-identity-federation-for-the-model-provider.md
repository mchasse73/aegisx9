# 9. Workload Identity Federation for the model provider, with spend caps

- Status: Accepted
- Date: 2026-10-22

## Context

The gateway's first real model provider is Anthropic, paid from a fixed monthly credit
allowance of $200. Two constraints follow from the owner's decision of 2026-10-22:

1. **No static provider key anywhere.** A long-lived `sk-ant-` key in Vault, a Secret, an
   environment variable or a CI store is exactly the kind of credential this project exists
   to protect. Anthropic supports Workload Identity Federation (WIF): a workload presents a
   signed OIDC JWT to `POST /v1/oauth/token` (RFC 7523 `jwt-bearer` grant with
   `federation_rule_id`, `organization_id`, `service_account_id` and, when the rule spans
   several workspaces, `workspace_id`) and receives a short-lived access token used as
   `Authorization: Bearer`. The minted token lives for the lesser of the rule's
   `token_lifetime_seconds` (60-86400, default 3600) and twice the JWT's remaining lifetime.
   Assertions that carry a `jti` are single-use. `ANTHROPIC_API_KEY` shadows federation in
   every Anthropic SDK.
2. **Spend must stay inside the credits**, with room for error.

The cluster's own service-account issuer is internal and is not accepted as a federation
issuer, so the identity token has to come from an issuer the provider accepts.

## Decision

### Identity: Vault-signed OIDC tokens, exchanged by a sidecar broker

- Vault's identity secrets engine issues the OIDC identity tokens. Its issuer is a public
  name; the federation issuer holds Vault's signing keys inline. The federation rule's
  audience is the Vault OIDC role's client id and its subject is the Vault entity of the
  gateway's Kubernetes-auth role.
- A **token-broker sidecar** (`aegisx9.wif_broker`, same image, standard library only) runs
  in the gateway pod. It logs in to Vault with the pod's short-lived projected
  service-account token (Kubernetes auth, mount path configurable), keeps the Vault token
  in memory and renews it, and **reads a fresh identity token before every exchange**, so a
  `jti` is never presented twice. It refreshes the access token at 80 % of its lifetime,
  with capped, jittered backoff on failure.
- The broker serves a **loopback-only reverse proxy** on `127.0.0.1:8787`. LiteLLM's
  Anthropic models use it as `api_base` with a placeholder key (LiteLLM refuses an empty
  one). The broker strips any `x-api-key`/`Authorization` header, injects the current
  bearer token, forwards only `/v1/messages*` and `/v1/models*`, streams responses
  unbuffered (SSE), drops the `anthropic-organization-id` response header, and answers
  `503` while it holds no valid token. Its `/healthz` gates pod readiness.
- LiteLLM's own WIF support is disabled per model
  (`anthropic_disable_workload_identity_federation`). No token, Vault credential or
  identity assertion ever exists in the LiteLLM process, its environment or its config.
- The broker never logs tokens, assertions or bodies; errors are logged by exception type
  name only. It refuses to start when `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` is set.
- The federation identifiers, the Vault address and CA certificate, and the Vault role,
  identity-token path and auth mount come from the External Secrets-managed Secret, not
  from Git. The broker fails closed (exits with `BrokerConfigError`) when any is missing.

### Spend caps

- Proxy-wide LiteLLM budget **$180 per 30 days** (`litellm_settings.max_budget`; the chart
  previously set it under `general_settings`, where LiteLLM ignores it).
- Per-consumer LiteLLM teams, created and kept in sync by a PostSync Job through the admin
  API: `public-chat` $20 (Haiku 5.5 only), `staging-tests` $30 (Haiku and Sonnet 5.5),
  `developers` $25 per member within a $50 team cap (Sonnet 5.5 by default, Opus 5.5 only
  when asked for by name, Haiku 5.5). The remaining $80 is unallocated headroom. The
  provider-side workspace spend limit ($200) and disabled auto-reload are the last line.
- A CronJob logs spend per scope; Loki rules alert at 50, 80 and 100 % of each budget.

### Alternatives considered

- **LiteLLM's built-in WIF.** Less code, but the access token and the exchange would live in
  the same process that runs guard callbacks and handles untrusted prompts.
- **The cluster's projected service-account token as the assertion.** The provider does
  not accept the internal issuer; it would also make every exchange wait for kubelet
  rotation because of single-use `jti`.
- **A static key in Vault, rotated by AAP.** Rejected by the owner: a long-lived key is the
  risk to remove, not to manage.

## Consequences

- **Signing-key rotation breaks exchanges.** The federation issuer holds Vault's public keys
  inline; when Vault rotates its OIDC signing key, every exchange fails until the issuer is
  updated. An hourly job compares Vault's `identity/oidc/.well-known/keys` digest with the
  configured one and alerts on change (`AegisX9FederationKeysChanged`); the broker alerts
  when it has held no valid token for five minutes (`AegisX9WifNoValidToken`). Publishing
  a new key well before it signs anything, and keeping the old one until its tokens expire,
  avoids an outage.
- Vault is on the request path for token refresh (not for each model call). An access token
  stays valid for up to an hour, so a short Vault outage is absorbed.
- Budgets need the proxy database (`DATABASE_URL`); without it LiteLLM only warns.
- Rollout is two-step: this change ships the code and chart with `wif.enabled` and the
  budget/JWKS jobs off in staging; a follow-up promotes the signed image that contains the
  broker and `gateway_ops` and turns them on in the same change.
- Team budgets apply to callers whose identity-provider groups map to the team ids.
- The broker is new code on a sensitive path; it is covered by unit tests for the exchange
  request shape, refresh timing, header replacement, SSE pass-through, health states and
  the absence of secrets in logs.
