# 10. Short-lived JWT authentication in an auth sidecar

- Status: Accepted
- Date: 2026-10-27

## Context

The gateway is meant to sit behind the organisation's single sign-on: people and workloads
present an OIDC token (JWT), and the gateway maps it to a user and a LiteLLM team for budgets
and model access. The chart turned on LiteLLM's `enable_jwt_auth` for this.

Verifying staging for #68 showed that this never worked. In the open-source LiteLLM build,
JWT auth is an Enterprise feature: every JWT-shaped bearer gets HTTP 403 with a message
naming the product, edition and licence state (#86). No SSO caller could authenticate, and
the error disclosed implementation details to unauthenticated callers.

The owner's decision of 2026-10-27 also sets the bar for any replacement: **every credential
the gateway accepts is short-lived**, because this whole project is security first.

Options considered:

1. Buy a LiteLLM Enterprise licence. A recurring cost, the licence becomes another managed
   secret, and the token-lifetime policy would still be LiteLLM's rather than ours.
2. Validate JWTs in LiteLLM's open-source `custom_auth` hook. A prototype worked, but in the
   open-source build a configured `custom_auth` replaces **all** of LiteLLM's key
   authentication: handing a non-JWT bearer back to LiteLLM's own checks is only possible
   through the proprietary `litellm-enterprise` package (removed from the image, #91). The
   hook would have had to reimplement the admin-key and virtual-key paths, roughly 4,000
   lines of security-critical LiteLLM code, and track them across upgrades.
3. An SSO proxy that passes identity in a trusted header. Non-browser clients (CLIs,
   services) fit badly, and LiteLLM has no open-source header-trust mode with budgets.
4. **An auth sidecar in the gateway pod that exchanges a verified JWT for a short-lived
   LiteLLM virtual key.**

## Decision

Option 4: `aegisx9.auth_proxy`, a container in the gateway pod built from the same image.

- **Topology.** The sidecar owns the service port. LiteLLM listens on `127.0.0.1` only, so
  every request from outside the pod passes the sidecar. Probes for LiteLLM run inside its
  container.
- **Routing.** A bearer that isn't shaped like a JWT (in `Authorization`, `x-api-key` or
  `x-litellm-api-key`) is forwarded unchanged, so the admin key and virtual keys go through
  LiteLLM's own key checks (their lifetime controls are #90). Only JWTs are handled.
- **Trust** (`aegisx9.auth`). A token must name a configured issuer (exact `iss`), be signed
  by a key in that issuer's JWKS (fetched over HTTPS with redirects refused, cached
  5 minutes, refetched at most every 30 s when an unknown `kid` appears, last good keys kept
  for at most an hour during an outage) with an asymmetric allow-listed algorithm bound to
  the key (`RS*`, `PS*`, `ES256/384`; never `none` or HMAC), and carry the configured
  audience. Several issuers are supported, so the identity provider and Vault-issued
  workload or developer tokens (#49) can both be trusted; user ids are namespaced by issuer.
- **Short-lived only.** `exp` and `iat` are required, and `exp - iat` may not exceed
  **900 seconds**, a constant in code; an issuer's `maxLifetimeSeconds` can lower it and the
  chart refuses to render a higher value. `iat` may be at most 30 s in the future.
- **Exchange.** A valid token is exchanged for a LiteLLM virtual key scoped to the caller's
  user and team that **expires with the token** (`duration` = remaining lifetime, never more
  than 900 s, and dropped from the cache two seconds before LiteLLM expires it), minted
  through LiteLLM's admin API with the master key. The caller is enrolled into its team
  first, so team model access, team budgets and per-member budgets all apply through
  LiteLLM's unmodified checks. Minted keys live only in the sidecar's memory, keyed by the
  token's SHA-256, and are dropped when they expire.
- **Inference routes only.** A JWT caller may use the chat, completion, embedding, messages
  and model-list routes; any other path (`/key/*`, `/user/*`, `/team/*`, ...) is a 403
  before anything is minted, so a short-lived token can never become a longer-lived
  credential. A token with only a few seconds left is refused rather than exchanged.
- **Fail closed.** Every rejected token gets the same 401 `Authentication failed`; if the
  key exchange itself fails the request gets 503. The access log carries method, path,
  status, duration and a short reason code, never a token, its claims or an exception
  message.
- **Configuration.** The chart renders `auth.json` from `gateway.oidc.issuers`; issuer and
  JWKS URLs are read from the gateway Secret by variable name, so identity-provider details
  stay out of the public repository. The sidecar receives only the master key from that
  Secret. A set but invalid configuration stops the sidecar at startup.

## Consequences

- SSO and workload identities work on the open-source build, under a lifetime policy this
  project owns and tests, without reimplementing LiteLLM's key authentication.
- Token issuers must be configured for 15-minute tokens or less (the identity provider's
  access-token lifetime; Vault's identity-token TTL, #49), or their tokens are refused.
- The sidecar holds the master key. It uses only the public admin API (`/team/member_add`,
  `/key/generate`), which is stable across LiteLLM releases; a CI boot smoke with Postgres
  runs the whole exchange on every image build.
- Minted keys accumulate in LiteLLM's database until they are cleaned up; expired-key
  cleanup is part of #90.
- One extra hop inside the pod. Request bodies are streamed and responses relayed without
  buffering; idle clients time out after 60 s and concurrent connections are capped, so
  unauthenticated traffic can't exhaust the sidecar. Only the ingress's `X-Forwarded-For`
  is kept (`gateway.oidc.trustedProxies`); any other peer's is replaced.
- Enabling it in an environment is a separate change that pins an image containing the
  sidecar and adds the issuer variables to the environment's Secret.
