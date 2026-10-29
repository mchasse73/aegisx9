# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `aegisx9-login`, a developer CLI that gets a short-lived gateway token (#122): OIDC
  authorization code with PKCE (S256) against a public client and a loopback redirect, an
  https-only discovery whose issuer must match exactly, single-use `state`, and the access
  token written to a 0600 file by atomic replace. It never prints the token, only its
  remaining lifetime, and reports errors by exception type only.

### Changed
- Staging runs v0.4.0 with the auth sidecar enabled (#86): callers present identity-provider
  access tokens of at most 15 minutes, which the sidecar exchanges for virtual keys that
  expire with them. The issuer, JWKS URL, audience and group-to-team mapping are read from
  the gateway Secret, so the public overlay holds no identity-provider details.

### Fixed
- Scanner root volume tags are now part of the launch request (`volume_tags`) instead of a
  CreateTags after launch, which the deploy role is not granted (#124); in-place volume tag
  changes are ignored and take effect on the next instance replacement.

## [0.4.0] - 2026-10-29

### Added
- Auth sidecar: an issuer's `audience` and its group-to-team mapping can now come from the
  gateway Secret (`audienceEnv`, and `groupTeamsEnv` holding ordered `group=team` pairs
  separated by `;`), like `issuerEnv` and `jwksUrlEnv`. This means no identity-provider
  details need to be committed to the public repository (refs #86).
- Product scope and build plan (#107): AegisX9 is the security gateway for AI-driven
  development: an LLM gateway, a build and action gate, and approval governance, with one
  view of what AI is building and changing. ADRs 0011 (scope, accepted), 0012 (approval
  governance: typed policy-as-code, signed statements with nonce, expiry and per-signer
  records, N-of-M and separation of duties, break-glass), 0013 (short-lived, single-use
  secrets and per-action credentials) and 0014 (integrations without inbound exposure,
  GitHub first, then Jira, then a connector framework with a trust bar). The roadmap is
  rebuilt into Phases 2 to 6 (epics #109 to #115). ADRs 0012-0014 fold in the detailed
  design and the owner's decisions of 2026-10-29. AegisX9 builds its own gate, and the
  homelab's build-request system is customer zero. Customer zero is a declared
  single-approver tenant, with a cooling-off delay and the second hardware key for T3/T4.
  Events are polled only, with no inbound exposure.

### Changed
- README: describes the new scope and roadmap; the status shows version 0.3.1 (it said 0.1.0).

### Security
- CI: ten new filelock 3.x advisories (#117) are assessed and listed in `.trivyignore` with
  their rationale. All need a second local user, or are Windows-only, and the gateway pod is
  a single non-root user on a read-only root filesystem. LiteLLM still caps `filelock<4`, so
  the fixed 4.x releases don't resolve. pip-audit --strict was failing every PR.

## [0.3.1] - 2026-10-28

### Fixed
- Scanner: the webhook URL parameter is now optional (#102). v0.3.0's boot-time fetcher
  required it, so the scan units could not start before an Event-Driven Ansible receiver
  existed; the redeploy for #96 stopped on the missing parameter. With no URL the webhook is
  off and alerts go by email only (the notifier already treated an empty URL that way); the
  webhook HMAC secret is required only when a URL is set. A non-https placeholder was not a
  safe workaround: it logs an error on every alert.

## [0.3.0] - 2026-10-28

### Added
- Short-lived JWT authentication (ADR 0010): `aegisx9.auth_proxy`, an auth sidecar in
  the gateway pod in front of LiteLLM (which then listens on loopback only). It validates
  tokens from configured issuers (JWKS signature with asymmetric algorithms only, `iss`,
  `aud`), requires `exp` and `iat`, refuses any token that lives longer than 15 minutes (a
  ceiling in code that configuration can only lower), maps groups to LiteLLM teams and
  exchanges the token for a virtual key scoped to that user and team that expires with the
  token, so model access, team and per-member budgets apply through LiteLLM's own checks.
  JWT callers are limited to inference routes; management routes answer 403.
  Every rejected token gets a generic 401; logs carry only a reason code. Other bearers
  (admin key, virtual keys) pass through unchanged. Chart: `gateway.oidc.issuers[]`
  replaces `jwksUrl`/`audience`/`userIdClaim`/`teamIdClaim`, and `gateway.oidc.enabled`
  defaults to false until an environment pins an image with the sidecar. CI image smoke
  boots LiteLLM and the sidecar with Postgres and runs `scripts/ci/auth_smoke.py` (refs #86).
- CI image boot smoke asserts that `/v1/models` without valid credentials returns 401:
  no header and an empty bearer with and without a database, and a random bearer with the
  database (the production setup), so an exception in the auth path can't ship as a 500
  again (closes #68).

### Fixed
- Workspace image: npm, npx and corepack are removed after Claude Code is installed, so
  the workspace has no package manager and none of npm's bundled dependencies. That
  clears two new undici advisories (certificate-validation bypass, TLS renegotiation DoS)
  that no Node 24 release fixes yet, and four older npm ignore entries. Claude Code's
  self-update is off (`DISABLE_AUTOUPDATER`), because the signed image pins its version.
  The Vault CLI moves to 2.2.1, which still bundles go-jose 4.1.5: its JWK-parsing DoS
  advisory has a documented ignore entry until the next Vault release. Developers no
  longer have `npm` in the workspace (owner decision, closes #99).
- The gateway image no longer contains `litellm-enterprise`, a proprietary package that
  `litellm[proxy]` pulls in (production use needs a BerriAI subscription; redistribution is
  not allowed). LiteLLM runs without it; the image job fails if it ever comes back
  (closes #91).
- The chart no longer enables LiteLLM's `enable_jwt_auth`, an Enterprise-only feature that
  answered every JWT with 403 and a message disclosing the edition and licence state
  (refs #86).
- CI: pip-audit and the gateway image Trivy scans read one documented ignore list
  (`.trivyignore`). It holds three filelock advisories that don't apply to the gateway
  and can't be fixed while LiteLLM requires filelock<4.0; removed once it allows 4.2.1.
  The workspace image ignores the undici advisory in Node.js 24.22.1's bundled copy until
  the next Node 24 LTS release (closes #88).
- External vantage scanner deploy defects found on an Ubuntu 24.04 rebuild: the bootstrap
  installs the AWS CLI v2 from the official zip with its PGP signature verified (the
  `awscli` package doesn't exist on noble and the snap can't run in the secrets fetcher's
  sandbox); the package installs with the PEP 508 `aegisx9[scanner] @ git+...` form, from a
  now-required `scanner_package_ref` (release tag or commit SHA), with CPU-only torch and no
  pip cache, on a 30 GiB root volume; the secrets fetcher fails, with an error naming the
  parameter and without leaving an empty file, when a required parameter can't be read; the
  daily unit drops `ProcSubset=pid` (nmap needs `/proc/net`) and sets
  `StateDirectoryMode`/`LogsDirectoryMode=0770` so the uptime and red-team units can write
  the shared state directory; the fetcher retries transient read errors and keeps the
  last good value, restarts itself on failure, and a failure no longer stops the timers
  from being enabled at bootstrap; the AWS CLI check also rejects expired or revoked keys;
  the role installs the package once per ref change (dependencies included) against a
  `+cpu` torch constraint, replaces a CUDA torch it finds, and re-runs the fetcher when it
  changes; uptime and red-team notify on a change of state (24-hour
  reminder, one recovery notice) instead of every run, registry entries that the
  never-target list covers are reported as intentionally not scanned (a never-target in
  targets.yml still alerts and fails `validate-config`), and the daily scan still sends
  its daily summary. Unit-file lint tests
  and a CI job that runs nmap under the daily unit's sandbox guard the units (refs #96).

## [0.2.0] - 2026-10-22

### Added
- Anthropic through Workload Identity Federation, with no static provider key (ADR 0009):
  `aegisx9.wif_broker` sidecar that logs in to Vault with the pod's service-account token,
  reads a fresh Vault-signed identity token for every exchange, keeps a short-lived
  Anthropic access token and serves a loopback-only proxy for LiteLLM (credential
  replacement, path allowlist, unbuffered SSE, `/healthz`); chart values `wif.*`. Staging
  activation (models `claude-haiku-5-5`, `claude-sonnet-5-5`, `claude-opus-5-5` via the
  broker) follows with the promotion of a signed image that contains it (refs #53).
- Spend caps: proxy-wide budget $180 per 30 days in staging and per-consumer LiteLLM teams
  (`public-chat` $20, `staging-tests` $30, `developers` $25 per member) kept in sync by a
  PostSync Job; spend-check CronJob (whenever a proxy budget is set, with or without teams)
  and Loki alerts at 50/80/100 %; broker no-token alert; hourly check of Vault's OIDC
  signing keys against the federation issuer. The jobs are behind
  `gateway.budgets.jobs.enabled` until that image is promoted (refs #53).
- Public-repository preparation: an `identifier check` CI job that fails on internal
  identifiers (generic patterns in the repo, organisation-specific ones only from a CI secret), and a log redaction filter used by
  the self-hosted workflows so Terraform plan bodies and internal URLs stay out of public
  Actions logs (refs #1).
- Developer tier: Coder workspace template as Terraform (`infra/workspaces/coder-template`):
  one restricted pod per developer running the signed workspace image by digest, persistent
  home, CPU/memory/team parameters, gateway and OTel environment, no provider key; the
  `signed-digest-images` Sentinel policy now also checks bare pods (refs #47).
- Break-glass local workspace (`workspace/breakglass`): hardened devcontainer on the same
  image, `breakglass-login` (OIDC Vault window with an HMAC-signed activation event),
  `handoff-sync` (gitleaks-gated, append-only union sync back to the central workspace with
  manifest verification, shred and token revoke), EDA rules and the `breakglass` role with
  ledger and window-expiry job templates (refs #52).
- External vantage scanner (`scanner/`, console script `aegisx9-scan`): daily port, TLS,
  exposure-file, nuclei and DNS checks from a cloud host outside every allow-list,
  diffed against the approved-exposure registry and the previous snapshot; five-minute
  uptime checks; weekly external red-team run; dated clean reports; HMAC-signed webhook
  to Event-Driven Ansible and SES email; a never-target deny list enforced before any
  scan. With hardened systemd units, Terraform for the host (`infra/scanner/`), an
  Ansible deploy role and an EDA rule that opens an incident on `exposure_change`
  (refs #42).
- Developer workspace image (`workspace/`): signed, digest-pinned devcontainer with the
  locked Claude Code baseline as root-owned managed settings (gateway-only routing,
  `apiKeyHelper`, model allowlist, bypass disabled, secret-path denies, Bash sandbox with
  a network allowlist, exclusive managed MCP list, fail-closed hooks, telemetry without
  prompt text); CI builds and self-tests it, the release pipeline publishes it to
  `ghcr.io/mchasse73/aegisx9/workspace` with SBOM, Trivy scan and keyless signature
  (refs #48).
- `gateway-token` apiKeyHelper: Vault OIDC login for role `aegisx9-developer` and a
  short-lived gateway JWT from Vault's identity OIDC provider, cached in 0600 files, no
  static key anywhere (refs #49).
- Session memory and daily handoff: `handoff` CLI, `/handoff` skill, a `SessionEnd`
  hook that writes a stub note, team-memory publish, and documented home/team-memory
  mounts; every note is scanned with the same secret patterns as prompts (refs #51).
- `.gitignore` refuses credential-shaped files in the working tree (refs #33).
- Project onboarded into the maintainer environment: repo remote, tracking issue, docs
  collection and memory (refs #33).
- Initial scaffold: guard pipeline interface with prompt-injection, secret and PII
  guards; audit-event schema with no content fields and a secret self-check; model
  allowlist, budget and rate-limit policy; LiteLLM proxy hook adapter.
- CI (ruff, mypy, pytest with an 85% coverage gate, gitleaks, Semgrep, pip-audit,
  Checkov, kube-linter, Docker build, Trivy), release pipeline (Syft SBOM, keyless cosign
  signing, GHCR push) and a staging red-team workflow restricted to ARC runners on `main`.
- Helm chart, Kustomize overlays for staging and prod, Argo CD applications and a Kyverno
  image-verification policy.
- promptfoo and garak red-team suites, ADRs 0001-0007, contribution and security policies.
- `AuditSigner` interface with a Vault transit implementation and a local test double;
  signed audit envelopes.
- Terraform roots for staging and prod (Terraform Enterprise, organization `x9`) covering
  Kubernetes namespaces/quotas, Vault KV/transit/PKI, the identity-provider app, GitHub
  environments and branch protection, the ARC runner scale set and Route 53.
- Sentinel policy set (6 policies) with mock-based tests.
- Ansible collection `x9.aegisx9`, AAP playbooks and an Event-Driven Ansible rulebook.
- CI jobs for Terraform (fmt, validate, tflint, Checkov), Sentinel tests and ansible-lint;
  `infra-apply` workflow for TFE runs on ARC runners.

### Changed
- infra-apply runs only when the repository variable `INFRA_APPLY_ENABLED` is `true`, until the
  Terraform Enterprise workspaces and token exist (refs #17).
- Staging runs on Workload Identity Federation: new signed image with the broker, models
  `claude-sonnet-5-5`, `claude-haiku-5-5`, `claude-opus-5-5`, budget jobs and the signing-key
  check enabled (refs #53).
- Release signs and attests in cosign's legacy layout so the cluster's keyless image
  verifier finds the signature; overlays no longer render a NetworkPolicy (platform-owned);
  the Argo CD AppProject file mirrors the live, namespace-whitelisted project (refs #8).
- Branch protection no longer requires an approving review (single maintainer); required
  checks, linear history, conversation resolution and admin enforcement remain (refs #1).
- Staging overlay pinned to the first release digest signed in the legacy cosign layout; overlays no longer carry the
  Namespace object, which the platform team owns (refs #8).

### Fixed
- Day-2 jobs retry connection failures for up to 60 seconds (a new pod can be refused for its
  first seconds while network policy catches up) and can set a priority class (refs #53).
- Dependency bumps: hatchling 1.32.4, pytest 9.1.1, pytest-cov 7.1.0, ruff 0.17.1, mypy 2.4.0,
  checkov-action 12.3134.0 (supersedes Dependabot PRs #34 to #39).
- The gateway image starts with a database: the Prisma client (`prisma==0.11.0`, the version
  LiteLLM 1.106.2 ships), its CLI, query and schema engines and a digest-pinned Node.js are
  baked in at build time, the client is generated from LiteLLM's schema, and LiteLLM's
  migrations run from `/tmp` (`LITELLM_MIGRATION_DIR`), so nothing is downloaded at runtime and
  the read-only root filesystem holds. CI now also boots the image read-only against Postgres 17
  and checks that the migrations were applied, and that the Prisma CLI runs with no network.
- The signing-key check no longer alerts every day: it compared a digest of every key Vault
  publishes, including a built-in key that rotates daily. The broker now checks the `kid` of
  each identity token against `wif.uploadedKids` (`wif_kid_not_uploaded`), and the hourly job
  checks that every uploaded kid is still published (`missing_uploaded_kids`). The
  `wif.jwksCheck.expectedSha256` value and its alerts are removed; ADR 0009 describes key
  rotation.
- The guard callback subclasses LiteLLM's CustomLogger so the proxy loads it; CI boots the proxy
  with the real config as a smoke test; ExternalSecret defaults are explicit to avoid Argo CD
  drift (refs #8).
- First CI run: Checkov runs one framework per step, the rollout-wait script selects the
  namespace literal by comparison (no tainted argv for SAST), and GitHub provenance
  attestation is skipped while the repository is private; the gitleaks job can read PR
  commits (refs #2).

