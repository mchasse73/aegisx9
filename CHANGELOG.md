# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CI image boot smoke asserts that `/v1/models` without valid credentials returns 401:
  no header and an empty bearer with and without a database, and a random bearer with the
  database (the production setup), so an exception in the auth path can't ship as a 500
  again (closes #68).

### Fixed
- CI: pip-audit and the gateway image Trivy scans read one documented ignore list
  (`.trivyignore`). It holds three filelock advisories that don't apply to the gateway
  and can't be fixed while LiteLLM requires filelock<4.0; removed once it allows 4.2.1.
  The workspace image ignores the undici advisory in Node.js 24.22.1's bundled copy until
  the next Node 24 LTS release (closes #88).

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

