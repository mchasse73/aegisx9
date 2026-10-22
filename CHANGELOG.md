# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- The guard callback subclasses LiteLLM's CustomLogger so the proxy loads it; CI boots the proxy
  with the real config as a smoke test; ExternalSecret defaults are explicit to avoid Argo CD
  drift (refs #8).

### Added
- Public-repository preparation: an `identifier check` CI job that fails on internal
  identifiers (generic patterns in the repo, organisation-specific ones only from a CI secret), and a log redaction filter used by
  the self-hosted workflows so Terraform plan bodies and internal URLs stay out of public
  Actions logs (refs #1).

### Changed
- Release signs and attests in cosign's legacy layout so the cluster's keyless image
  verifier finds the signature; overlays no longer render a NetworkPolicy (platform-owned);
  the Argo CD AppProject file mirrors the live, namespace-whitelisted project (refs #8).
- Branch protection no longer requires an approving review (single maintainer); required
  checks, linear history, conversation resolution and admin enforcement remain (refs #1).
- Staging overlay pinned to the first release digest signed in the legacy cosign layout; overlays no longer carry the
  Namespace object, which the platform team owns (refs #8).

### Fixed
- First CI run: Checkov runs one framework per step, the rollout-wait script selects the
  namespace literal by comparison (no tainted argv for SAST), and GitHub provenance
  attestation is skipped while the repository is private; the gitleaks job can read PR
  commits (refs #2).

### Added
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
