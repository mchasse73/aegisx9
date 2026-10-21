# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- First CI run: Checkov runs one framework per step, the rollout-wait script selects the
  namespace literal by comparison (no tainted argv for SAST), and GitHub provenance
  attestation is skipped while the repository is private; the gitleaks job can read PR
  commits (refs #2).

### Added
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
