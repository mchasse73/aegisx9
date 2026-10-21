# Contributing to aegisx9

Thanks for your interest. aegisx9 is run like an enterprise product, so contributions
follow a fixed workflow.

## Workflow

1. **Every change starts with an issue.** Search first; open one using the templates if
   nothing covers it. Security problems go through [SECURITY.md](SECURITY.md), never a
   public issue.
2. **Trunk-based development.** Branch from `main` with a short-lived branch
   (`feat/<issue>-short-name`, `fix/<issue>-...`). Keep branches small; merge within days.
3. **Conventional Commits.** `feat:`, `fix:`, `docs:`, `ci:`, `refactor:`, `test:`,
   `chore:`, `security:`; use `!` or a `BREAKING CHANGE:` footer for breaking changes.
   Reference the issue (`Refs #12`, `Closes #12`).
4. **Pull requests** use the template, link the issue, and must pass every required
   check: lint, type check, tests with the coverage gate, secret scan, SAST, dependency
   audit, IaC scan, container build and image scan. CODEOWNERS review is required.
5. **CHANGELOG.md** gets an entry under `## [Unreleased]` in the same PR.

## Versioning and releases

SemVer, starting at `0.1.0`. The `VERSION` file is the source of truth; a release is a
signed tag `vX.Y.Z` whose commit moves `[Unreleased]` to a dated section. The release
workflow builds, generates an SBOM, signs the image with keyless cosign, and pushes to
GHCR. Promotion to production is a PR that changes the prod overlay's image digest and
needs owner approval.

## Local checks

```bash
pip install -e '.[dev]'
ruff check . && ruff format --check . && mypy && pytest
helm lint deploy/helm/aegisx9
```

## Rules for test data and docs

- **No credential-shaped literals anywhere**, not even fake ones: secret scanners flag
  them. Build samples at runtime (see `tests/samples.py`).
- No real hostnames, IP addresses or internal paths in code, issues or public docs.
- Audit records must never contain prompt or completion text, or secret values.

## Code of conduct

Be professional and constructive. Keep discussion on the technical subject.
