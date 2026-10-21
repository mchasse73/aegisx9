# 3. Argo CD GitOps delivery

- Status: Accepted
- Date: 2026-10-21

## Context

Deployments must be reproducible, reviewable and reversible, and CI must not hold
credentials that can write to the cluster.

## Decision

- Argo CD in the homelab k3s cluster **pulls** from GitHub. CI never pushes to the cluster.
- `deploy/helm/aegisx9` is the single Helm chart. `deploy/overlays/{staging,prod}` are
  Kustomize overlays that render the chart (`--enable-helm`) and pin the image by
  **digest** in `images[].digest`.
- Staging syncs automatically with prune and self-heal. Production syncs automatically
  but only changes when its overlay changes.
- **Promotion to production is a pull request** that changes the prod overlay's digest
  (opened by the `promote-prod` workflow after verifying the signature). CODEOWNERS and
  branch protection require the owner's approval.
- Kyverno `verifyImages` in both namespaces admits only images signed by the main release
  workflow (ADR 0002), so a bypass of Git still cannot run an unsigned image.

## Consequences

- Rollback is a revert PR.
- Argo CD needs `kustomize.buildOptions: --enable-helm`.
- PRs opened with the default `GITHUB_TOKEN` do not trigger CI; the promotion workflow
  should move to a GitHub App token so required checks run on promotion PRs.
