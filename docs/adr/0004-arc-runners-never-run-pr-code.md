# 4. Self-hosted ARC runners never run pull-request code

- Status: Accepted
- Date: 2026-10-21

## Context

The red-team gate and deploy smoke tests must reach the staging and production
gateways, which are only reachable from inside the homelab k3s cluster. That requires
self-hosted runners. The repository will become public, and on a public repository any
pull request, including one from a fork, can propose workflow changes. A self-hosted
runner that executes PR code would let an outsider run arbitrary code inside the homelab.

## Decision

- In-cluster jobs run only on **ephemeral** self-hosted runners from Actions Runner
  Controller (one pod per job, label `aegisx9-arc`), registered to this repository only.
- Workflows containing `aegisx9-arc` jobs have **no `pull_request` or
  `pull_request_target` trigger**. They run on `push` to `main`, `workflow_run` of a
  successful push-triggered release on `main`, `schedule`, or `workflow_dispatch`.
- Every such job carries an `if:` guard requiring this repository, `refs/heads/main`, and
  a non-PR event (for `workflow_run`, a successful `push` run on `main` of this repository).
- Every such job targets a protected environment (`staging` or `production`) with
  required reviewers and deployment branches limited to `main`.
- All PR checks run on GitHub-hosted runners only.
- The ARC runner pods are non-root, have a NetworkPolicy allowing only GitHub and the
  AegisX9 gateways, and a service account limited to reading Deployments in the AegisX9
  namespaces.

## Consequences

- Red-team results arrive after merge, not on the PR. A regression fails the gate and
  blocks promotion to production rather than blocking the merge.
- Contributors cannot run in-cluster tests from a fork; maintainers can reproduce on
  `main` via `workflow_dispatch`.
- Any workflow change is CODEOWNERS-reviewed; adding a PR trigger to a workflow with a
  self-hosted job must be rejected (documented in `SECURITY.md`).
