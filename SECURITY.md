# Security Policy

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting
("Report a vulnerability" under the repository's Security tab). Expect an
acknowledgement within 5 working days. Coordinated disclosure: we aim to fix critical
issues within 30 days and will credit reporters who want it.

## Supported versions

Only the latest released minor version receives security fixes while the project is
`0.x`.

## CI runner policy: pull requests never run on self-hosted runners

aegisx9 has two kinds of CI runner:

| Runner | Used for | Runs untrusted PR code? |
|--------|----------|-------------------------|
| GitHub-hosted (`ubuntu-latest`) | All PR and push checks, image build, SBOM, signing, GHCR push | Yes, isolated and ephemeral |
| Self-hosted, ephemeral, Actions Runner Controller on the homelab k3s cluster (label `aegisx9-arc`) | In-cluster jobs only: the staging red-team gate, deploy smoke tests, and Terraform Enterprise runs (`infra-apply`) | **Never** |

The self-hosted runners can reach the staging environment, so they must never execute
code an outsider controls. This is enforced in the workflows, not just by convention:

1. Jobs that use `runs-on: aegisx9-arc` (`redteam-staging`, `deploy-smoke`,
   `infra-apply`) are only in workflows triggered by `push` to `main`, `workflow_run` of the release workflow on `main`, or `workflow_dispatch`.
   **No such workflow has a `pull_request` or `pull_request_target` trigger.**
2. Each such job has an `if:` guard that requires `github.repository ==
   'mchasse73/aegisx9'`, `github.ref == 'refs/heads/main'` and an event that is not a pull
   request, so a copied workflow in a fork, or a future trigger change, still cannot
   schedule it.
3. Each such job targets a **protected environment** (`staging` or `production`) with
   required reviewers and a deployment-branch rule limited to `main`. A job cannot start
   on a runner until a reviewer approves it.
4. The ARC runner scale set is registered to this repository only, its pods are
   ephemeral (one job per pod), run as non-root, and their network policy allows only
   the staging gateway and GitHub.
5. Repository settings require approval for workflow runs from all outside
   collaborators, and forks cannot receive secrets.

Any change to these workflows needs CODEOWNERS review. A PR that adds a
`pull_request` trigger to a workflow with a self-hosted job must be rejected.

## Supply chain

- Every third-party action is pinned to a full commit SHA; Dependabot proposes updates.
- Images are built on GitHub-hosted runners, scanned with Trivy, described by a Syft
  SBOM, and signed keylessly with cosign (Sigstore, GitHub OIDC). The cluster's Kyverno
  policy admits only images signed by this repository's release workflow on `main`.
- Secret scanning (gitleaks), SAST (Semgrep), dependency audit (pip-audit) and IaC
  scanning (Checkov, kube-linter) run on every PR.

## Infrastructure and secrets

- All infrastructure is Terraform (`infra/`) applied through Terraform Enterprise; every
  run is checked by the Sentinel policy set in `policies/sentinel/` (no public exposure
  without approval, digest-pinned allowlisted images, resource limits, no plaintext
  secret variables, DNS changes confined to the project's zone).
- Model-provider keys live in Vault and are read by the gateway at runtime; they are
  never in configuration, images or Terraform variables.
- Audit records are signed with a non-exportable Vault transit key.
- Day-2 automation (`automation/`) receives credentials only as environment variables
  injected by the automation controller, and every task that touches one is `no_log`.

## Data handling

aegisx9 never logs prompt or completion text, or secret values. Audit events carry a
SHA-256 digest, a length and per-category finding counts only, and the serializer
refuses to emit a record that matches a secret pattern.
