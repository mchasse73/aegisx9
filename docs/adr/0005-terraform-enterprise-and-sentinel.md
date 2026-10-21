# 5. Terraform Enterprise and Sentinel for all infrastructure

- Status: Accepted
- Date: 2026-10-21

## Context

AegisX9 depends on infrastructure outside its container: namespaces and quotas, Vault
mounts and policies, an OIDC application in the identity provider, GitHub environments
and branch protection, the self-hosted runner scale set and public DNS. Changing any of
these by hand is untracked and unreviewed.

## Decision

- All of it is Terraform under `infra/`, one root per environment, sharing the
  `aegisx9-env` module.
- Runs happen in Terraform Enterprise (organization `x9`), workspaces `aegisx9-staging`
  and `aegisx9-prod`. TFE is internal, so runs are CLI-driven from the in-cluster ARC
  runners (`infra-apply` workflow, `main` only, protected environments), never via a VCS
  webhook. The TFE hostname comes from `TF_CLOUD_HOSTNAME` and is not in the repository.
- Provider credentials come from TFE dynamic provider credentials (Vault, AWS) or
  sensitive workspace variables; nothing secret is a Terraform variable default.
- A Sentinel policy set (`policies/sentinel/`) runs on every plan. Hard-mandatory:
  public-exposure approval, resource limits, signed/digest-pinned images, no plaintext
  secret variables, Route 53 confined to aegisx9.com. Soft-mandatory: required labels.
  Policies are tested with mocks in CI.

## Consequences

- PRs get fmt/validate/tflint/Checkov/Sentinel-test feedback on GitHub-hosted runners, but
  real plans only after merge. A speculative-plan path for PRs would need TFE reachable
  from GitHub and is out of scope.
- Relaxing a Sentinel policy or its enforcement level requires an ADR.
