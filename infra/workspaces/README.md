# infra/workspaces: the developer tier

Developers work in centralized, per-developer workspaces provisioned by
[Coder](https://coder.com) on the same Kubernetes cluster as the gateway, in the namespace
`aegisx9-dev`. A workspace is one pod running the signed devcontainer image
`ghcr.io/mchasse73/aegisx9/workspace` by digest with a persistent home volume. All model
traffic from a workspace goes through the AegisX9 gateway, so the same guards, budgets and
audit trail apply to a developer's agent as to a production caller.

| Component | Where | Status |
|-----------|-------|--------|
| Coder template (pod, PVC, agent, parameters) | `coder-template/` | this repository, pushed with the `coder` CLI |
| Namespace `aegisx9-dev`: PodSecurity `restricted`, ResourceQuota, LimitRange, default-deny NetworkPolicy plus egress to the gateway, the OTel collector, the Coder control plane and the package mirrors; registry pull secret | platform team (build request) | requested; the template assumes it exists |
| Workspace image (devcontainer, signed, digest-pinned) | `workspace/` image build (separate change) | in progress; referenced here only by the `workspace_image_digest` variable |
| Break-glass local workspace (same image on a managed laptop during a central outage) | `workspace/breakglass/` | this repository |

Why Terraform for the template: a Coder template *is* Terraform, so it gets the same
review, `fmt`/`validate`/`tflint`/Checkov checks and policy conventions (ownership labels,
digest-only images, request = limit) as the rest of `infra/`. It is the one Terraform root
in this repository that Terraform Enterprise does not apply: the Coder provisioner does,
with the Coder control plane's own Kubernetes service account.

Local checks:

```bash
terraform -chdir=coder-template fmt -check
terraform -chdir=coder-template init -backend=false && terraform -chdir=coder-template validate
tflint --chdir=coder-template
```
