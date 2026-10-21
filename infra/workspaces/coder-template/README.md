# AegisX9 developer workspace (Coder template)

One Kubernetes pod per developer in the `aegisx9-dev` namespace, running the signed
devcontainer image `ghcr.io/mchasse73/aegisx9/workspace` **by digest**, with a persistent
home volume. Every model call from a workspace leaves through the AegisX9 gateway
(`ANTHROPIC_BASE_URL`); no provider key is present anywhere in a workspace.

The template is plain Terraform (`coder/coder` + `hashicorp/kubernetes`). It is applied
by the Coder provisioner, not by Terraform Enterprise, so it has no backend and no cloud
block. Namespace, quota, LimitRange, NetworkPolicies and the registry pull secret are
built by the platform team; the template only creates what belongs to one workspace.

## What a workspace gets

| Control | Setting |
|---------|---------|
| Image | `${workspace_image}@${workspace_image_digest}` (digest validated; registry path must be `ghcr.io/mchasse73/aegisx9`); Kyverno verifies the cosign signature at admission |
| Identity | `runAsNonRoot`, uid/gid/fsGroup 1000 (`dev`), no service-account token, no service links |
| Hardening | `allowPrivilegeEscalation=false`, all capabilities dropped, seccomp `RuntimeDefault`, read-only root filesystem with writable `/tmp` (emptyDir, 4 Gi cap) and `/home/dev` (PVC) |
| Resources | request = limit, chosen from `cpu` ∈ {2, 4} cores and `memory` ∈ {4, 8} GiB |
| Labels | `app.kubernetes.io/part-of=aegisx9`, `aegisx9.io/tier=developer`, `owner`/`aegisx9.io/owner` = Coder workspace owner, `team`/`aegisx9.io/team` = the `team` parameter |
| Environment | `ANTHROPIC_BASE_URL` (gateway), `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_RESOURCE_ATTRIBUTES` (owner, team, tier). Never `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` |
| Access | `coder ssh` (VS Code Remote-SSH via `coder config-ssh`, JetBrains Gateway via the Coder plugin), an unprivileged in-workspace sshd on `ssh_port` (loopback only, keys in the home volume), optional code-server app (off by default; needs code-server in the image) |
| Idle stop | Coder's workspace TTL (set on the template, below). Stopping deletes the pod and keeps the home PVC |

## Parameters and variables

Two kinds of inputs:

- **Template variables** (`variables.tf`) are set by the platform team when the template
  version is pushed. Developers cannot change them. See `terraform.tfvars.example`.
- **Workspace parameters** (`coder_parameter` in `main.tf`) are the choices a developer
  makes when creating a workspace.

| Parameter | Options | Plan effect |
|-----------|---------|-------------|
| `cpu` | 2 (default), 4 | `resources.requests.cpu` and `resources.limits.cpu` on the `dev` container |
| `memory` | 4 (default), 8 | `resources.requests.memory` and `resources.limits.memory` (`<n>Gi`) |
| `team` | lowercase label, default `platform`, immutable | labels `team` and `aegisx9.io/team` on the pod and PVC, `aegisx9.team` in `OTEL_RESOURCE_ATTRIBUTES` |
| `code_server` | false (default), true | creates `coder_app.code_server` pointing at `localhost:13337` |

| Variable | Default | Plan effect |
|----------|---------|-------------|
| `workspace_image` | `ghcr.io/mchasse73/aegisx9/workspace` | image repository (must stay under `ghcr.io/mchasse73/aegisx9`) |
| `workspace_image_digest` | none (required) | `@sha256:...` suffix; a new template version per release |
| `namespace` | `aegisx9-dev` | namespace of the pod and PVC |
| `image_pull_secret` | `""` | `imagePullSecrets` entry while the image is private |
| `home_size` / `storage_class` | `50Gi` / cluster default | PVC size and class |
| `gateway_url` | none (required, https) | `ANTHROPIC_BASE_URL` |
| `otel_endpoint` | none (required) | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| `agent_arch` | `amd64` | Coder agent binary architecture |
| `ssh_port` | `2222` | in-workspace sshd port (unprivileged) |

## Pushing the template

Prerequisites: the `coder` CLI logged in as a template admin, and a completed platform
request for the `aegisx9-dev` namespace (with its pull secret while the image is private).

```bash
cd infra/workspaces/coder-template
terraform fmt -check && terraform init -backend=false && terraform validate

# Variables file: copy terraform.tfvars.example to a path that is not committed.
coder templates push aegisx9-workspace \
  --directory . \
  --variables-file ../../../../aegisx9-workspace.tfvars \
  --message "workspace image <short digest>" \
  --yes

# Idle stop and lifecycle (template settings, not Terraform):
coder templates edit aegisx9-workspace \
  --default-ttl 8h \
  --activity-bump 1h \
  --autostop-requirement-weekdays monday,tuesday,wednesday,thursday,friday \
  --failure-ttl 24h \
  --inactivity-ttl 720h
```

Each workspace-image release produces a new digest; push a new template version with
the new `workspace_image_digest` and let developers update on their next start. Never
point `workspace_image` at a tag: the variable validation and the Sentinel policy
`signed-digest-images` both reject it.

Create a workspace:

```bash
coder create --template aegisx9-workspace --parameter cpu=4 --parameter memory=8 \
  --parameter team=platform my-workspace
coder config-ssh    # then VS Code Remote-SSH to host "coder.my-workspace"
```

## Policy checks

CI runs `terraform fmt`, `terraform validate`, `tflint` and Checkov over this directory.
The Sentinel policy set in `policies/sentinel/` is enforced by Terraform Enterprise, which
does not run this template; the policies are still written to cover it (`required-labels`
applies to every `kubernetes_*` resource, `signed-digest-images` checks `kubernetes_pod_v1`
containers), so a plan of this directory can be checked locally with
`sentinel apply -config=../../../policies/sentinel/sentinel.hcl` against a plan mock when
the policies change.
