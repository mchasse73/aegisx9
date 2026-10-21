# infra

Terraform for everything AegisX9 needs outside its own container image. Runs in
Terraform Enterprise (organization `x9`) workspaces `aegisx9-staging` and `aegisx9-prod`,
API/CLI-driven from the in-cluster ARC runners (TFE is not reachable from GitHub). Every
run is checked by the Sentinel policy set in `policies/sentinel/`.

| Root | Workspace | Manages |
|------|-----------|---------|
| `staging/` | `aegisx9-staging` | staging namespace, quota, limits, default-deny NetworkPolicy; Vault KV/transit/PKI + policies + Kubernetes auth role; identity-provider OIDC app; GitHub `staging` environment and branch protection on `main`; ARC runner scale set |
| `prod/` | `aegisx9-prod` | the same for production, plus Route 53 records in the aegisx9.com zone (only with an exposure approval) |

The TFE hostname is not in this repository: export `TF_CLOUD_HOSTNAME` (and
`TF_TOKEN_<host>`) in the runner environment. Provider credentials come from TFE
dynamic provider credentials (Vault, AWS) or workspace environment variables marked
sensitive (Kubernetes, identity provider, GitHub). No secret is a Terraform variable
default, and Sentinel rejects any secret-named variable that is not `sensitive`.

Local checks:

```bash
terraform fmt -check -recursive
for r in staging prod; do terraform -chdir=$r init -backend=false && terraform -chdir=$r validate; done
tflint --recursive
```
