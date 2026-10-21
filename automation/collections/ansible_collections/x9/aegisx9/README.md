# x9.aegisx9

Day-2 automation for the AegisX9 gateway, run from Ansible Automation Platform job
templates and Event-Driven Ansible.

| Role | Purpose |
|------|---------|
| `provider_key` | Store a new model-provider key in Vault, roll the gateway, verify, retire the old key |
| `gateway` | Upgrade the gateway by opening a promotion PR (GitOps), then verify the rollout |
| `audit_evidence` | Collect signed audit records, policy results and SBOM/signature evidence into a bundle |
| `incident` | Block a gateway key and open an incident record |

Credentials come from AAP credential types injected as environment variables; tasks that
touch them use `no_log: true`. Nothing secret is ever passed on a command line.
