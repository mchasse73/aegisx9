# x9.aegisx9

Day-2 automation for the AegisX9 gateway, run from Ansible Automation Platform job
templates and Event-Driven Ansible.

| Role | Purpose |
|------|---------|
| `provider_key` | Store a new model-provider key in Vault, roll the gateway, verify, retire the old key |
| `gateway` | Upgrade the gateway by opening a promotion PR (GitOps), then verify the rollout |
| `audit_evidence` | Collect signed audit records, policy results and SBOM/signature evidence into a bundle |
| `incident` | Block a gateway key and open an incident record |
| `breakglass` | Keep the ledger of break-glass local-workspace activations and syncs; expire a window by revoking its Vault token (by accessor) |
| `scanner` | Install or update the external vantage scanner (package, config, systemd timers) on its host over SSM Session Manager |
| `exposure_change` | Open an incident record for a scanner `exposure_change`, `down` or `redteam_regression` event |

The scanner host is reached with the `community.aws.aws_ssm` connection plugin
(`automation/inventory/scanner.yml`); it has no SSH. The approved-exposure registry the
scanner compares against is maintained in the platform operations repository and is
passed to the `scanner` role as a file path, never embedded here.

Credentials come from AAP credential types injected as environment variables; tasks that
touch them use `no_log: true`. Nothing secret is ever passed on a command line.
