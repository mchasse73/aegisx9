# infra/scanner

Terraform for the AegisX9 **external vantage** host: one `t3.small` on the public
internet that runs the daily exposure scan, the 5-minute uptime probe and the weekly
external red-team run (see `scanner/README.md`). Applied by platform operations through
the Terraform Enterprise workspace `aegisx9-scanner`, checked by the Sentinel policy set.

| Concern | How |
|---------|-----|
| Access | SSM Session Manager only. The security group has **no ingress rules**; egress is open because the scanner must reach the public surface it audits. |
| Image | Ubuntu 24.04 LTS from Canonical's public SSM parameter; IMDSv2 required; encrypted gp3 root volume. |
| Address | `aws_eip_association` to an **existing** Elastic IP (`eip_allocation_id`): the address is on allowlists and is never created or released here. |
| IAM | Session Manager agent actions only (the managed `AmazonSSMManagedInstanceCore` policy is not attached: it would grant parameter reads account-wide); `ses:SendEmail` on one identity; `ssm:GetParameter*` on `/aegisx9/scanner/*` only; `kms:Decrypt` via SSM. |
| Secrets | SecureString parameters (webhook HMAC, tunnel, red-team key) are created out of band. Only their **names** are variables. `aegisx9-scanner-env.service` fetches them at every boot into 0600 root files; the scan units read them through systemd `LoadCredential=`. Nothing secret is in user-data. |
| Bootstrap | `cloud-init.sh.tftpl` installs nmap, a pinned checksum-verified nuclei, the scanner package at a pinned git tag, and the systemd units from the same tag. Scan configuration is then managed by the `x9.aegisx9.scanner` role over SSM. |
| Vault | `vault_aws_auth_enabled` is a placeholder for the Vault AWS IAM auth method (instance-role login, no secret on the box). Platform operations decides the paths. |

```bash
terraform fmt -check -recursive
terraform init -backend=false && terraform validate
```

Copy `terraform.tfvars.example` for local plans; the real ids are workspace variables.
