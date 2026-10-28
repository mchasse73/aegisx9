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
| Bootstrap | `cloud-init.sh.tftpl` installs nmap, the AWS CLI v2 from the official zip (PGP signature verified against the embedded AWS CLI team key; a bad, expired or revoked signature or key fails closed; Ubuntu 24.04 has no `awscli` package and the snap cannot run in the hardened secrets fetcher), a pinned checksum-verified nuclei, CPU-only torch (`torch_version` from `torch_index_url`, pinned as `+cpu` in a constraints file so no later install can bring the CUDA build back), the scanner package at `scanner_package_ref` and garak (`garak_version`) with no pip cache, and the systemd units and red-team suites from the same ref. The timers are enabled even when the secrets fetcher fails (the scan units `Requires=` it); the bootstrap log then names the missing parameters. Architecture comes from `uname -m`. Scan configuration is then managed by the `x9.aegisx9.scanner` role over SSM. |
| Required inputs | `scanner_package_ref` has **no default**: a `vX.Y.Z` release tag or a 40-character commit SHA that contains the bootstrap fixes of issue #96 (earlier tags cannot boot on Ubuntu 24.04). `volume_size` defaults to, and must be at least, 30 GiB. |
| Key rotation | The embedded AWS CLI signing key expires 2027-07-01. Refresh it from the AWS CLI user guide ("Verify the integrity and authenticity of the downloaded installer") before then, or the bootstrap stops at the signature check. |
| Vault | `vault_aws_auth_enabled` is a placeholder for the Vault AWS IAM auth method (instance-role login, no secret on the box). Platform operations decides the paths. |

```bash
terraform fmt -check -recursive
terraform init -backend=false && terraform validate
```

Copy `terraform.tfvars.example` for local plans; the real ids are workspace variables.
