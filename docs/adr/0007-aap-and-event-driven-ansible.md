# 7. Ansible Automation Platform for day-2 operations and response

- Status: Accepted
- Date: 2026-10-21

## Context

Operating the gateway needs repeatable procedures (key rotation, upgrades, evidence
collection) and fast, consistent responses to security events, with an audit trail of
who ran what.

## Decision

- Day-2 procedures are Ansible playbooks in `automation/playbooks/`, built on roles in the
  `x9.aegisx9` collection (`automation/collections/`), run as Ansible Automation Platform
  job templates. Collections are pinned in `collections/requirements.yml`.
- Credentials are AAP credential types injected as environment variables; tasks that use
  them are `no_log: true`; nothing secret goes on a command line.
- Upgrades go through GitOps: the playbook triggers the promotion workflow, which opens a
  reviewed PR; the playbook then verifies the rollout. It never patches images directly.
- **Event-Driven Ansible** rulebooks (`extensions/eda/rulebooks/`) consume Alertmanager
  alerts from Loki rules. Repeated prompt-injection blocks from one principal run the
  "Revoke agent key" job template (block the key, open an incident). Audit-signing
  failures trigger evidence collection.
- `ansible-lint` (production profile) runs in CI.

## Consequences

- Automated revocation can lock out a legitimate client after false positives; the
  threshold (5 blocks in 5 minutes) and the 15-minute throttle are tuned with red-team data.
- AAP must be able to reach the cluster API, Vault and the gateway admin API.
