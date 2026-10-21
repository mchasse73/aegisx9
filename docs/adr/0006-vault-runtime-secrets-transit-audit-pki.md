# 6. Vault for runtime secrets, audit signing and mTLS

- Status: Accepted
- Date: 2026-10-21

## Context

The gateway holds the most sensitive credentials in the system (model-provider keys) and
produces the evidence an assessor relies on (audit records). Both need stronger handling
than Kubernetes Secrets and plain log lines.

## Decision

- **Provider keys** live in a per-environment Vault KV v2 mount and are read at runtime
  (Vault Agent sidecar or External Secrets) by the gateway's Kubernetes service account,
  through a Vault Kubernetes-auth role bound to that account and namespace. They are
  never in Helm values, images, Terraform variables or Git. Rotation writes a new KV
  version and rolls the gateway (AAP playbook).
- **Audit records** are signed with a per-environment **transit** key (`ed25519`,
  non-exportable, auto-rotated every 30 days; old versions still verify). The gateway
  policy can only `sign`; a separate verifier policy can only `verify`. The code depends
  on an `AuditSigner` interface with a transit implementation and a local HMAC test double.
- **mTLS** between the gateway and in-cluster callers uses short-lived certificates (24 h,
  max 72 h, `no_store`) from a per-environment PKI intermediate mount.
- Mounts, keys, roles and policies are Terraform (vault provider), applied by TFE.
- **Later (Phase 2):** per-agent short-lived credentials issued by Vault.

## Consequences

- Vault availability is on the request path for signing. The audit sink must buffer and
  alert (`AegisX9AuditSigningFailed`) rather than drop records when Vault is unavailable.
- Tampering with Loki contents is detectable by re-verifying signatures.
