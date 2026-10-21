output "namespace" {
  description = "Kubernetes namespace for this environment."
  value       = kubernetes_namespace_v1.this.metadata[0].name
}

output "vault_mounts" {
  description = "Vault mounts created for this environment."
  value = {
    kv      = vault_mount.kv.path
    transit = vault_mount.transit.path
    pki     = vault_mount.pki.path
  }
}

output "audit_signing_key" {
  description = "Transit key name used to sign audit records."
  value       = vault_transit_secret_backend_key.audit.name
}

output "oidc_client_id" {
  description = "OIDC client id (not secret). The client secret is stored in Vault only."
  value       = authentik_provider_oauth2.gateway.client_id
}
