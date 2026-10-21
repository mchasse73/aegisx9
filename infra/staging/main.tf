module "env" {
  source = "../modules/aegisx9-env"

  environment = "staging"
  quota = {
    requests_cpu    = "2"
    requests_memory = "4Gi"
    limits_cpu      = "4"
    limits_memory   = "8Gi"
    pods            = 20
  }

  vault_kubernetes_auth_path  = var.vault_kubernetes_auth_path
  pki_domain                  = var.pki_domain
  idp_authorization_flow_slug = var.idp_authorization_flow_slug
  idp_invalidation_flow_slug  = var.idp_invalidation_flow_slug
  idp_redirect_uris           = var.idp_redirect_uris

  # Staging owns the repository-wide settings and the single ARC runner scale set.
  manage_branch_protection = true
  deploy_arc_runners       = true
}

output "namespace" {
  description = "Staging namespace."
  value       = module.env.namespace
}

output "vault_mounts" {
  description = "Staging Vault mounts."
  value       = module.env.vault_mounts
}
