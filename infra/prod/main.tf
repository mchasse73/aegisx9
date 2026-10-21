module "env" {
  environment_reviewers_enabled = var.environment_reviewers_enabled
  source                        = "../modules/aegisx9-env"

  environment = "prod"
  quota = {
    requests_cpu    = "4"
    requests_memory = "8Gi"
    limits_cpu      = "8"
    limits_memory   = "16Gi"
    pods            = 30
  }

  vault_kubernetes_auth_path  = var.vault_kubernetes_auth_path
  pki_domain                  = var.pki_domain
  idp_authorization_flow_slug = var.idp_authorization_flow_slug
  idp_invalidation_flow_slug  = var.idp_invalidation_flow_slug
  idp_redirect_uris           = var.idp_redirect_uris

  public_records           = var.public_records
  public_exposure_approval = var.public_exposure_approval
}

output "namespace" {
  description = "Production namespace."
  value       = module.env.namespace
}

output "vault_mounts" {
  description = "Production Vault mounts."
  value       = module.env.vault_mounts
}
