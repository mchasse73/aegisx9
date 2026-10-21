variable "environment_tag" {
  description = "Environment tag applied to AWS resources."
  type        = string
  default     = "prod"
}

variable "vault_kubernetes_auth_path" {
  description = "Vault Kubernetes auth mount for the homelab cluster (workspace variable)."
  type        = string
}

variable "pki_domain" {
  description = "Internal DNS suffix for mTLS certificates (workspace variable)."
  type        = string
}

variable "idp_authorization_flow_slug" {
  description = "Identity-provider authorization flow (MFA) slug."
  type        = string
}

variable "idp_invalidation_flow_slug" {
  description = "Identity-provider invalidation flow slug."
  type        = string
}

variable "idp_redirect_uris" {
  description = "OIDC redirect URIs for production."
  type        = list(string)
}

variable "public_records" {
  description = "Public DNS records in the aegisx9.com zone."
  type = map(object({
    type    = string
    ttl     = number
    records = list(string)
  }))
  default = {}
}

variable "public_exposure_approval" {
  description = "Approval reference required for any public exposure (checked by Sentinel)."
  type        = string
  default     = ""
}
