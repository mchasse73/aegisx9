variable "environment" {
  description = "Environment name: staging or prod."
  type        = string
  validation {
    condition     = contains(["staging", "prod"], var.environment)
    error_message = "environment must be staging or prod."
  }
}

variable "owner" {
  description = "Owning team or person, recorded as a label on every resource."
  type        = string
  default     = "mchasse73"
}

variable "quota" {
  description = "Namespace resource quota."
  type = object({
    requests_cpu    = string
    requests_memory = string
    limits_cpu      = string
    limits_memory   = string
    pods            = number
  })
}

variable "gateway_service_account" {
  description = "Kubernetes service account the gateway runs as (from the Helm chart)."
  type        = string
  default     = "aegisx9"
}

variable "vault_kubernetes_auth_path" {
  description = "Path of the Vault Kubernetes auth backend for the homelab cluster (set in the workspace)."
  type        = string
}

variable "vault_mount_prefix" {
  description = "Prefix for the Vault mounts this module creates."
  type        = string
  default     = "aegisx9"
}

variable "pki_domain" {
  description = "Internal DNS suffix for gateway mTLS certificates (set in the workspace)."
  type        = string
}

variable "idp_authorization_flow_slug" {
  description = "Identity-provider flow slug that enforces MFA for the gateway app."
  type        = string
}

variable "idp_invalidation_flow_slug" {
  description = "Identity-provider logout flow slug."
  type        = string
}

variable "idp_redirect_uris" {
  description = "Allowed OIDC redirect URIs for this environment."
  type        = list(string)
}

variable "github_repository" {
  description = "Repository name (without owner)."
  type        = string
  default     = "aegisx9"
}

variable "github_reviewers" {
  description = "GitHub usernames that must approve deployments to this environment."
  type        = list(string)
  default     = ["mchasse73"]
}

variable "manage_branch_protection" {
  description = "Whether this workspace owns the branch protection on main (exactly one should)."
  type        = bool
  default     = false
}

variable "environment_reviewers_enabled" {
  description = "Attach required reviewers to the GitHub environment (needs a public repository or a paid plan)."
  type        = bool
  default     = false
}

variable "required_status_checks" {
  description = "CI job names required before merging to main."
  type        = list(string)
  default = [
    "lint, types, tests",
    "gitleaks",
    "semgrep",
    "pip-audit",
    "helm lint, Checkov, kube-linter",
    "docker build + Trivy",
    "terraform fmt, validate, tflint, Checkov",
    "sentinel test",
    "ansible-lint",
  ]
}

variable "deploy_arc_runners" {
  description = "Install the ARC runner scale set (once per cluster)."
  type        = bool
  default     = false
}

variable "arc_chart_version" {
  description = "Pinned gha-runner-scale-set chart version."
  type        = string
  default     = "0.15.0"
}

variable "arc_github_config_ref" {
  description = "Name of the Kubernetes Secret (created by External Secrets) holding the ARC GitHub App credentials."
  type        = string
  default     = "aegisx9-arc-github-app"
}

variable "public_records" {
  description = "Public DNS records in the aegisx9.com zone. Empty unless exposure is approved."
  type = map(object({
    type    = string
    ttl     = number
    records = list(string)
  }))
  default = {}
}

variable "public_exposure_approval" {
  description = "Change/approval reference for any public exposure. Sentinel requires it when public records exist."
  type        = string
  default     = ""
}
