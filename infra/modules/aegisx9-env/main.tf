locals {
  namespace = "aegisx9-${var.environment}"
  labels = {
    "app.kubernetes.io/part-of"    = "aegisx9"
    "app.kubernetes.io/managed-by" = "terraform"
    "aegisx9.io/environment"       = var.environment
    "aegisx9.io/owner"             = var.owner
  }
  kv_mount      = "${var.vault_mount_prefix}-${var.environment}-kv"
  transit_mount = "${var.vault_mount_prefix}-${var.environment}-transit"
  pki_mount     = "${var.vault_mount_prefix}-${var.environment}-pki"
}

# --- Kubernetes: namespace, quota, limits, default deny ------------------------------

resource "kubernetes_namespace_v1" "this" {
  metadata {
    name = local.namespace
    labels = merge(local.labels, {
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
    })
  }
}

resource "kubernetes_resource_quota_v1" "this" {
  metadata {
    name      = "aegisx9-quota"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    labels    = local.labels
  }
  spec {
    hard = {
      "requests.cpu"    = var.quota.requests_cpu
      "requests.memory" = var.quota.requests_memory
      "limits.cpu"      = var.quota.limits_cpu
      "limits.memory"   = var.quota.limits_memory
      "pods"            = tostring(var.quota.pods)
    }
  }
}

resource "kubernetes_limit_range_v1" "this" {
  metadata {
    name      = "aegisx9-defaults"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    labels    = local.labels
  }
  spec {
    limit {
      type = "Container"
      default = {
        cpu    = "500m"
        memory = "512Mi"
      }
      default_request = {
        cpu    = "100m"
        memory = "128Mi"
      }
    }
  }
}

resource "kubernetes_network_policy_v1" "default_deny" {
  metadata {
    name      = "default-deny"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    labels    = local.labels
  }
  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

# --- Vault: runtime provider keys, transit audit signing, PKI for mTLS ---------------

resource "vault_mount" "kv" {
  path        = local.kv_mount
  type        = "kv"
  options     = { version = "2" }
  description = "AegisX9 ${var.environment}: model-provider keys, read at runtime only"
}

resource "vault_mount" "transit" {
  path        = local.transit_mount
  type        = "transit"
  description = "AegisX9 ${var.environment}: audit-record signing"
}

resource "vault_transit_secret_backend_key" "audit" {
  backend            = vault_mount.transit.path
  name               = "audit"
  type               = "ed25519"
  exportable         = false
  deletion_allowed   = false
  auto_rotate_period = 2592000 # 30 days; old versions still verify
}

resource "vault_mount" "pki" {
  path                  = local.pki_mount
  type                  = "pki"
  description           = "AegisX9 ${var.environment}: gateway mTLS (intermediate CA)"
  max_lease_ttl_seconds = 31536000
}

resource "vault_pki_secret_backend_role" "gateway" {
  backend           = vault_mount.pki.path
  name              = "gateway"
  allowed_domains   = [var.pki_domain]
  allow_subdomains  = true
  allow_any_name    = false
  enforce_hostnames = true
  server_flag       = true
  client_flag       = true
  key_type          = "ec"
  key_bits          = 256
  max_ttl           = "72h"
  ttl               = "24h"
  no_store          = true
}

resource "vault_policy" "gateway" {
  name   = "aegisx9-${var.environment}-gateway"
  policy = <<-EOT
    # Read provider keys at runtime (Vault Agent / External Secrets); never list or write.
    path "${vault_mount.kv.path}/data/providers/*" {
      capabilities = ["read"]
    }
    # Sign audit records. Verification is a separate, read-only policy.
    path "${vault_mount.transit.path}/sign/${vault_transit_secret_backend_key.audit.name}" {
      capabilities = ["update"]
    }
    # Issue short-lived mTLS certificates.
    path "${vault_mount.pki.path}/issue/${vault_pki_secret_backend_role.gateway.name}" {
      capabilities = ["update"]
    }
  EOT
}

resource "vault_policy" "audit_verifier" {
  name   = "aegisx9-${var.environment}-audit-verifier"
  policy = <<-EOT
    path "${vault_mount.transit.path}/verify/${vault_transit_secret_backend_key.audit.name}" {
      capabilities = ["update"]
    }
  EOT
}

resource "vault_kubernetes_auth_backend_role" "gateway" {
  backend                          = var.vault_kubernetes_auth_path
  role_name                        = "aegisx9-${var.environment}-gateway"
  bound_service_account_names      = [var.gateway_service_account]
  bound_service_account_namespaces = [kubernetes_namespace_v1.this.metadata[0].name]
  token_policies                   = [vault_policy.gateway.name]
  token_ttl                        = 3600
  token_max_ttl                    = 14400
  audience                         = "vault"
}

# --- Identity provider: OIDC application for the gateway -----------------------------

data "authentik_flow" "authorization" {
  slug = var.idp_authorization_flow_slug
}

data "authentik_flow" "invalidation" {
  slug = var.idp_invalidation_flow_slug
}

resource "authentik_provider_oauth2" "gateway" {
  name               = "aegisx9-${var.environment}"
  client_id          = "aegisx9-${var.environment}"
  client_type        = "confidential"
  authorization_flow = data.authentik_flow.authorization.id
  invalidation_flow  = data.authentik_flow.invalidation.id
  allowed_redirect_uris = [
    for uri in var.idp_redirect_uris : { matching_mode = "strict", url = uri }
  ]
  access_token_validity = "minutes=10"
}

resource "authentik_application" "gateway" {
  name              = "AegisX9 (${var.environment})"
  slug              = "aegisx9-${var.environment}"
  protocol_provider = authentik_provider_oauth2.gateway.id
}

# The client secret goes straight into Vault; it is never an output.
resource "vault_kv_secret_v2" "oidc_client" {
  mount = vault_mount.kv.path
  name  = "oidc/gateway"
  data_json = jsonencode({
    client_id     = authentik_provider_oauth2.gateway.client_id
    client_secret = authentik_provider_oauth2.gateway.client_secret
  })
}

# --- GitHub: protected environment and branch protection ------------------------------

data "github_repository" "this" {
  name = var.github_repository
}

data "github_user" "reviewers" {
  for_each = toset(var.github_reviewers)
  username = each.value
}

resource "github_repository_environment" "this" {
  repository          = data.github_repository.this.name
  environment         = var.environment == "prod" ? "production" : "staging"
  prevent_self_review = false
  can_admins_bypass   = false
  reviewers {
    users = [for u in data.github_user.reviewers : tonumber(u.id)]
  }
  deployment_branch_policy {
    protected_branches     = true
    custom_branch_policies = false
  }
}

resource "github_branch_protection" "main" {
  count                           = var.manage_branch_protection ? 1 : 0
  repository_id                   = data.github_repository.this.node_id
  pattern                         = "main"
  enforce_admins                  = true
  require_signed_commits          = false
  required_linear_history         = true
  require_conversation_resolution = true
  allows_force_pushes             = false
  allows_deletions                = false

  required_status_checks {
    strict   = true
    contexts = var.required_status_checks
  }

  required_pull_request_reviews {
    required_approving_review_count = 1
    require_code_owner_reviews      = true
    dismiss_stale_reviews           = true
  }
}

# --- ARC: ephemeral self-hosted runners for in-cluster jobs (main only) ---------------

resource "kubernetes_namespace_v1" "arc" {
  count = var.deploy_arc_runners ? 1 : 0
  metadata {
    name = "aegisx9-arc"
    labels = merge(local.labels, {
      "pod-security.kubernetes.io/enforce" = "restricted"
    })
  }
}

resource "helm_release" "arc_runners" {
  count      = var.deploy_arc_runners ? 1 : 0
  name       = "aegisx9-arc"
  namespace  = kubernetes_namespace_v1.arc[0].metadata[0].name
  repository = "oci://ghcr.io/actions/actions-runner-controller-charts"
  chart      = "gha-runner-scale-set"
  version    = var.arc_chart_version

  set = [
    { name = "githubConfigUrl", value = "https://github.com/mchasse73/${var.github_repository}" },
    { name = "githubConfigSecret", value = var.arc_github_config_ref },
    { name = "runnerScaleSetName", value = "aegisx9-arc" },
    { name = "minRunners", value = "0" },
    { name = "maxRunners", value = "2" },
  ]
}

# --- Route 53: aegisx9.com only, and only with an exposure approval -------------------

data "aws_route53_zone" "aegisx9" {
  count        = length(var.public_records) > 0 ? 1 : 0
  name         = "aegisx9.com."
  private_zone = false
}

resource "aws_route53_record" "public" {
  for_each = var.public_exposure_approval != "" ? var.public_records : {}
  zone_id  = data.aws_route53_zone.aegisx9[0].zone_id
  name     = each.key == "@" ? "aegisx9.com" : "${each.key}.aegisx9.com"
  type     = each.value.type
  ttl      = each.value.ttl
  records  = each.value.records
}
