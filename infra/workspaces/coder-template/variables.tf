# Template variables: set once per template version with `coder templates push
# --variable name=value` (or --variables-file). Developers never see them; they choose
# the per-workspace coder_parameters in main.tf instead.

variable "namespace" {
  description = "Namespace that holds the developer workspaces (built by the platform team with its quota, LimitRange and NetworkPolicies)."
  type        = string
  default     = "aegisx9-dev"
}

variable "workspace_image" {
  description = "Workspace image repository. Must be the signed devcontainer image from this project's registry path."
  type        = string
  default     = "ghcr.io/mchasse73/aegisx9/workspace"
  validation {
    condition     = startswith(var.workspace_image, "ghcr.io/mchasse73/aegisx9")
    error_message = "workspace_image must be under ghcr.io/mchasse73/aegisx9 (the only registry path the admission policy admits)."
  }
}

variable "workspace_image_digest" {
  description = "sha256 digest of the workspace image to run. A new template version is pushed for every digest; tags are never used."
  type        = string
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.workspace_image_digest))
    error_message = "workspace_image_digest must look like sha256:<64 hex characters>."
  }
}

variable "image_pull_secret" {
  description = "Name of the registry pull Secret in the namespace (created by the platform team). Empty when the image is public."
  type        = string
  default     = ""
}

variable "home_size" {
  description = "Size of the persistent home volume (/home/dev)."
  type        = string
  default     = "50Gi"
}

variable "storage_class" {
  description = "StorageClass for the home volume. Empty uses the cluster default."
  type        = string
  default     = ""
}

variable "gateway_url" {
  description = "AegisX9 gateway base URL, exported as ANTHROPIC_BASE_URL. Every model call from a workspace goes through it; no provider key is ever present in a workspace."
  type        = string
  validation {
    condition     = startswith(var.gateway_url, "https://")
    error_message = "gateway_url must be an https:// URL."
  }
}

variable "otel_endpoint" {
  description = "OpenTelemetry collector endpoint, exported as OTEL_EXPORTER_OTLP_ENDPOINT so agent tooling in the workspace reports to the same audit pipeline as the gateway."
  type        = string
}

variable "agent_arch" {
  description = "CPU architecture of the cluster nodes (the Coder agent binary is chosen from it)."
  type        = string
  default     = "amd64"
  validation {
    condition     = contains(["amd64", "arm64"], var.agent_arch)
    error_message = "agent_arch must be amd64 or arm64."
  }
}

variable "ssh_port" {
  description = "Port the in-workspace sshd listens on for Remote-SSH and JetBrains Gateway (unprivileged, so above 1024)."
  type        = number
  default     = 2222
  validation {
    condition     = var.ssh_port > 1024 && var.ssh_port < 65536
    error_message = "ssh_port must be an unprivileged port (1025-65535)."
  }
}
