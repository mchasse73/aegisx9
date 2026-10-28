variable "aws_region" {
  description = "AWS region for the scanner host."
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "VPC the scanner runs in (supplied by platform operations as a workspace variable)."
  type        = string
  validation {
    condition     = can(regex("^vpc-[0-9a-f]+$", var.vpc_id))
    error_message = "vpc_id must be a VPC id (vpc-...)."
  }
}

variable "subnet_id" {
  description = "Public subnet for the scanner (supplied by platform operations as a workspace variable)."
  type        = string
  validation {
    condition     = can(regex("^subnet-[0-9a-f]+$", var.subnet_id))
    error_message = "subnet_id must be a subnet id (subnet-...)."
  }
}

variable "eip_allocation_id" {
  description = "Allocation id of the EXISTING Elastic IP to associate. The address is kept (it is on allowlists); this root never creates one."
  type        = string
  validation {
    condition     = can(regex("^eipalloc-[0-9a-f]+$", var.eip_allocation_id))
    error_message = "eip_allocation_id must be an EIP allocation id (eipalloc-...)."
  }
}

variable "instance_type" {
  description = "EC2 instance type."
  type        = string
  default     = "t3.small"
}

variable "volume_size" {
  description = "Root volume size in GiB. The red-team toolchain (garak, CPU-only torch, Node.js), nuclei templates, reports and patches need room; 16 GiB filled up during bootstrap."
  type        = number
  default     = 30
  validation {
    condition     = var.volume_size >= 30
    error_message = "volume_size must be at least 30 GiB (the red-team toolchain does not fit in less)."
  }
}

variable "detailed_monitoring" {
  description = "Enable EC2 detailed (1-minute) CloudWatch monitoring. Costs a few USD a month; Checkov CKV_AWS_126 expects it."
  type        = bool
  default     = true
}

variable "cost_center" {
  description = "Cost-centre tag applied to every resource."
  type        = string
}

variable "owner" {
  description = "Owner tag applied to every resource."
  type        = string
  default     = "platform-operations"
}

variable "team" {
  description = "Team tag applied to every resource."
  type        = string
  default     = "aegisx9"
}

variable "ses_identity_arn" {
  description = "ARN of the ONE SES identity the scanner may send from (ses:SendEmail is restricted to it)."
  type        = string
  validation {
    condition     = can(regex("^arn:aws:ses:[a-z0-9-]+:[0-9]{12}:identity/", var.ses_identity_arn))
    error_message = "ses_identity_arn must be an SES identity ARN."
  }
}

variable "report_email" {
  description = "Recipient of scan reports (comma-separated allowed). Empty disables email."
  type        = string
  default     = ""
}

variable "report_from_email" {
  description = "Sender address (must belong to ses_identity_arn). Empty disables email."
  type        = string
  default     = ""
}

variable "nuclei_version" {
  description = "Pinned nuclei release installed at boot (checksum-verified)."
  type        = string
  default     = "3.6.0"
}

variable "scanner_package_ref" {
  description = "Release tag (vX.Y.Z) or full 40-character commit SHA of this repository that the scanner package, its systemd units and the red-team suites are installed from. Required: it must name a release that contains the bootstrap and unit fixes of issue #96 (no earlier tag boots cleanly)."
  type        = string
  validation {
    condition     = can(regex("^(v[0-9]+\\.[0-9]+\\.[0-9]+|[0-9a-f]{40})$", var.scanner_package_ref))
    error_message = "scanner_package_ref must be a vX.Y.Z release tag or a 40-character lowercase commit SHA."
  }
}

variable "torch_version" {
  description = "torch release installed from the CPU-only wheel index before garak, so pip never pulls the multi-gigabyte CUDA build."
  type        = string
  default     = "2.14.1"
  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.torch_version))
    error_message = "torch_version must be X.Y.Z."
  }
}

variable "torch_index_url" {
  description = "Wheel index that serves the CPU-only torch build (torch==<torch_version>+cpu). Keep in step with scanner_torch_index_url in the x9.aegisx9.scanner role."
  type        = string
  default     = "https://download.pytorch.org/whl/cpu"
  validation {
    condition     = can(regex("^https://", var.torch_index_url))
    error_message = "torch_index_url must be an https URL."
  }
}

variable "garak_version" {
  description = "garak release installed next to the scanner for the weekly red-team unit. Keep in step with scanner_garak_version in the x9.aegisx9.scanner role."
  type        = string
  default     = "0.17.1"
  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.garak_version))
    error_message = "garak_version must be X.Y.Z."
  }
}

variable "redteam_target_url" {
  description = "Public gateway URL for the weekly external red-team run. Empty = the unit exits 0 with a note."
  type        = string
  default     = ""
}

variable "redteam_model" {
  description = "Model name the red-team suites request from the gateway."
  type        = string
  default     = ""
}

variable "alert_min_severity" {
  description = "Lowest alert severity that triggers a notification (low, medium, high, critical)."
  type        = string
  default     = "medium"
  validation {
    condition     = contains(["low", "medium", "high", "critical"], var.alert_min_severity)
    error_message = "alert_min_severity must be low, medium, high or critical."
  }
}

# SSM Parameter Store parameter NAMES (SecureString). Values are created by platform
# operations and are never Terraform variables, outputs or user-data text.
variable "ssm_parameter_prefix" {
  description = "Prefix of the scanner's SSM parameters; the instance role may read only this subtree."
  type        = string
  default     = "/aegisx9/scanner"
}

variable "webhook_url_parameter" {
  description = "SSM parameter holding the Event-Driven Ansible webhook URL. Optional: absent means webhook alerts off (email only)."
  type        = string
  default     = "/aegisx9/scanner/webhook_url"
}

variable "webhook_secret_parameter" {
  description = "SSM SecureString holding the webhook HMAC secret. Required only when the webhook URL parameter exists."
  type        = string
  default     = "/aegisx9/scanner/webhook_secret"
}

variable "tunnel_secret_parameter" {
  description = "SSM SecureString for the outbound tunnel agent that lets the internal network read the scanner's reports."
  type        = string
  default     = "/aegisx9/scanner/tunnel_secret"
}

variable "redteam_key_parameter" {
  description = "SSM SecureString holding the gateway red-team API key."
  type        = string
  default     = "/aegisx9/scanner/redteam_key"
}

variable "ssm_kms_key_arn" {
  description = "KMS key that encrypts the scanner's SecureString parameters. null = the AWS-managed alias/aws/ssm key."
  type        = string
  default     = null
  nullable    = true
}

# TODO(platform operations): when the Vault AWS IAM auth method is enabled, the host
# authenticates with its instance role (no secret on the box); set this and
# vault_address / vault_auth_role then. Vault paths are decided by platform operations
# and are not invented here.
variable "vault_aws_auth_enabled" {
  description = "Write VAULT_ADDR/VAULT_AUTH_ROLE into the scanner environment for Vault AWS IAM auth."
  type        = bool
  default     = false
}

variable "vault_address" {
  description = "Vault address used only when vault_aws_auth_enabled is true."
  type        = string
  default     = null
  nullable    = true
}

variable "vault_auth_role" {
  description = "Vault AWS auth role used only when vault_aws_auth_enabled is true."
  type        = string
  default     = null
  nullable    = true
}
