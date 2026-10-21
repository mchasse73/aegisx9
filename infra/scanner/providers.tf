# Credentials never live in this repository or in variable defaults.
#  - aws: TFE dynamic provider credentials (TFC_AWS_PROVIDER_AUTH, TFC_AWS_RUN_ROLE_ARN)
# The scanner's own secrets (webhook HMAC, tunnel, red-team key) are SecureString
# parameters in the SSM Parameter Store, created by platform operations outside this
# root; only their NAMES are variables here.
provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project    = "aegisx9"
      ManagedBy  = "terraform"
      Component  = "external-vantage"
      CostCenter = var.cost_center
      owner      = var.owner
      team       = var.team
    }
  }
}
