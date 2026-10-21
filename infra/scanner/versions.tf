terraform {
  required_version = ">= 1.9.0"

  # Terraform Enterprise. The hostname is supplied by TF_CLOUD_HOSTNAME (not stored here).
  cloud {
    organization = "x9"
    workspaces {
      name = "aegisx9-scanner"
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.69"
    }
  }
}
