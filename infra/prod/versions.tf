terraform {
  required_version = ">= 1.9.0"

  # Terraform Enterprise. The hostname is supplied by TF_CLOUD_HOSTNAME (not stored here).
  cloud {
    organization = "x9"
    workspaces {
      name = "aegisx9-prod"
    }
  }

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 3.4"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 3.3"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 5.13"
    }
    github = {
      source  = "integrations/github"
      version = "~> 6.13"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.69"
    }
    authentik = {
      source  = "goauthentik/authentik"
      version = "~> 2026.8"
    }
  }
}
