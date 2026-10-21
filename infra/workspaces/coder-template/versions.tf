terraform {
  required_version = ">= 1.9.0"

  # This template is applied by the Coder provisioner (coder templates push), not by
  # Terraform Enterprise, so there is no cloud {} block and no remote state here.
  required_providers {
    coder = {
      source  = "coder/coder"
      version = "~> 2.11"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 3.4"
    }
  }
}
