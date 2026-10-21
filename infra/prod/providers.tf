# Credentials never live in this repository or in variable defaults.
#  - kubernetes/helm: KUBE_HOST, KUBE_TOKEN, KUBE_CLUSTER_CA_CERT_DATA (sensitive workspace env)
#  - vault: TFE dynamic provider credentials (TFC_VAULT_PROVIDER_AUTH, TFC_VAULT_ADDR, ...)
#  - aws: TFE dynamic provider credentials (TFC_AWS_PROVIDER_AUTH, TFC_AWS_RUN_ROLE_ARN)
#  - authentik: AUTHENTIK_URL, AUTHENTIK_TOKEN (sensitive workspace env)
#  - github: GITHUB_TOKEN from a GitHub App installation (sensitive workspace env)
provider "kubernetes" {}

provider "helm" {
  kubernetes = {}
}

provider "vault" {}

provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      Project     = "aegisx9"
      ManagedBy   = "terraform"
      Environment = var.environment_tag
    }
  }
}

provider "authentik" {}

provider "github" {
  owner = "mchasse73"
}
