# AegisX9 Sentinel policy set, attached in Terraform Enterprise to the
# aegisx9-staging and aegisx9-prod workspaces. Tests: `sentinel test` in this directory.

policy "public-exposure-approval" {
  source            = "./public-exposure-approval.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "required-labels" {
  source            = "./required-labels.sentinel"
  enforcement_level = "soft-mandatory"
}

policy "resource-limits" {
  source            = "./resource-limits.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "signed-digest-images" {
  source            = "./signed-digest-images.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "no-plaintext-secret-variables" {
  source            = "./no-plaintext-secret-variables.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "route53-aegisx9-zone-only" {
  source            = "./route53-aegisx9-zone-only.sentinel"
  enforcement_level = "hard-mandatory"
}
