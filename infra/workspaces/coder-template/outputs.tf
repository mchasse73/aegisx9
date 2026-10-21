output "workspace_image" {
  description = "Exact image reference the workspace runs (repository@digest)."
  value       = local.image
}

output "home_claim" {
  description = "PersistentVolumeClaim that holds this workspace's home directory."
  value       = kubernetes_persistent_volume_claim_v1.home.metadata[0].name
}

output "pod_name" {
  description = "Name of the workspace pod while the workspace is running."
  value       = local.pod_name
}

output "labels" {
  description = "Labels applied to every Kubernetes object of the workspace."
  value       = local.labels
}
