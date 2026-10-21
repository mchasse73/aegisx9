output "instance_id" {
  description = "Scanner instance id (SSM target)."
  value       = aws_instance.scanner.id
}

output "private_ip" {
  description = "Private address inside the VPC."
  value       = aws_instance.scanner.private_ip
}

output "ssm_session_command" {
  description = "Open a shell through SSM Session Manager (no SSH)."
  value       = "aws ssm start-session --region ${local.region} --target ${aws_instance.scanner.id}"
}
