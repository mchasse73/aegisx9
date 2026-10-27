# AegisX9 external vantage host: one small instance on the public internet that looks at
# the organisation's public surface every day. Reached only through SSM Session Manager
# (no SSH, no inbound rules at all). Secrets are SSM SecureString parameters read at boot
# with the instance role, never user-data text.

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# Ubuntu 24.04 LTS, resolved through Canonical's public SSM parameter (no owner id to pin).
data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

data "aws_kms_alias" "ssm" {
  name = "alias/aws/ssm"
}

locals {
  name       = "aegisx9-scanner"
  region     = data.aws_region.current.region
  account_id = data.aws_caller_identity.current.account_id
  ssm_arn    = "arn:aws:ssm:${local.region}:${local.account_id}:parameter${var.ssm_parameter_prefix}/*"
  kms_arn    = coalesce(var.ssm_kms_key_arn, data.aws_kms_alias.ssm.target_key_arn)
  tags = {
    Name       = local.name
    Project    = "aegisx9"
    CostCenter = var.cost_center
    owner      = var.owner
    team       = var.team
  }
  user_data = templatefile("${path.module}/cloud-init.sh.tftpl", {
    aws_region               = local.region
    nuclei_version           = var.nuclei_version
    scanner_package_ref      = var.scanner_package_ref
    torch_version            = var.torch_version
    webhook_url_parameter    = var.webhook_url_parameter
    webhook_secret_parameter = var.webhook_secret_parameter
    tunnel_secret_parameter  = var.tunnel_secret_parameter
    redteam_key_parameter    = var.redteam_key_parameter
    report_email             = var.report_email
    report_from_email        = var.report_from_email
    redteam_target_url       = var.redteam_target_url
    redteam_model            = var.redteam_model
    alert_min_severity       = var.alert_min_severity
    vault_aws_auth_enabled   = var.vault_aws_auth_enabled
    vault_address            = var.vault_address == null ? "" : var.vault_address
    vault_auth_role          = var.vault_auth_role == null ? "" : var.vault_auth_role
  })
}

# ---------------------------------------------------------------------------
# Network: no ingress at all. Egress is open because the scanner's job is to reach
# the public internet it audits.
# ---------------------------------------------------------------------------

resource "aws_security_group" "scanner" {
  name        = local.name
  description = "AegisX9 external vantage scanner: no ingress (SSM Session Manager only)"
  vpc_id      = var.vpc_id
  tags        = local.tags
}

resource "aws_vpc_security_group_egress_rule" "all_ipv4" {
  # checkov:skip=CKV_AWS_382:the scanner must reach the whole public internet it audits
  security_group_id = aws_security_group.scanner.id
  description       = "Scanner egress to the public internet (IPv4)"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  tags              = local.tags
}

resource "aws_vpc_security_group_egress_rule" "all_ipv6" {
  # checkov:skip=CKV_AWS_382:the scanner must reach the whole public internet it audits
  security_group_id = aws_security_group.scanner.id
  description       = "Scanner egress to the public internet (IPv6)"
  ip_protocol       = "-1"
  cidr_ipv6         = "::/0"
  tags              = local.tags
}

# ---------------------------------------------------------------------------
# IAM: SSM Session Manager, SES from one identity, read the scanner's own parameters.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scanner" {
  name               = local.name
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = local.tags
}

# AmazonSSMManagedInstanceCore is deliberately NOT attached: it grants
# ssm:GetParameter(s) on every parameter in the account, and IAM allows are additive,
# so the path-scoped statement below would not restrict it. "SessionManagerAgent"
# carries only what the SSM agent needs for Session Manager.
data "aws_iam_policy_document" "scanner" {
  # checkov:skip=CKV_AWS_355:the SSM agent and Session Manager actions below do not support resource-level permissions
  # checkov:skip=CKV_AWS_356:the SSM agent and Session Manager actions below do not support resource-level permissions
  # checkov:skip=CKV_AWS_111:only ssm:UpdateInstanceInformation and the Session Manager channel actions are unconstrained; AWS offers no resource scope for them
  # checkov:skip=CKV_AWS_290:ssm:UpdateInstanceInformation is the agent heartbeat; it has no resource constraint
  statement {
    sid = "SessionManagerAgent"
    actions = [
      "ssm:UpdateInstanceInformation",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
      "ec2messages:AcknowledgeMessage",
      "ec2messages:DeleteMessage",
      "ec2messages:FailMessage",
      "ec2messages:GetEndpoint",
      "ec2messages:GetMessages",
      "ec2messages:SendReply",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "SendReportsFromOneIdentity"
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = [var.ses_identity_arn]
  }

  statement {
    sid       = "ReadOwnParameters"
    actions   = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
    resources = [local.ssm_arn]
  }

  statement {
    sid       = "DecryptOwnParameters"
    actions   = ["kms:Decrypt"]
    resources = [local.kms_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${local.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "scanner" {
  name   = "${local.name}-runtime"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.scanner.json
}

resource "aws_iam_instance_profile" "scanner" {
  name = local.name
  role = aws_iam_role.scanner.name
  tags = local.tags
}

# ---------------------------------------------------------------------------
# Instance
# ---------------------------------------------------------------------------

resource "aws_instance" "scanner" {
  ami                    = nonsensitive(data.aws_ssm_parameter.ubuntu_ami.value)
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.scanner.id]
  iam_instance_profile   = aws_iam_instance_profile.scanner.name
  monitoring             = var.detailed_monitoring
  ebs_optimized          = true

  user_data_base64            = base64encode(local.user_data)
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = var.volume_size
    tags        = local.tags
  }

  tags = local.tags

  lifecycle {
    ignore_changes = [ami] # the "current" Ubuntu AMI moves; rebuilds are deliberate
  }
}

# Association only: the Elastic IP already exists and its address is on the
# organisation's allowlists. Destroying this root never releases the address.
resource "aws_eip_association" "scanner" {
  instance_id   = aws_instance.scanner.id
  allocation_id = var.eip_allocation_id
}
