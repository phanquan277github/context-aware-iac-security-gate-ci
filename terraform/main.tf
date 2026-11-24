# Synthetic CI-5 fixture adapted from the project-authored D-040 scenario.
# Static demo only. Do not deploy.
terraform {
  required_version = "= 1.16.2"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.100.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}

resource "aws_vpc" "demo" {
  cidr_block           = "10.57.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "ci5-synthetic-vpc"
  }
}

# Standalone rule resources reference this security group and its VPC.
resource "aws_security_group" "demo" {
  name        = "ci5-synthetic-gate"
  description = "Static demonstration security group"
  vpc_id      = aws_vpc.demo.id

  tags = {
    Name = "ci5-synthetic-gate"
  }
}

# Intended ingress diagnostic: public HTTP access on TCP port 80.
resource "aws_security_group_rule" "http_ingress" {
  type              = "ingress"
  description       = "Synthetic public HTTP ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.demo.id
}

# Intended egress diagnostic: unrestricted outbound IPv4 reachability.
resource "aws_security_group_rule" "open_egress" {
  type              = "egress"
  description       = "Synthetic unrestricted outbound traffic"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.demo.id
}

# Single literal IAM statement keeps Action/Resource evidence readable.
resource "aws_iam_policy" "demo_pass_role" {
  name        = "ci5_synthetic_pass_role"
  description = "Static demonstration of unconstrained PassRole resource scope"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DemoUnconstrainedPassRole"
      Effect   = "Allow"
      Action   = "iam:PassRole"
      Resource = "*"
    }]
  })
}
