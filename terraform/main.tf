terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.100.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

locals {
  name_prefix = "${var.project_name}-${var.environment}"

  common_tags = merge(
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    },
    var.additional_tags
  )
}

# ------------------------------------------------------------------------------
# Variables
# ------------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region where infrastructure resources will be provisioned."
  type        = string
  default     = "ap-southeast-1"
}

variable "project_name" {
  description = "Project identifier used for naming and tagging resources."
  type        = string
  default     = "webapp"
}

variable "environment" {
  description = "Deployment environment name (e.g., dev, staging, prod)."
  type        = string
  default     = "prod"
}

variable "vpc_cidr" {
  description = "IPv4 CIDR block for the dedicated VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "IPv4 CIDR block for the public subnet."
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "IPv4 CIDR block for the private subnet."
  type        = string
  default     = "10.0.2.0/24"
}

variable "public_subnet_az" {
  description = "Availability Zone for the public subnet."
  type        = string
  default     = "ap-southeast-1a"
}

variable "private_subnet_az" {
  description = "Availability Zone for the private subnet."
  type        = string
  default     = "ap-southeast-1b"
}

variable "ami_id" {
  description = "AMI ID for the web application EC2 instance."
  type        = string
  default     = "ami-0123456789abcdef0"
}

variable "instance_type" {
  description = "EC2 instance type for hosting the web application."
  type        = string
  default     = "t3.micro"
}

variable "key_name" {
  description = "Name of an existing EC2 Key Pair for SSH administrative access."
  type        = string
  default     = "webapp-admin-key"
}

variable "admin_cidr_blocks" {
  description = "List of trusted IPv4 CIDR blocks permitted for SSH administrative maintenance."
  type        = list(string)
  default     = ["203.0.113.0/24"]
}

variable "assets_bucket_name" {
  description = "Globally unique name for the S3 bucket storing application assets."
  type        = string
  default     = "webapp-prod-application-assets-ap-southeast-1"
}

variable "additional_tags" {
  description = "Additional custom tags to apply to all resources."
  type        = map(string)
  default     = {}
}

# ------------------------------------------------------------------------------
# Networking (VPC, Subnets, Internet Gateway, Route Tables)
# ------------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-default-sg-restricted"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = var.public_subnet_az
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.name_prefix}-public-subnet"
    Tier = "Public"
  }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.private_subnet_cidr
  availability_zone       = var.private_subnet_az
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.name_prefix}-private-subnet"
    Tier = "Private"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-public-rt"
  }
}

resource "aws_route" "public_internet_access" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# ------------------------------------------------------------------------------
# Security Groups
# ------------------------------------------------------------------------------

resource "aws_security_group" "web_app" {
  name        = "${local.name_prefix}-web-sg"
  description = "Security group for the public-facing web application EC2 instance."
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-web-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "web_http" {
  security_group_id = aws_security_group.web_app.id
  description       = "Allow inbound HTTP traffic from Internet users."
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"

  tags = {
    Name = "${local.name_prefix}-ingress-http"
  }
}

resource "aws_vpc_security_group_ingress_rule" "web_https" {
  security_group_id = aws_security_group.web_app.id
  description       = "Allow inbound HTTPS traffic from Internet users."
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"

  tags = {
    Name = "${local.name_prefix}-ingress-https"
  }
}

resource "aws_vpc_security_group_ingress_rule" "web_ssh_admin" {
  for_each = toset(var.admin_cidr_blocks)

  security_group_id = aws_security_group.web_app.id
  description       = "Allow SSH administrative maintenance from trusted CIDR blocks."
  cidr_ipv4         = each.value
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"

  tags = {
    Name = "${local.name_prefix}-ingress-ssh"
  }
}

resource "aws_vpc_security_group_egress_rule" "web_https_outbound" {
  security_group_id = aws_security_group.web_app.id
  description       = "Allow outbound HTTPS traffic for AWS API calls (S3) and secure updates."
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"

  tags = {
    Name = "${local.name_prefix}-egress-https"
  }
}

resource "aws_vpc_security_group_egress_rule" "web_http_outbound" {
  security_group_id = aws_security_group.web_app.id
  description       = "Allow outbound HTTP traffic for OS package repositories."
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"

  tags = {
    Name = "${local.name_prefix}-egress-http"
  }
}

# ------------------------------------------------------------------------------
# S3 Bucket for Application Assets
# ------------------------------------------------------------------------------

resource "aws_s3_bucket" "assets" {
  bucket = var.assets_bucket_name

  tags = {
    Name = "${local.name_prefix}-assets-bucket"
  }
}

resource "aws_s3_bucket_ownership_controls" "assets" {
  bucket = aws_s3_bucket.assets.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket = aws_s3_bucket.assets.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "assets" {
  bucket = aws_s3_bucket.assets.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# ------------------------------------------------------------------------------
# IAM Role & Instance Profile for S3 Access
# ------------------------------------------------------------------------------

resource "aws_iam_role" "web_app" {
  name        = "${local.name_prefix}-ec2-role"
  description = "IAM role allowing the web application EC2 instance to access S3 assets."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEC2AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${local.name_prefix}-ec2-role"
  }
}

resource "aws_iam_policy" "s3_assets_access" {
  name        = "${local.name_prefix}-s3-assets-policy"
  description = "Least-privilege policy granting read/write access to the application assets S3 bucket."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListAssetsBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = aws_s3_bucket.assets.arn
      },
      {
        Sid    = "ManageAssetsObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.assets.arn}/*"
      }
    ]
  })

  tags = {
    Name = "${local.name_prefix}-s3-assets-policy"
  }
}

resource "aws_iam_role_policy_attachment" "web_app_s3" {
  role       = aws_iam_role.web_app.name
  policy_arn = aws_iam_policy.s3_assets_access.arn
}

resource "aws_iam_instance_profile" "web_app" {
  name = "${local.name_prefix}-ec2-profile"
  role = aws_iam_role.web_app.name

  tags = {
    Name = "${local.name_prefix}-ec2-profile"
  }
}

# ------------------------------------------------------------------------------
# Compute (Web Application EC2 Instance)
# ------------------------------------------------------------------------------

resource "aws_instance" "web_app" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.web_app.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.web_app.name
  key_name                    = var.key_name
  ebs_optimized               = true
  monitoring                  = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true
  }

  depends_on = [
    aws_internet_gateway.main,
    aws_route_table_association.public,
    aws_iam_role_policy_attachment.web_app_s3
  ]

  tags = {
    Name = "${local.name_prefix}-web-server"
    Role = "WebApplication"
  }
}

# ------------------------------------------------------------------------------
# Outputs
# ------------------------------------------------------------------------------

output "vpc_id" {
  description = "ID of the dedicated VPC."
  value       = aws_vpc.main.id
}

output "public_subnet_id" {
  description = "ID of the public subnet."
  value       = aws_subnet.public.id
}

output "private_subnet_id" {
  description = "ID of the private subnet."
  value       = aws_subnet.private.id
}

output "web_app_security_group_id" {
  description = "ID of the web application security group."
  value       = aws_security_group.web_app.id
}

output "web_app_instance_id" {
  description = "ID of the web application EC2 instance."
  value       = aws_instance.web_app.id
}

output "web_app_public_ip" {
  description = "Public IPv4 address of the web application EC2 instance."
  value       = aws_instance.web_app.public_ip
}

output "web_app_public_dns" {
  description = "Public DNS name of the web application EC2 instance."
  value       = aws_instance.web_app.public_dns
}

output "web_app_iam_role_arn" {
  description = "ARN of the IAM role attached to the web application instance."
  value       = aws_iam_role.web_app.arn
}

output "web_app_instance_profile_arn" {
  description = "ARN of the IAM instance profile attached to the web application instance."
  value       = aws_iam_instance_profile.web_app.arn
}

output "assets_s3_bucket_id" {
  description = "Name (ID) of the S3 bucket storing application assets."
  value       = aws_s3_bucket.assets.id
}

output "assets_s3_bucket_arn" {
  description = "ARN of the S3 bucket storing application assets."
  value       = aws_s3_bucket.assets.arn
}
