terraform {
  required_version = "= 1.16.2"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.100.0"
    }
  }
}

resource "aws_vpc" "demonstration" {
  cidr_block = "10.19.0.0/16"
}
