terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # Null deploys into the caller's own account (the standalone demo). The
  # landing zone sets the security account's OrganizationAccountAccessRole so
  # security tooling never lands in the management account.
  dynamic "assume_role" {
    for_each = var.deploy_role_arn == null ? [] : [var.deploy_role_arn]
    content {
      role_arn = assume_role.value
    }
  }

  default_tags {
    tags = {
      Project   = "secops-secrets-lifecycle"
      ManagedBy = "terraform"
    }
  }
}
