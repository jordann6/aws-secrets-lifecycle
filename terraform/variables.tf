variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "prefix" {
  description = "Name prefix applied to every resource"
  type        = string
  default     = "secops"
}

variable "bedrock_model_id" {
  description = "Bedrock model ID used by the analyzer for runbook synthesis"
  type        = string
  default     = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
}

variable "cloudtrail_lookback_days" {
  description = "Trailing window of CloudTrail events the analyzer queries"
  type        = number
  default     = 90
}

variable "evidence_retention_days" {
  description = "Object Lock governance retention for evidence artifacts"
  type        = number
  default     = 1
}

variable "rotation_days" {
  description = "AutomaticallyAfterDays the executor sets when it starts rotation"
  type        = number
  default     = 30
}

variable "scan_target_role_arns" {
  description = "Exact metadata-only cross-account role ARNs from the landing zone secrets root"
  type        = set(string)
  default     = []
  validation {
    condition     = alltrue([for arn in var.scan_target_role_arns : can(regex("^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", arn))])
    error_message = "Every scan target must be an IAM role ARN."
  }
}

variable "scan_regions" {
  type    = set(string)
  default = ["us-east-1"]
  validation {
    condition     = length(var.scan_regions) > 0 && alltrue([for region in var.scan_regions : can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", region))])
    error_message = "Supply at least one AWS region."
  }
}

variable "secret_max_age_days" {
  type    = number
  default = 90
  validation {
    condition     = var.secret_max_age_days >= 1 && var.secret_max_age_days <= 365 && floor(var.secret_max_age_days) == var.secret_max_age_days
    error_message = "Secret maximum age must be a whole number from 1 to 365."
  }
}

variable "secret_alert_email" {
  description = "Optional subscriber for age and missed-scan alerts"
  type        = string
  default     = null
}
