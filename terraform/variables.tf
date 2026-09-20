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
