variable "prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "role_arn" {
  type = string
}

variable "table_name" {
  type = string
}

variable "bedrock_model_id" {
  type = string
}

variable "lookback_days" {
  type = number
}

variable "zip_path" {
  type = string
}

variable "evidence_bucket" {
  type    = string
  default = ""
}

variable "securityhub_enabled" {
  type    = bool
  default = false
}
