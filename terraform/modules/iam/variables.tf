variable "prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "scan_target_role_arns" {
  type    = set(string)
  default = []
}
