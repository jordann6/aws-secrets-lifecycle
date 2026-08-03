variable "prefix" {
  type = string
}

variable "role_arn" {
  type = string
}

variable "table_name" {
  type = string
}

variable "scan_target_role_arns" {
  type    = string
  default = ""
}

variable "scan_regions" {
  type    = string
  default = "us-east-1"
}

variable "zip_path" {
  type = string
}
