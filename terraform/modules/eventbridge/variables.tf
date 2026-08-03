variable "prefix" {
  type = string
}

variable "scanner_function_name" {
  type = string
}

variable "scanner_function_arn" {
  type = string
}

variable "analyzer_function_name" {
  type = string
}

variable "analyzer_function_arn" {
  type = string
}

variable "reporter_function_arn" {
  type = string
}

variable "schedule_expression" {
  type    = string
  default = "rate(1 day)"
}
