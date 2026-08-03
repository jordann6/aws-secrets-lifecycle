# Single-table design.
# pk = resource ARN, sk = record kind:
#   INVENTORY#<scan_id>  normalized scanner record
#   ANALYSIS#<scan_id>   consumer map + readiness score + runbook ref
# gsi1 (scan_id) lets the analyzer and reporter fetch a whole scan.

resource "aws_dynamodb_table" "inventory" {
  name         = "${var.prefix}-secret-inventory"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "scan_id"
    type = "S"
  }

  global_secondary_index {
    name            = "scan-index"
    hash_key        = "scan_id"
    range_key       = "pk"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = false
  }
}
