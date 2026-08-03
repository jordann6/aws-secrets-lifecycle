output "table_name" {
  value = aws_dynamodb_table.inventory.name
}

output "table_arn" {
  value = aws_dynamodb_table.inventory.arn
}
