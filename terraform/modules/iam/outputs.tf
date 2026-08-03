output "scanner_role_arn" {
  value = aws_iam_role.scanner.arn
}

output "scan_target_role_arn" {
  value = aws_iam_role.scan_target.arn
}

output "analyzer_role_arn" {
  value = aws_iam_role.analyzer.arn
}

output "reporter_role_arn" {
  value = aws_iam_role.reporter.arn
}
