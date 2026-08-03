output "function_name" {
  value = aws_lambda_function.reporter.function_name
}

output "function_arn" {
  value = aws_lambda_function.reporter.arn
}

output "dashboard_url" {
  value = "http://${aws_s3_bucket.dashboard.bucket}.s3-website-us-east-1.amazonaws.com/"
}
