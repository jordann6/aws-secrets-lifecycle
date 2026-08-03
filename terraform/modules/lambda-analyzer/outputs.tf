output "function_name" {
  value = aws_lambda_function.analyzer.function_name
}

output "function_arn" {
  value = aws_lambda_function.analyzer.arn
}

output "trail_bucket" {
  value = aws_s3_bucket.trail.bucket
}
