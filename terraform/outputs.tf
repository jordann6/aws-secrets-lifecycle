output "account_id" {
  value = local.account_id
}

output "region" {
  value = data.aws_region.current.name
}

output "dashboard_url" {
  value = module.lambda_reporter.dashboard_url
}

output "evidence_bucket" {
  value = module.s3_evidence.bucket_name
}
