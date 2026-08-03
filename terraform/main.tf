data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  prefix     = var.prefix
}

module "dynamodb" {
  source = "./modules/dynamodb"
  prefix = local.prefix
}

module "iam" {
  source     = "./modules/iam"
  prefix     = local.prefix
  account_id = local.account_id
  region     = var.aws_region
}

module "s3_evidence" {
  source            = "./modules/s3-evidence"
  prefix            = local.prefix
  account_id        = local.account_id
  analyzer_role_arn = module.iam.analyzer_role_arn
  retention_days    = var.evidence_retention_days
}

module "securityhub" {
  source = "./modules/securityhub"
}

module "lambda_analyzer" {
  source              = "./modules/lambda-analyzer"
  prefix              = local.prefix
  account_id          = local.account_id
  region              = var.aws_region
  role_arn            = module.iam.analyzer_role_arn
  table_name          = module.dynamodb.table_name
  bedrock_model_id    = var.bedrock_model_id
  lookback_days       = var.cloudtrail_lookback_days
  zip_path            = "${path.root}/../analyzer/build/analyzer.zip"
  evidence_bucket     = module.s3_evidence.bucket_name
  securityhub_enabled = true

  depends_on = [module.securityhub]
}

module "eventbridge" {
  source                 = "./modules/eventbridge"
  prefix                 = local.prefix
  scanner_function_name  = module.lambda_scanner.function_name
  scanner_function_arn   = module.lambda_scanner.function_arn
  analyzer_function_name = module.lambda_analyzer.function_name
  analyzer_function_arn  = module.lambda_analyzer.function_arn
  reporter_function_arn  = module.lambda_reporter.function_arn
}

module "lambda_reporter" {
  source     = "./modules/lambda-reporter"
  prefix     = local.prefix
  account_id = local.account_id
  role_arn   = module.iam.reporter_role_arn
  table_name = module.dynamodb.table_name
  zip_path   = "${path.root}/../reporter/build/reporter.zip"
}

module "lambda_scanner" {
  source     = "./modules/lambda-scanner"
  prefix     = local.prefix
  role_arn   = module.iam.scanner_role_arn
  table_name = module.dynamodb.table_name
  zip_path   = "${path.root}/../scanner/build/scanner.zip"
}
