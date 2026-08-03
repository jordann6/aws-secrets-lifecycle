resource "aws_lambda_function" "scanner" {
  function_name    = "${var.prefix}-scanner"
  role             = var.role_arn
  runtime          = "provided.al2023"
  handler          = "bootstrap"
  architectures    = ["arm64"]
  filename         = var.zip_path
  source_code_hash = filebase64sha256(var.zip_path)
  timeout          = 300
  memory_size      = 256

  environment {
    variables = {
      INVENTORY_TABLE       = var.table_name
      SCAN_REGIONS          = var.scan_regions
      SCAN_TARGET_ROLE_ARNS = var.scan_target_role_arns
    }
  }
}

resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/lambda/${var.prefix}-scanner"
  retention_in_days = 14
}
