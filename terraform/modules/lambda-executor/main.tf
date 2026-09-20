# ---------- rotation executor Lambda ----------
#
# The one component in this stack that is allowed to read and write secret
# values. It is deliberately a separate function with a separate role (see
# the iam module) so the read-only governance pipeline keeps its explicit
# deny on secret material. Nothing here runs unless the approval guardrails
# in approval.py pass.

resource "aws_lambda_function" "executor" {
  function_name    = "${var.prefix}-executor"
  role             = var.role_arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  architectures    = ["arm64"]
  filename         = var.zip_path
  source_code_hash = filebase64sha256(var.zip_path)
  timeout          = 120
  memory_size      = 256

  environment {
    variables = {
      INVENTORY_TABLE       = var.table_name
      EXECUTOR_FUNCTION_ARN = "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.prefix}-executor"
      ROTATION_DAYS         = tostring(var.rotation_days)
    }
  }
}

resource "aws_cloudwatch_log_group" "executor" {
  name              = "/aws/lambda/${var.prefix}-executor"
  retention_in_days = 14
}

# Lets Secrets Manager invoke the executor for the four-step rotation
# contract once RotateSecret points a secret at it.
resource "aws_lambda_permission" "secretsmanager" {
  statement_id   = "AllowSecretsManagerInvoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.executor.function_name
  principal      = "secretsmanager.amazonaws.com"
  source_account = var.account_id
}
