# Scheduled pipeline: EventBridge fires the scanner asynchronously,
# then Lambda on-success destinations chain scanner -> analyzer ->
# reporter, passing scan_id through each response payload.

resource "aws_cloudwatch_event_rule" "scan_schedule" {
  name                = "${var.prefix}-scan-schedule"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "scanner" {
  rule = aws_cloudwatch_event_rule.scan_schedule.name
  arn  = var.scanner_function_arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.scanner_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scan_schedule.arn
}

resource "aws_lambda_function_event_invoke_config" "scanner_chain" {
  function_name          = var.scanner_function_name
  maximum_retry_attempts = 1

  destination_config {
    on_success {
      destination = var.analyzer_function_arn
    }
  }
}

resource "aws_lambda_function_event_invoke_config" "analyzer_chain" {
  function_name          = var.analyzer_function_name
  maximum_retry_attempts = 0

  destination_config {
    on_success {
      destination = var.reporter_function_arn
    }
  }
}
