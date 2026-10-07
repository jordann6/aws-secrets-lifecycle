# The scanner emits two low-cardinality EMF metrics after a complete scan. A
# missing scan is alarmed separately, so an AccessDenied cannot look healthy.
resource "aws_kms_key" "secret_alerts" {
  description             = "Secret-age and missed-scan alert encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "KeyAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchNotifications"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:aws:sns:topicArn" = "arn:aws:sns:${var.aws_region}:${local.account_id}:${var.prefix}-secret-alerts"
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic" "secret_alerts" {
  name              = "${var.prefix}-secret-alerts"
  kms_master_key_id = aws_kms_key.secret_alerts.arn
}

resource "aws_sns_topic_policy" "secret_alerts" {
  arn = aws_sns_topic.secret_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.secret_alerts.arn
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:cloudwatch:${var.aws_region}:${local.account_id}:alarm:${var.prefix}-secret-*" }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "secret_email" {
  count     = var.secret_alert_email == null ? 0 : 1
  topic_arn = aws_sns_topic.secret_alerts.arn
  protocol  = "email"
  endpoint  = var.secret_alert_email
}

resource "aws_cloudwatch_metric_alarm" "secret_age" {
  alarm_name          = "${var.prefix}-secret-age"
  alarm_description   = "A current credential exceeds ${var.secret_max_age_days} days, or current version metadata is absent or invalid"
  namespace           = "SecOps/Secrets"
  metric_name         = "SecretsNeedingAttention"
  dimensions          = { Scanner = module.lambda_scanner.function_name }
  statistic           = "Maximum"
  period              = 86400
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.secret_alerts.arn]
  ok_actions          = [aws_sns_topic.secret_alerts.arn]
  depends_on          = [aws_sns_topic_policy.secret_alerts]
}

resource "aws_cloudwatch_metric_alarm" "secret_scan_missing" {
  alarm_name          = "${var.prefix}-secret-scan-missing"
  alarm_description   = "No complete secret scan in two daily periods"
  namespace           = "SecOps/Secrets"
  metric_name         = "ScanCompleted"
  dimensions          = { Scanner = module.lambda_scanner.function_name }
  statistic           = "Sum"
  period              = 86400
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.secret_alerts.arn]
  ok_actions          = [aws_sns_topic.secret_alerts.arn]
  depends_on          = [aws_sns_topic_policy.secret_alerts]
}
