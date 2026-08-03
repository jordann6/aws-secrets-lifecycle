# ---------- CloudTrail trail + log bucket ----------

resource "aws_s3_bucket" "trail" {
  bucket        = "${var.prefix}-trail-${var.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = var.lookback_days + 7
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.region}:${var.account_id}:trail/${var.prefix}-trail"
          }
        }
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${var.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.region}:${var.account_id}:trail/${var.prefix}-trail"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "${var.prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.trail]
}

# ---------- Athena ----------

resource "aws_s3_bucket" "athena_results" {
  bucket        = "${var.prefix}-athena-results-${var.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket                  = aws_s3_bucket.athena_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule {
    id     = "expire-results"
    status = "Enabled"
    filter {}
    expiration {
      days = 7
    }
  }
}

resource "aws_athena_workgroup" "main" {
  name          = "${var.prefix}-wg"
  force_destroy = true

  configuration {
    enforce_workgroup_configuration = true
    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/results/"
    }
  }
}

resource "aws_glue_catalog_database" "cloudtrail" {
  name = "${var.prefix}_cloudtrail"
}

# ---------- analyzer Lambda ----------

resource "aws_lambda_function" "analyzer" {
  function_name    = "${var.prefix}-analyzer"
  role             = var.role_arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  architectures    = ["arm64"]
  filename         = var.zip_path
  source_code_hash = filebase64sha256(var.zip_path)
  timeout          = 900
  memory_size      = 512

  environment {
    variables = {
      INVENTORY_TABLE     = var.table_name
      ATHENA_DATABASE     = aws_glue_catalog_database.cloudtrail.name
      ATHENA_WORKGROUP    = aws_athena_workgroup.main.name
      TRAIL_BUCKET        = aws_s3_bucket.trail.bucket
      LOOKBACK_DAYS       = tostring(var.lookback_days)
      BEDROCK_MODEL_ID    = var.bedrock_model_id
      EVIDENCE_BUCKET     = var.evidence_bucket
      SECURITYHUB_ENABLED = tostring(var.securityhub_enabled)
    }
  }
}

resource "aws_cloudwatch_log_group" "analyzer" {
  name              = "/aws/lambda/${var.prefix}-analyzer"
  retention_in_days = 14
}
