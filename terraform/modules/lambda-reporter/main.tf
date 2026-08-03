# Dashboard bucket: S3 static website hosting with a public-read bucket
# policy only, per the design constraint. No CloudFront, no ACLs.

resource "aws_s3_bucket" "dashboard" {
  bucket        = "${var.prefix}-dashboard-${var.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_website_configuration" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id
  index_document {
    suffix = "index.html"
  }
}

resource "aws_s3_bucket_public_access_block" "dashboard" {
  bucket                  = aws_s3_bucket.dashboard.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadDashboard"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.dashboard.arn}/*"
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.dashboard]
}

resource "aws_lambda_function" "reporter" {
  function_name    = "${var.prefix}-reporter"
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
      INVENTORY_TABLE  = var.table_name
      DASHBOARD_BUCKET = aws_s3_bucket.dashboard.bucket
    }
  }
}

resource "aws_cloudwatch_log_group" "reporter" {
  name              = "/aws/lambda/${var.prefix}-reporter"
  retention_in_days = 14
}
