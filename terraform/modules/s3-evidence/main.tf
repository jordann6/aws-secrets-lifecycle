# Evidence bucket: versioned, Object Lock in governance mode so scan
# artifacts are tamper-evident for auditors. Retention is short for the
# demo; production would use months. Destroy requires a governance
# bypass sweep first, handled by the Makefile destroy target.

resource "aws_s3_bucket" "evidence" {
  bucket              = "${var.prefix}-evidence-${var.account_id}"
  object_lock_enabled = true
  force_destroy       = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AnalyzerWriteOnly"
        Effect    = "Allow"
        Principal = { AWS = var.analyzer_role_arn }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.evidence.arn}/evidence/*"
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.evidence.arn,
          "${aws_s3_bucket.evidence.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}
