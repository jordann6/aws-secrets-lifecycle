locals {
  lambda_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  # Explicit deny on secret material. Attached to every role in this stack.
  # kms:Decrypt is denied only via Secrets Manager and SSM so Lambda can
  # still decrypt its own environment variables at cold start.
  deny_secret_material = {
    Sid    = "DenySecretMaterial"
    Effect = "Deny"
    Action = [
      "secretsmanager:GetSecretValue",
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath"
    ]
    Resource = "*"
  }

  deny_secret_kms = {
    Sid      = "DenySecretKmsDecrypt"
    Effect   = "Deny"
    Action   = "kms:Decrypt"
    Resource = "*"
    Condition = {
      StringEquals = {
        "kms:ViaService" = [
          "secretsmanager.${var.region}.amazonaws.com",
          "ssm.${var.region}.amazonaws.com"
        ]
      }
    }
  }

  logs_statement = {
    Sid    = "Logs"
    Effect = "Allow"
    Action = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    Resource = "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/${var.prefix}-*"
  }
}

# ---------- scanner ----------

resource "aws_iam_role" "scanner" {
  name               = "${var.prefix}-scanner-role"
  assume_role_policy = local.lambda_trust
}

resource "aws_iam_role_policy" "scanner" {
  name = "${var.prefix}-scanner-policy"
  role = aws_iam_role.scanner.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecretsMetadata"
        Effect = "Allow"
        Action = [
          "secretsmanager:ListSecrets",
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetResourcePolicy",
          "secretsmanager:ListSecretVersionIds"
        ]
        Resource = "*"
      },
      {
        Sid    = "SsmMetadata"
        Effect = "Allow"
        Action = [
          "ssm:DescribeParameters",
          "ssm:ListTagsForResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "IamKeyMetadata"
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed"
        ]
        Resource = "*"
      },
      {
        Sid    = "InventoryWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:BatchWriteItem"
        ]
        Resource = "arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.prefix}-*"
      },
      {
        Sid      = "AssumeScanTargets"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::*:role/${var.prefix}-scan-target-role"
      },
      {
        Sid      = "ChainAnalyzer"
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.prefix}-analyzer"
      },
      local.logs_statement,
      local.deny_secret_material,
      local.deny_secret_kms
    ]
  })
}

# ---------- scan target (assumed by the scanner, one per account) ----------

resource "aws_iam_role" "scan_target" {
  name = "${var.prefix}-scan-target-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.scanner.arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "scan_target" {
  name = "${var.prefix}-scan-target-policy"
  role = aws_iam_role.scan_target.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecretsMetadata"
        Effect = "Allow"
        Action = [
          "secretsmanager:ListSecrets",
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetResourcePolicy",
          "secretsmanager:ListSecretVersionIds"
        ]
        Resource = "*"
      },
      {
        Sid    = "SsmMetadata"
        Effect = "Allow"
        Action = [
          "ssm:DescribeParameters",
          "ssm:ListTagsForResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "IamKeyMetadata"
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed"
        ]
        Resource = "*"
      },
      local.deny_secret_material,
      local.deny_secret_kms
    ]
  })
}

# ---------- analyzer ----------

resource "aws_iam_role" "analyzer" {
  name               = "${var.prefix}-analyzer-role"
  assume_role_policy = local.lambda_trust
}

resource "aws_iam_role_policy" "analyzer" {
  name = "${var.prefix}-analyzer-policy"
  role = aws_iam_role.analyzer.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InventoryReadWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:BatchWriteItem"
        ]
        Resource = "arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.prefix}-*"
      },
      {
        Sid    = "AthenaQuery"
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution",
          "athena:GetWorkGroup"
        ]
        Resource = "arn:aws:athena:${var.region}:${var.account_id}:workgroup/${var.prefix}-*"
      },
      {
        Sid    = "GlueCatalog"
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetPartitions",
          "glue:CreateTable"
        ]
        Resource = [
          "arn:aws:glue:${var.region}:${var.account_id}:catalog",
          "arn:aws:glue:${var.region}:${var.account_id}:database/${var.prefix}*",
          "arn:aws:glue:${var.region}:${var.account_id}:table/${var.prefix}*/*"
        ]
      },
      {
        Sid    = "TrailAndResultsBuckets"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetBucketLocation",
          "s3:ListBucket",
          "s3:PutObject"
        ]
        Resource = [
          "arn:aws:s3:::${var.prefix}-*",
          "arn:aws:s3:::${var.prefix}-*/*"
        ]
      },
      {
        Sid    = "PrincipalResolution"
        Effect = "Allow"
        Action = [
          "iam:GetRole",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GetRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:ListRolePolicies",
          "iam:ListEntitiesForPolicy"
        ]
        Resource = "*"
      },
      {
        Sid      = "SecretResourcePolicies"
        Effect   = "Allow"
        Action   = "secretsmanager:GetResourcePolicy"
        Resource = "*"
      },
      {
        Sid      = "BedrockRunbooks"
        Effect   = "Allow"
        Action   = "bedrock:InvokeModel"
        Resource = "arn:aws:bedrock:${var.region}::foundation-model/anthropic.claude-opus-5"
      },
      {
        Sid      = "BedrockMantleRunbooks"
        Effect   = "Allow"
        Action   = "bedrock-mantle:CreateInference"
        Resource = "arn:aws:bedrock-mantle:${var.region}:${var.account_id}:project/default"
      },
      {
        Sid      = "SecurityHubImport"
        Effect   = "Allow"
        Action   = "securityhub:BatchImportFindings"
        Resource = "arn:aws:securityhub:${var.region}:${var.account_id}:product/${var.account_id}/default"
      },
      {
        Sid      = "ChainReporter"
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.prefix}-reporter"
      },
      local.logs_statement,
      local.deny_secret_material,
      local.deny_secret_kms
    ]
  })
}

# ---------- reporter ----------

resource "aws_iam_role" "reporter" {
  name               = "${var.prefix}-reporter-role"
  assume_role_policy = local.lambda_trust
}

resource "aws_iam_role_policy" "reporter" {
  name = "${var.prefix}-reporter-policy"
  role = aws_iam_role.reporter.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InventoryRead"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = "arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.prefix}-*"
      },
      {
        Sid    = "DashboardWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.prefix}-dashboard-*",
          "arn:aws:s3:::${var.prefix}-dashboard-*/*"
        ]
      },
      local.logs_statement,
      local.deny_secret_material,
      local.deny_secret_kms
    ]
  })
}
