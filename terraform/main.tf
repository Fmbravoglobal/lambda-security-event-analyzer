terraform {
  required_version = ">= 1.4.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda_function/app.py"
  output_path = "${path.module}/lambda_function_payload.zip"
}

resource "aws_kms_key" "security" {
  description             = "KMS key for Lambda Security Event Analyzer resources"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "security" {
  name          = "alias/lambda-security-event-analyzer"
  target_key_id = aws_kms_key.security.key_id
}

resource "aws_vpc" "lambda_vpc" {
  cidr_block           = "10.50.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name    = "${var.project_name}-vpc"
    Project = var.project_name
  }
}

resource "aws_subnet" "private_a" {
  vpc_id                  = aws_vpc.lambda_vpc.id
  cidr_block              = "10.50.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = {
    Name    = "${var.project_name}-private-a"
    Project = var.project_name
  }
}

resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.lambda_vpc.id
  cidr_block              = "10.50.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = false

  tags = {
    Name    = "${var.project_name}-private-b"
    Project = var.project_name
  }
}

resource "aws_security_group" "lambda_sg" {
  name        = "${var.project_name}-lambda-sg"
  description = "Security group for Lambda function"
  vpc_id      = aws_vpc.lambda_vpc.id

  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-lambda-sg"
    Project = var.project_name
  }
}

resource "aws_sns_topic" "security_alerts" {
  name              = "${var.project_name}-alerts"
  kms_master_key_id = aws_kms_key.security.arn
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_dynamodb_table" "security_findings" {
  name         = "${var.project_name}-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.security.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name        = "${var.project_name}-findings"
    Environment = "Dev"
    Project     = var.project_name
  }
}

resource "aws_s3_bucket" "source_bucket" {
  bucket = var.source_bucket_name

  tags = {
    Name        = var.source_bucket_name
    Environment = "Dev"
    Project     = var.project_name
  }
}

resource "aws_s3_bucket_public_access_block" "source_bucket" {
  bucket                  = aws_s3_bucket.source_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "source_bucket" {
  bucket = aws_s3_bucket.source_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "source_bucket" {
  bucket = aws_s3_bucket.source_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.security.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket" "quarantine_bucket" {
  bucket = var.quarantine_bucket_name

  tags = {
    Name        = var.quarantine_bucket_name
    Environment = "Dev"
    Project     = var.project_name
  }
}

resource "aws_s3_bucket_public_access_block" "quarantine_bucket" {
  bucket                  = aws_s3_bucket.quarantine_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "quarantine_bucket" {
  bucket = aws_s3_bucket.quarantine_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "quarantine_bucket" {
  bucket = aws_s3_bucket.quarantine_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.security.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_iam_role" "lambda_exec_role" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_custom_policy" {
  name = "${var.project_name}-lambda-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSpecificLogWrites"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.lambda_logs.arn}:*"
      },
      {
        Sid    = "AllowPublishAlerts"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Sid    = "AllowWriteFindings"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem"
        ]
        Resource = aws_dynamodb_table.security_findings.arn
      },
      {
        Sid    = "AllowReadFromSourceBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.source_bucket.arn}/*"
      },
      {
        Sid    = "AllowDeleteFromSourceBucket"
        Effect = "Allow"
        Action = [
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.source_bucket.arn}/*"
      },
      {
        Sid    = "AllowWriteToQuarantineBucket"
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.quarantine_bucket.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_custom_policy_attach" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_custom_policy.arn
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.project_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.security.arn
}

resource "aws_signer_signing_profile" "lambda_signing_profile" {
  name_prefix = "${var.project_name}-signer-"
  platform_id = "AWSLambda-SHA384-ECDSA"
}

resource "aws_lambda_code_signing_config" "lambda_csc" {
  description = "Code signing config for Lambda Security Event Analyzer"

  allowed_publishers {
    signing_profile_version_arns = [
      aws_signer_signing_profile.lambda_signing_profile.version_arn
    ]
  }

  policies {
    untrusted_artifact_on_deployment = "Warn"
  }
}

resource "aws_lambda_function" "security_analyzer" {
  function_name = var.project_name
  role          = aws_iam_role.lambda_exec_role.arn
  handler       = "app.lambda_handler"
  runtime       = "python3.11"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  timeout     = 15
  memory_size = 256
  kms_key_arn = aws_kms_key.security.arn

  tracing_config {
    mode = "Active"
  }

  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  code_signing_config_arn = aws_lambda_code_signing_config.lambda_csc.arn

  environment {
    variables = {
      FUNCTION_NAME      = var.project_name
      SNS_TOPIC_ARN      = aws_sns_topic.security_alerts.arn
      FINDINGS_TABLE     = aws_dynamodb_table.security_findings.name
      QUARANTINE_BUCKET  = aws_s3_bucket.quarantine_bucket.bucket
      ENABLE_REMEDIATION = "true"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role_policy_attachment.lambda_custom_policy_attach
  ]
}

resource "aws_lambda_permission" "allow_s3_invoke" {
  statement_id  = "AllowExecutionFromS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_analyzer.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.source_bucket.arn
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.source_bucket.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.security_analyzer.arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.allow_s3_invoke]
}

resource "aws_cloudwatch_event_rule" "iam_activity_rule" {
  name        = "${var.project_name}-iam-events"
  description = "Captures IAM API activity via EventBridge"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.iam_activity_rule.name
  target_id = "LambdaSecurityAnalyzer"
  arn       = aws_lambda_function.security_analyzer.arn
}

resource "aws_lambda_permission" "allow_eventbridge_invoke" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_analyzer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_activity_rule.arn
}