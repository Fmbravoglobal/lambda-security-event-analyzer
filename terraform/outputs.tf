output "lambda_function_name" {
  value = aws_lambda_function.security_analyzer.function_name
}

output "lambda_function_arn" {
  value = aws_lambda_function.security_analyzer.arn
}

output "source_bucket_name" {
  value = aws_s3_bucket.source_bucket.bucket
}

output "quarantine_bucket_name" {
  value = aws_s3_bucket.quarantine_bucket.bucket
}

output "sns_topic_arn" {
  value = aws_sns_topic.security_alerts.arn
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.security_findings.name
}

output "eventbridge_rule_name" {
  value = aws_cloudwatch_event_rule.iam_activity_rule.name
}