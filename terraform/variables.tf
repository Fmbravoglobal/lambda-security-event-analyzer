variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name prefix"
  type        = string
  default     = "lambda-security-event-analyzer"
}

variable "source_bucket_name" {
  description = "S3 bucket name for monitored uploads"
  type        = string
  default     = "lambda-security-event-analyzer-source-demo-2026"
}

variable "quarantine_bucket_name" {
  description = "S3 bucket name for quarantined risky uploads"
  type        = string
  default     = "lambda-security-event-analyzer-quarantine-demo-2026"
}

variable "alert_email" {
  description = "Email address for SNS security alerts"
  type        = string
  default     = "oluwafemiokunlola308@gmail.com"
}