![Lambda Security Pipeline](https://github.com/Fmbravoglobal/lambda-security-event-analyzer/actions/workflows/security-pipeline.yml/badge.svg)

# AWS Lambda Security Event Analyzer

## Overview

This project demonstrates a **serverless cloud security automation solution** using **AWS Lambda, Amazon S3, DynamoDB, SNS, EventBridge, Terraform, and GitHub Actions**.

It is designed to analyze cloud events, classify them as normal, suspicious, or high-risk, store findings, trigger alerts, and perform basic automated remediation.

---

## Core Capabilities

- **S3 upload event monitoring**
- **SNS alerting for high-risk uploads**
- **DynamoDB storage for security findings**
- **EventBridge integration for IAM event monitoring**
- **IAM anomaly detection logic**
- **Automated remediation workflow** for risky file uploads
- **Terraform-based provisioning**
- **GitHub Actions CI/CD validation**
- **Checkov infrastructure security scanning**

---

## How It Works

### S3 Event Workflow
1. A file is uploaded to the S3 source bucket.
2. S3 triggers the Lambda function.
3. The Lambda function checks the file extension and size.
4. Medium- and high-risk findings are stored in DynamoDB.
5. Alerts are sent through SNS.
6. High-risk files are moved to the quarantine bucket.

### IAM Event Workflow
1. IAM activity is captured through EventBridge.
2. Lambda analyzes sensitive IAM API events.
3. High-risk activity is written to DynamoDB.
4. SNS notifications are sent for review.

---

## Technologies Used

- AWS Lambda
- Amazon S3
- Amazon SNS
- Amazon DynamoDB
- Amazon EventBridge
- AWS IAM
- AWS CloudWatch Logs
- Terraform
- GitHub Actions
- Checkov

---

## Repository Structure

```text
lambda-security-event-analyzer
│
├── lambda_function
│   └── app.py
│
├── terraform
│   ├── main.tf
│   ├── variables.tf
│   └── outputs.tf
│
├── .github
│   └── workflows
│       └── security-pipeline.yml
│
└── README.md