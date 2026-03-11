import json
import os
import urllib.parse
from datetime import datetime, timezone

import boto3

RISKY_EXTENSIONS = {".exe", ".bat", ".cmd", ".sh", ".ps1", ".js", ".jar", ".msi"}
RISKY_IAM_ACTIONS = {
    "DeleteUser",
    "DeleteRole",
    "DeletePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "CreateAccessKey",
    "UpdateAssumeRolePolicy",
}

sns_client = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")
s3_client = boto3.client("s3")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE", "")
QUARANTINE_BUCKET = os.environ.get("QUARANTINE_BUCKET", "")
ENABLE_REMEDIATION = os.environ.get("ENABLE_REMEDIATION", "true").lower() == "true"


def get_file_extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return "." + filename.split(".")[-1].lower()


def publish_sns(subject: str, message: dict) -> None:
    if not SNS_TOPIC_ARN:
        return
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=json.dumps(message, indent=2, default=str),
    )


def store_finding(item: dict) -> None:
    if not FINDINGS_TABLE:
        return
    table = dynamodb.Table(FINDINGS_TABLE)
    table.put_item(Item=item)


def quarantine_object(source_bucket: str, object_key: str) -> dict:
    if not QUARANTINE_BUCKET:
        return {"remediation_status": "skipped", "reason": "No quarantine bucket configured."}

    copy_source = {"Bucket": source_bucket, "Key": object_key}
    s3_client.copy_object(
        Bucket=QUARANTINE_BUCKET,
        Key=object_key,
        CopySource=copy_source,
    )

    s3_client.delete_object(Bucket=source_bucket, Key=object_key)

    return {
        "remediation_status": "completed",
        "action": "moved_to_quarantine",
        "quarantine_bucket": QUARANTINE_BUCKET,
    }


def classify_s3_upload(bucket_name: str, key: str, size: int) -> dict:
    extension = get_file_extension(key)
    risk_level = "LOW"
    reason = "Normal upload pattern detected."
    remediation = {"remediation_status": "not_needed"}

    if extension in RISKY_EXTENSIONS:
        risk_level = "HIGH"
        reason = f"Uploaded object has risky extension: {extension}"

    elif size > 50_000_000:
        risk_level = "MEDIUM"
        reason = "Uploaded object is unusually large."

    finding = {
        "resource_type": "S3Object",
        "resource_id": f"{bucket_name}/{key}",
        "bucket_name": bucket_name,
        "object_key": key,
        "object_size": size,
        "extension": extension,
        "risk_level": risk_level,
        "reason": reason,
    }

    if risk_level == "HIGH" and ENABLE_REMEDIATION:
        remediation = quarantine_object(bucket_name, key)

    finding["remediation"] = remediation
    return finding


def classify_iam_event(event_detail: dict) -> dict:
    event_name = event_detail.get("eventName", "UnknownEvent")
    source_ip = event_detail.get("sourceIPAddress", "unknown")
    user_identity = event_detail.get("userIdentity", {})
    user_type = user_identity.get("type", "unknown")
    principal = user_identity.get("arn", "unknown")

    risk_level = "LOW"
    reason = "IAM activity appears normal."

    if event_name in RISKY_IAM_ACTIONS:
        risk_level = "HIGH"
        reason = f"High-risk IAM action detected: {event_name}"
    elif "ConsoleLogin" in event_name or "AccessKey" in event_name:
        risk_level = "MEDIUM"
        reason = f"Sensitive IAM-related event detected: {event_name}"

    return {
        "resource_type": "IAMEvent",
        "resource_id": principal,
        "event_name": event_name,
        "source_ip": source_ip,
        "user_type": user_type,
        "principal": principal,
        "risk_level": risk_level,
        "reason": reason,
        "remediation": {"remediation_status": "manual_review_recommended"},
    }


def build_finding_record(finding: dict) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    finding_id = f"{finding['resource_type']}#{finding['resource_id']}#{now}"

    return {
        "finding_id": finding_id,
        "detected_at": now,
        **finding,
    }


def process_s3_event(event: dict) -> list:
    findings = []
    for record in event.get("Records", []):
        event_name = record.get("eventName", "")
        s3_info = record.get("s3", {})
        bucket_name = s3_info.get("bucket", {}).get("name", "unknown-bucket")
        raw_key = s3_info.get("object", {}).get("key", "unknown-object")
        object_key = urllib.parse.unquote_plus(raw_key)
        object_size = s3_info.get("object", {}).get("size", 0)

        finding = classify_s3_upload(bucket_name, object_key, object_size)
        finding["event_name"] = event_name
        findings.append(build_finding_record(finding))
    return findings


def process_eventbridge_event(event: dict) -> list:
    findings = []
    detail = event.get("detail", {})
    source = event.get("source", "")
    detail_type = event.get("detail-type", "")

    if source == "aws.iam" or "CloudTrail" in detail_type:
        finding = classify_iam_event(detail)
        finding["event_source"] = source
        finding["detail_type"] = detail_type
        findings.append(build_finding_record(finding))

    return findings


def lambda_handler(event, context):
    print("Received event:")
    print(json.dumps(event, indent=2, default=str))

    findings = []

    if "Records" in event:
        findings.extend(process_s3_event(event))
    else:
        findings.extend(process_eventbridge_event(event))

    for finding in findings:
        store_finding(finding)

        if finding["risk_level"] in {"HIGH", "MEDIUM"}:
            publish_sns(
                subject=f"Security Finding: {finding['risk_level']}",
                message=finding,
            )

    response = {
        "message": "Security analysis completed successfully.",
        "function_name": os.environ.get("FUNCTION_NAME", "unknown"),
        "total_findings": len(findings),
        "findings": findings,
    }

    print("Analysis result:")
    print(json.dumps(response, indent=2, default=str))

    return {
        "statusCode": 200,
        "body": json.dumps(response, default=str),
    }