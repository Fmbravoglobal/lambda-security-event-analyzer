"""
Unit tests for AWS Lambda Security Event Analyzer.
Covers S3 classification, IAM event classification, and handler routing.
"""

import json
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.modules["boto3"] = MagicMock()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lambda_function.app import (
    get_file_extension,
    classify_s3_upload,
    classify_iam_event,
    build_finding_record,
    process_s3_event,
    process_eventbridge_event,
    lambda_handler,
    RISKY_EXTENSIONS,
    RISKY_IAM_ACTIONS,
)


class TestGetFileExtension(unittest.TestCase):

    def test_simple_extension(self):
        self.assertEqual(get_file_extension("malware.exe"), ".exe")

    def test_no_extension_returns_empty(self):
        self.assertEqual(get_file_extension("Makefile"), "")

    def test_uppercase_normalized(self):
        self.assertEqual(get_file_extension("VIRUS.EXE"), ".exe")

    def test_multiple_dots_returns_last(self):
        self.assertEqual(get_file_extension("archive.tar.gz"), ".gz")

    def test_dotfile(self):
        self.assertEqual(get_file_extension(".bashrc"), ".bashrc")


class TestClassifyS3Upload(unittest.TestCase):

    def test_risky_extension_returns_high(self):
        finding = classify_s3_upload("my-bucket", "payload.exe", 1024)
        self.assertEqual(finding["risk_level"], "HIGH")
        self.assertIn(".exe", finding["reason"])

    def test_bat_file_is_high_risk(self):
        finding = classify_s3_upload("bucket", "script.bat", 512)
        self.assertEqual(finding["risk_level"], "HIGH")

    def test_large_file_returns_medium(self):
        finding = classify_s3_upload("bucket", "data.csv", 60_000_000)
        self.assertEqual(finding["risk_level"], "MEDIUM")
        self.assertIn("large", finding["reason"])

    def test_normal_file_returns_low(self):
        finding = classify_s3_upload("bucket", "report.pdf", 2048)
        self.assertEqual(finding["risk_level"], "LOW")

    def test_all_risky_extensions_flagged(self):
        for ext in RISKY_EXTENSIONS:
            finding = classify_s3_upload("bucket", f"file{ext}", 100)
            self.assertEqual(finding["risk_level"], "HIGH", f"Expected HIGH for {ext}")

    def test_finding_contains_expected_fields(self):
        finding = classify_s3_upload("bucket", "test.txt", 100)
        for field in ["resource_type", "resource_id", "bucket_name", "object_key", "risk_level", "reason"]:
            self.assertIn(field, finding)

    def test_resource_id_format(self):
        finding = classify_s3_upload("my-bucket", "path/file.txt", 100)
        self.assertEqual(finding["resource_id"], "my-bucket/path/file.txt")


class TestClassifyIAMEvent(unittest.TestCase):

    def test_risky_iam_action_returns_high(self):
        for action in RISKY_IAM_ACTIONS:
            detail = {
                "eventName": action,
                "sourceIPAddress": "1.2.3.4",
                "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/test"},
            }
            finding = classify_iam_event(detail)
            self.assertEqual(finding["risk_level"], "HIGH", f"Expected HIGH for {action}")

    def test_console_login_returns_medium(self):
        detail = {
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "5.6.7.8",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/dev"},
        }
        finding = classify_iam_event(detail)
        self.assertEqual(finding["risk_level"], "MEDIUM")

    def test_access_key_event_medium(self):
        detail = {
            "eventName": "GetAccessKeyLastUsed",
            "sourceIPAddress": "1.1.1.1",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/dev"},
        }
        finding = classify_iam_event(detail)
        self.assertEqual(finding["risk_level"], "MEDIUM")

    def test_normal_iam_event_low(self):
        detail = {
            "eventName": "ListBuckets",
            "sourceIPAddress": "10.0.0.1",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/dev"},
        }
        finding = classify_iam_event(detail)
        self.assertEqual(finding["risk_level"], "LOW")

    def test_finding_includes_principal(self):
        detail = {
            "eventName": "ListBuckets",
            "sourceIPAddress": "10.0.0.1",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/alice"},
        }
        finding = classify_iam_event(detail)
        self.assertEqual(finding["principal"], "arn:aws:iam::123:user/alice")

    def test_missing_fields_handled(self):
        finding = classify_iam_event({})
        self.assertIn("risk_level", finding)
        self.assertIn("event_name", finding)


class TestBuildFindingRecord(unittest.TestCase):

    def test_adds_finding_id_and_timestamp(self):
        base = {"resource_type": "S3Object", "resource_id": "bucket/key", "risk_level": "LOW", "reason": "ok"}
        record = build_finding_record(base)
        self.assertIn("finding_id", record)
        self.assertIn("detected_at", record)

    def test_original_fields_preserved(self):
        base = {"resource_type": "IAMEvent", "resource_id": "arn:x", "risk_level": "HIGH", "reason": "bad"}
        record = build_finding_record(base)
        self.assertEqual(record["risk_level"], "HIGH")


class TestLambdaHandler(unittest.TestCase):

    def setUp(self):
        import lambda_function.app as app_module
        app_module.SNS_TOPIC_ARN = ""
        app_module.FINDINGS_TABLE = ""
        app_module.QUARANTINE_BUCKET = ""
        app_module.ENABLE_REMEDIATION = False

    def test_s3_event_processed(self):
        event = {
            "Records": [{
                "eventName": "ObjectCreated:Put",
                "s3": {
                    "bucket": {"name": "my-bucket"},
                    "object": {"key": "upload.exe", "size": 1024},
                },
            }]
        }
        result = lambda_handler(event, {})
        self.assertEqual(result["statusCode"], 200)
        body = json.loads(result["body"])
        self.assertGreater(body["total_findings"], 0)

    def test_eventbridge_iam_event_processed(self):
        event = {
            "source": "aws.iam",
            "detail-type": "AWS API Call via CloudTrail",
            "detail": {
                "eventName": "DeleteUser",
                "sourceIPAddress": "1.2.3.4",
                "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/attacker"},
            },
        }
        result = lambda_handler(event, {})
        self.assertEqual(result["statusCode"], 200)
        body = json.loads(result["body"])
        self.assertGreater(body["total_findings"], 0)

    def test_empty_event_returns_200(self):
        result = lambda_handler({}, {})
        self.assertEqual(result["statusCode"], 200)


if __name__ == "__main__":
    unittest.main()
