import boto3  # type: ignore
import pytest  # type: ignore
from unittest.mock import patch, MagicMock
import importlib.util
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)

# Dynamically import the over-provisioned memory check
file_path = (
    Path(__file__).resolve().parent.parent
    / "library"
    / "aws"
    / "checks"
    / "lambda"
    / "check_lambda_over_provisioned_memory.py"
)
spec = importlib.util.spec_from_file_location(
    "check_lambda_over_provisioned_memory", str(file_path)
)
module = importlib.util.module_from_spec(spec)  # type: ignore
sys.modules["check_lambda_over_provisioned_memory"] = module
spec.loader.exec_module(module)  # type: ignore

check_lambda_over_provisioned_memory = module.check_lambda_over_provisioned_memory

# Metadata Fixture
metadata = CheckMetadata(
    Provider="AWS",
    CheckID="lambda_over_provisioned_memory",
    CheckTitle="Over-Provisioned Lambda Memory Check",
    CheckType=["Cost"],
    ServiceName="Lambda",
    SubServiceName="Configuration",
    ResourceIdTemplate="{function_name}",
    Severity="Low",
    ResourceType="AWS::Lambda::Function",
    Risk="Over-provisioned memory increases cost without performance benefit.",
    Remediation=Remediation(
        Code=RemediationCode(
            NativeIaC="",
            Terraform="""resource "aws_lambda_function" "example" {
  function_name = "example"
  memory_size   = 512
}""",
        ),
        Recommendation=RemediationRecommendation(
            Text="Review memory allocation for Lambda functions and reduce over-provisioned memory.",
            Url="https://docs.aws.amazon.com/lambda/latest/dg/configuration-memory.html",
        ),
    ),
    Description="Checks whether any Lambda functions are using significantly more memory than required.",
)


@pytest.fixture
def mock_boto_session():
    return boto3.Session(region_name="us-east-1")


@patch("boto3.Session.client")
def test_over_provisioned_and_properly_sized_lambda(mock_client, mock_boto_session):
    mock_lambda = MagicMock()
    mock_cloudwatch = MagicMock()

    # Stub boto3 client switching
    mock_client.side_effect = lambda service: {
        "lambda": mock_lambda,
        "cloudwatch": mock_cloudwatch,
    }[service]

    # Lambda functions
    mock_lambda.get_paginator.return_value.paginate.return_value = [
        {
            "Functions": [
                {"FunctionName": "over-provisioned", "MemorySize": 1024},
                {"FunctionName": "well-sized", "MemorySize": 1024},
            ]
        }
    ]

    now = datetime.now(timezone.utc)

    # CloudWatch metrics
    mock_cloudwatch.get_metric_statistics.side_effect = [
        {
            "Datapoints": [{"Maximum": 300.0, "Timestamp": now}],
            "Label": "MaxMemoryUsed",
        },
        {
            "Datapoints": [{"Maximum": 800.0, "Timestamp": now}],
            "Label": "MaxMemoryUsed",
        },
    ]

    check = check_lambda_over_provisioned_memory(metadata)
    report = check.execute(mock_boto_session)

    assert len(report.resource_ids_status) == 2

    over = next(
        r for r in report.resource_ids_status if r.resource.name == "over-provisioned"
    )
    assert over.status == CheckStatus.FAILED
    assert "Used: 300MB" in over.summary

    good = next(
        r for r in report.resource_ids_status if r.resource.name == "well-sized"
    )
    assert good.status == CheckStatus.PASSED
    assert "Used: 800MB" in good.summary


@patch("boto3.Session.client")
def test_no_lambda_functions(mock_client, mock_boto_session):
    mock_lambda = MagicMock()
    mock_cloudwatch = MagicMock()

    mock_client.side_effect = lambda service: {
        "lambda": mock_lambda,
        "cloudwatch": mock_cloudwatch,
    }[service]

    mock_lambda.get_paginator.return_value.paginate.return_value = [{"Functions": []}]

    check = check_lambda_over_provisioned_memory(metadata)
    report = check.execute(mock_boto_session)

    assert report.status is None
    assert len(report.resource_ids_status) == 0
