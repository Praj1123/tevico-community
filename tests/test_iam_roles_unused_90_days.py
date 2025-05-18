from unittest.mock import MagicMock
from boto3 import Session  # type: ignore
from datetime import datetime, timezone
import pytest  # type: ignore

from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)
from library.aws.checks.iam.iam_roles_unused_90_days import iam_roles_unused_90_days


def test_iam_roles_unused_90_days():
    session = MagicMock(spec=Session)

    mock_iam_client = MagicMock()
    mock_iam_client.generate_credential_report.return_value = {}

    csv_content = (
        "user,arn,password_last_used,access_key_1_last_used_date,access_key_2_last_used_date\n"
        "test-role,arn:aws:iam::123456789012:role/test-role,2025-04-18T00:00:00+00:00,N/A,N/A\n"
        "unused-role,arn:aws:iam::123456789012:role/unused-role,N/A,N/A,N/A\n"
        "old-role,arn:aws:iam::123456789012:role/old-role,2025-02-06T00:00:00+00:00,N/A,N/A\n"
    )
    mock_iam_client.get_credential_report.return_value = {
        "Content": csv_content.encode("utf-8")
    }

    session.client.return_value = mock_iam_client

    metadata = CheckMetadata(
        Provider="AWS",
        CheckID="iam_roles_not_used_90_days",
        CheckTitle="Ensure IAM Roles Are Not Unused for 90 Days",
        CheckType=["Security", "Governance"],
        ServiceName="iam",
        SubServiceName="",
        ResourceIdTemplate="arn:aws:iam::{account_id}:role/{role_name}",
        Severity="medium",
        ResourceType="AwsIamRole",
        Description="Checks if IAM roles have not been used in the last 90 days.",
        Risk="Unused IAM roles may present a security risk if not reviewed and removed.",
        Remediation=Remediation(
            Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
            Recommendation=RemediationRecommendation(
                Text="Review and delete IAM roles that have not been used in over 90 days.",
                Url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_delete.html",
            ),
        ),
    )

    check = iam_roles_unused_90_days(metadata)
    report = check.execute(session)

    failed = [r for r in report.resource_ids_status if r.status == CheckStatus.FAILED]
    passed = [r for r in report.resource_ids_status if r.status == CheckStatus.PASSED]

    assert len(failed) == 2
    failed_names = [r.resource.name for r in failed]
    assert "unused-role" in failed_names
    assert "old-role" in failed_names

    assert len(passed) == 1
    assert passed[0].resource.name == "test-role"


def test_no_roles():
    session = MagicMock(spec=Session)
    mock_iam_client = MagicMock()
    mock_iam_client.generate_credential_report.return_value = {}

    # Empty credential report CSV with only headers
    csv_content = "user,arn,password_last_used,access_key_1_last_used_date,access_key_2_last_used_date\n"
    mock_iam_client.get_credential_report.return_value = {
        "Content": csv_content.encode("utf-8")
    }

    session.client.return_value = mock_iam_client

    metadata = CheckMetadata(
        Provider="AWS",
        CheckID="iam_roles_not_used_90_days",
        CheckTitle="Ensure IAM Roles Are Not Unused for 90 Days",
        CheckType=["Security", "Governance"],
        ServiceName="iam",
        SubServiceName="",
        ResourceIdTemplate="arn:aws:iam::{account_id}:role/{role_name}",
        Severity="medium",
        ResourceType="AwsIamRole",
        Description="Checks if IAM roles have not been used in the last 90 days.",
        Risk="Unused IAM roles may present a security risk if not reviewed and removed.",
        Remediation=Remediation(
            Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
            Recommendation=RemediationRecommendation(
                Text="Review and delete IAM roles that have not been used in over 90 days.",
                Url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_delete.html",
            ),
        ),
    )

    check = iam_roles_unused_90_days(metadata)
    report = check.execute(session)

    assert report.status == CheckStatus.UNKNOWN
    assert "Credential report is empty or invalid" in report.resource_ids_status[0].summary   # type: ignore
