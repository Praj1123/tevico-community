import boto3  # type: ignore
import pytest  # type: ignore
from unittest.mock import patch, MagicMock
from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)
from library.aws.checks.route53.route53_dnssec_signing_not_enabled import route53_dnssec_signing_not_enabled


@pytest.fixture
def mock_boto_session():
    return boto3.Session(region_name="us-east-1")


@patch("boto3.Session.client")
def test_dnssec_not_enabled(mock_client, mock_boto_session):
    mock_route53 = MagicMock()
    mock_client.return_value = mock_route53

    # Hosted zone with no DNSSEC signing
    mock_route53.list_hosted_zones.return_value = {
        "HostedZones": [
            {
                "Id": "/hostedzone/ZONE1",
                "Name": "example.com.",
                "Config": {"PrivateZone": False},
            }
        ]
    }

    mock_route53.get_dnssec.return_value = {
        "Status": {
            "ServeSignature": "DISABLED"
        }
    }

    metadata = CheckMetadata(
        Provider="AWS",
        CheckID="route53_dnssec_signing_not_enabled",
        CheckTitle="Check if DNSSEC signing is not enabled on Route53 hosted zones",
        CheckType=["Security"],
        ServiceName="route53",
        SubServiceName="dnssec",
        ResourceIdTemplate="arn:aws:route53:::hostedzone/{zone_id}",
        Severity="medium",
        ResourceType="AwsRoute53HostedZone",
        Risk="Lack of DNSSEC makes DNS data vulnerable to tampering.",
        Description="Checks if Route53 hosted zones have DNSSEC signing enabled.",
        Remediation=Remediation(
            Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
            Recommendation=RemediationRecommendation(
                Text="Enable DNSSEC for Route53 hosted zones.",
                Url="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html",
            ),
        ),
    )

    check = route53_dnssec_signing_not_enabled(metadata)
    report = check.execute(mock_boto_session)

    failed_findings = [r for r in report.resource_ids_status if r.status == CheckStatus.FAILED]

    assert len(failed_findings) == 1
    assert failed_findings[0].resource.name == "example.com."
    assert "DNSSEC is not enabled" in failed_findings[0].summary # type: ignore


@patch("boto3.Session.client")
def test_dnssec_enabled(mock_client, mock_boto_session):
    mock_route53 = MagicMock()
    mock_client.return_value = mock_route53

    # Hosted zone with DNSSEC signing enabled
    mock_route53.list_hosted_zones.return_value = {
        "HostedZones": [
            {
                "Id": "/hostedzone/ZONE1",
                "Name": "example.com.",
                "Config": {"PrivateZone": False},
            }
        ]
    }

    mock_route53.get_dnssec.return_value = {
        "Status": {
            "ServeSignature": "ENABLED"
        }
    }

    metadata = CheckMetadata(
        Provider="AWS",
        CheckID="route53_dnssec_signing_not_enabled",
        CheckTitle="Check if DNSSEC signing is not enabled on Route53 hosted zones",
        CheckType=["Security"],
        ServiceName="route53",
        SubServiceName="dnssec",
        ResourceIdTemplate="arn:aws:route53:::hostedzone/{zone_id}",
        Severity="medium",
        ResourceType="AwsRoute53HostedZone",
        Risk="Lack of DNSSEC makes DNS data vulnerable to tampering.",
        Description="Checks if Route53 hosted zones have DNSSEC signing enabled.",
        Remediation=Remediation(
            Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
            Recommendation=RemediationRecommendation(
                Text="Enable DNSSEC for Route53 hosted zones.",
                Url="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html",
            ),
        ),
    )

    check = route53_dnssec_signing_not_enabled(metadata)
    report = check.execute(mock_boto_session)

    passed_findings = [r for r in report.resource_ids_status if r.status == CheckStatus.PASSED]

    assert len(passed_findings) == 1
    assert passed_findings[0].resource.name == "example.com." # type: ignore
    assert "DNSSEC is enabled" in passed_findings[0].summary # type: ignore
