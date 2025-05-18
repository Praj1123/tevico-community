from unittest.mock import MagicMock
from boto3 import Session  # type: ignore
import pytest  # type: ignore

from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)

from library.aws.checks.vpc.vpc_peering_dns_resolution_enabled import vpc_peering_dns_resolution_enabled


@pytest.fixture
def metadata():
    return CheckMetadata(
        Provider="AWS",
        CheckID="vpc_peering_dns_resolution_enabled",
        CheckTitle="Ensure DNS Resolution is Enabled for VPC Peering Connections",
        CheckType=["Networking"],
        ServiceName="ec2",
        SubServiceName="vpc",
        ResourceIdTemplate="arn:aws:ec2:{region}:{account_id}:vpc-peering-connection/{pcx_id}",
        Severity="low",
        ResourceType="AwsVpcPeeringConnection",
        Description="Check that DNS resolution is enabled for both requester and accepter in active VPC peering connections.",
        Risk="Without DNS resolution enabled, services in peered VPCs cannot resolve domain names.",
        Remediation=Remediation(
            Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
            Recommendation=RemediationRecommendation(
                Text="Enable DNS resolution in both directions for all active VPC peering connections.",
                Url="https://docs.aws.amazon.com/vpc/latest/peering/modify-peering-connections.html",
            ),
        ),
    )


def test_dns_enabled_both_sides(metadata):
    session = MagicMock(spec=Session)
    ec2_client = MagicMock()
    session.client.return_value = ec2_client

    ec2_client.describe_vpc_peering_connections.return_value = {
        "VpcPeeringConnections": [
            {
                "VpcPeeringConnectionId": "pcx-123abc",
                "Status": {"Code": "active"}
            }
        ]
    }

    ec2_client.describe_vpc_peering_connection_options.return_value = {
        "VpcPeeringConnectionOptions": {
            "RequesterPeeringConnectionOptions": {
                "AllowDnsResolutionFromRemoteVpc": True
            },
            "AccepterPeeringConnectionOptions": {
                "AllowDnsResolutionFromRemoteVpc": True
            }
        }
    }

    check = vpc_peering_dns_resolution_enabled(metadata)
    report = check.execute(session)

    assert report.status == CheckStatus.PASSED
    assert report.resource_ids_status[0].status == CheckStatus.PASSED
    assert "DNS resolution is enabled" in report.resource_ids_status[0].summary    # type: ignore


def test_dns_disabled_on_one_side(metadata):
    session = MagicMock(spec=Session)
    ec2_client = MagicMock()
    session.client.return_value = ec2_client

    ec2_client.describe_vpc_peering_connections.return_value = {
        "VpcPeeringConnections": [
            {"VpcPeeringConnectionId": "pcx-456def", "Status": {"Code": "active"}}
        ]
    }

    ec2_client.describe_vpc_peering_connection_options.return_value = {
        "VpcPeeringConnectionOptions": {
            "RequesterPeeringConnectionOptions": {
                "AllowDnsResolutionFromRemoteVpc": False
            },
            "AccepterPeeringConnectionOptions": {
                "AllowDnsResolutionFromRemoteVpc": True
            }
        }
    }

    check = vpc_peering_dns_resolution_enabled(metadata)
    report = check.execute(session)

    assert report.status == CheckStatus.FAILED
    assert report.resource_ids_status[0].status == CheckStatus.FAILED
    assert "not enabled on both sides" in report.resource_ids_status[0].summary   # type: ignore


def test_no_peering_connections(metadata):
    session = MagicMock(spec=Session)
    ec2_client = MagicMock()
    session.client.return_value = ec2_client

    ec2_client.describe_vpc_peering_connections.return_value = {
        "VpcPeeringConnections": []
    }

    check = vpc_peering_dns_resolution_enabled(metadata)
    report = check.execute(session)

    assert report.status == CheckStatus.NOT_APPLICABLE
    assert "No active VPC peering connections" in report.resource_ids_status[0].summary  # type: ignore


def test_exception_on_options_call(metadata):
    session = MagicMock(spec=Session)
    ec2_client = MagicMock()
    session.client.return_value = ec2_client

    ec2_client.describe_vpc_peering_connections.return_value = {
        "VpcPeeringConnections": [
            {"VpcPeeringConnectionId": "pcx-789ghi", "Status": {"Code": "active"}}
        ]
    }

    ec2_client.describe_vpc_peering_connection_options.side_effect = Exception("Access Denied")

    check = vpc_peering_dns_resolution_enabled(metadata)
    report = check.execute(session)

    assert report.status == CheckStatus.UNKNOWN
    assert "Error checking DNS resolution" in report.resource_ids_status[0].summary    # type: ignore
    assert report.resource_ids_status[0].status == CheckStatus.UNKNOWN 
