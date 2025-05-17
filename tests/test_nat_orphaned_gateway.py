import boto3  # type: ignore
import pytest  # type: ignore
from unittest.mock import patch, MagicMock
import sys
from tevico.engine.entities.report.check_model import (
    CheckStatus,
    CheckMetadata,
    Remediation,
    RemediationCode,
    RemediationRecommendation,
)
from library.aws.checks.nat.nat_orphaned_gateways import check_orphaned_nat_gateways


@pytest.fixture
def mock_boto_session():
    return boto3.Session(region_name="us-east-1")


@patch("boto3.Session.client")
def test_orphaned_nat_gateways_found(mock_client, mock_boto_session):
    mock_ec2 = MagicMock()
    mock_client.return_value = mock_ec2

    # Mock NAT Gateways: 2 gateways, one referenced, one orphaned
    mock_ec2.get_paginator.return_value.paginate.side_effect = [
        [  # describe_nat_gateways pages
            {
                "NatGateways": [
                    {
                        "NatGatewayId": "nat-123",
                        "SubnetId": "subnet-1",
                        "State": "available",
                    },
                    {
                        "NatGatewayId": "nat-456",
                        "SubnetId": "subnet-2",
                        "State": "available",
                    },
                ]
            }
        ],
        [  # describe_route_tables pages
            {
                "RouteTables": [
                    {
                        "Routes": [
                            {"NatGatewayId": "nat-123"},
                            {"GatewayId": "igw-123"},
                        ]
                    }
                ]
            }
        ],
    ]

    metadata = CheckMetadata(
        Provider="AWS",
        CheckID="orphaned_nat_gateway_check",
        CheckTitle="Ensure NAT Gateways are not orphaned",
        CheckType=["Networking", "Cost Optimization"],
        ServiceName="ec2",
        SubServiceName="natgateway",
        ResourceIdTemplate="arn:aws:ec2:{region}:{account_id}:natgateway/{nat_gateway_id}",
        Severity="medium",
        ResourceType="AwsNatGateway",
        Risk="Orphaned NAT Gateways can lead to unnecessary charges.",
        Description="Checks for NAT Gateways not referenced in any route table.",
        Remediation=Remediation(
            Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
            Recommendation=RemediationRecommendation(
                Text="Delete NAT Gateways not associated with any route tables to save cost.",
                Url="https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html",
            ),
        ),
    )
    check = check_orphaned_nat_gateways(metadata)
    report = check.execute(mock_boto_session)

    failed_findings = [
        r for r in report.resource_ids_status if r.status == CheckStatus.FAILED
    ]
    passed_findings = [
        r for r in report.resource_ids_status if r.status == CheckStatus.PASSED
    ]

    # Expect one failed for the orphaned NAT Gateway "nat-456"
    assert len(failed_findings) == 1
    assert failed_findings[0].resource.name == "nat-456"

    # No passed findings because at least one failed exists
    assert len(passed_findings) == 0


@patch("boto3.Session.client")
def test_no_orphaned_nat_gateways(mock_client, mock_boto_session):
    mock_ec2 = MagicMock()
    mock_client.return_value = mock_ec2

    # All NAT Gateways referenced in route tables
    mock_ec2.get_paginator.return_value.paginate.side_effect = [
        [
            {
                "NatGateways": [
                    {
                        "NatGatewayId": "nat-123",
                        "SubnetId": "subnet-1",
                        "State": "available",
                    },
                ]
            }
        ],
        [
            {
                "RouteTables": [
                    {
                        "Routes": [
                            {"NatGatewayId": "nat-123"},
                        ]
                    }
                ]
            }
        ],
    ]

    metadata = CheckMetadata(
        Provider="AWS",
        CheckID="orphaned_nat_gateway_check",
        CheckTitle="Ensure NAT Gateways are not orphaned",
        CheckType=["Networking", "Cost Optimization"],
        ServiceName="ec2",
        SubServiceName="natgateway",
        ResourceIdTemplate="arn:aws:ec2:{region}:{account_id}:natgateway/{nat_gateway_id}",
        Severity="medium",
        ResourceType="AwsNatGateway",
        Risk="Orphaned NAT Gateways can lead to unnecessary charges.",
        Description="Checks for NAT Gateways not referenced in any route table.",
        Remediation=Remediation(
            Code=RemediationCode(CLI="", NativeIaC="", Terraform=""),
            Recommendation=RemediationRecommendation(
                Text="Delete NAT Gateways not associated with any route tables to save cost.",
                Url="https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html",
            ),
        ),
    )

    check = check_orphaned_nat_gateways(metadata)
    report = check.execute(mock_boto_session)

    passed_findings = [
        r for r in report.resource_ids_status if r.status == CheckStatus.PASSED
    ]
    failed_findings = [
        r for r in report.resource_ids_status if r.status == CheckStatus.FAILED
    ]

    # Expect one passed finding because no orphaned NAT gateways exist
    assert len(passed_findings) == 1
    assert len(failed_findings) == 0

    assert passed_findings[0].summary == "All NAT Gateways are associated with route tables."

