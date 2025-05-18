"""
AUTHOR: Prajwal Choudhari
EMAIL: prajwal.choudhari@comprinno.net
DATE: 2025-05-18
"""

import boto3   # type: ignore
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class vpc_peering_dns_resolution_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            client = connection.client("ec2")
            pcx_response = client.describe_vpc_peering_connections(
                Filters=[{"Name": "status-code", "Values": ["active"]}]
            )

            peering_connections = pcx_response.get("VpcPeeringConnections", [])

            if not peering_connections:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="VPC Peering"),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No active VPC peering connections found."
                    )
                )
                return report

            region = client.meta.region_name
            account_id = connection.client("sts").get_caller_identity()["Account"]

            for pcx in peering_connections:
                pcx_id = pcx["VpcPeeringConnectionId"]
                pcx_arn = f"arn:aws:ec2:{region}:{account_id}:vpc-peering-connection/{pcx_id}"
                resource = AwsResource(arn=pcx_arn)

                try:
                    options_response = client.describe_vpc_peering_connection_options(
                        VpcPeeringConnectionId=pcx_id
                    )
                    requester_dns = options_response["VpcPeeringConnectionOptions"]["RequesterPeeringConnectionOptions"].get("AllowDnsResolutionFromRemoteVpc")
                    accepter_dns = options_response["VpcPeeringConnectionOptions"]["AccepterPeeringConnectionOptions"].get("AllowDnsResolutionFromRemoteVpc")

                    if requester_dns and accepter_dns:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.PASSED,
                                summary=f"DNS resolution is enabled for both sides of VPC Peering Connection {pcx_id}."
                            )
                        )
                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"DNS resolution is not enabled on both sides of VPC Peering Connection {pcx_id}."
                            )
                        )

                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error checking DNS resolution settings for {pcx_id}: {str(e)}",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="VPC Peering"),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error retrieving VPC peering connections: {str(e)}",
                    exception=str(e)
                )
            )

        return report
