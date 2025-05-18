import boto3  # type: ignore
from typing import Optional, List
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
from tevico.engine.entities.report.check_model import (
    CheckMetadata,
    CheckReport,
    ResourceStatus,
    CheckStatus,
    GeneralResource,
)
from tevico.engine.entities.check.check import Check

class check_orphaned_nat_gateways(Check):
    def __init__(self, metadata: Optional[CheckMetadata] = None):
        super().__init__(metadata=metadata)

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client("ec2")
        name = self.__class__.__name__
        report = CheckReport(name=name, check_metadata=self.metadata)
        findings: List[ResourceStatus] = []

        try:
            # Fetch all NAT Gateways
            nat_gateways = []
            paginator = client.get_paginator("describe_nat_gateways")
            for page in paginator.paginate():
                nat_gateways.extend(page.get("NatGateways", []))

            # Fetch all Route Tables
            route_tables = []
            paginator = client.get_paginator("describe_route_tables")
            for page in paginator.paginate():
                route_tables.extend(page.get("RouteTables", []))

            # Collect NAT Gateway IDs used in any route table route
            referenced_nat_gateway_ids = set()
            for rt in route_tables:
                for route in rt.get("Routes", []):
                    if "NatGatewayId" in route:
                        referenced_nat_gateway_ids.add(route["NatGatewayId"])

            # Find NAT Gateways not referenced by any route table
            orphaned_nats = [
                nat for nat in nat_gateways if nat["NatGatewayId"] not in referenced_nat_gateway_ids
            ]

            for nat in orphaned_nats:
                nat_id = nat.get("NatGatewayId", "N/A")
                subnet_id = nat.get("SubnetId", "N/A")
                state = nat.get("State", "unknown")
                creation_time = nat.get("CreateTime")
                creation_str = creation_time.isoformat() if creation_time else "N/A"

                findings.append(
                    ResourceStatus(
                        status=CheckStatus.FAILED,
                        resource=GeneralResource(name=nat_id),
                        resource_id=nat_id,
                        message="NAT Gateway is orphaned and not used in any route table.",
                        summary=f"Subnet: {subnet_id}, State: {state}, Created: {creation_str}",
                    )
                )

            # If no orphaned NAT Gateways, mark check passed
            if not orphaned_nats:
                findings.append(
                    ResourceStatus(
                        status=CheckStatus.PASSED,
                        resource=GeneralResource(name="NAT Gateways"),
                        resource_id="all",
                        message="No orphaned NAT Gateways found.",
                        summary="All NAT Gateways are associated with route tables.",
                    )
                )

        except (BotoCoreError, ClientError) as e:
            report.resource_ids_status.append(
                ResourceStatus(
                    resource_id="orphaned_nat_gateway_check",
                    status=CheckStatus.UNKNOWN,
                    message="Failed to fetch NAT Gateways or Route Tables.",
                    exception=str(e),
                )
            )
            return report

        report.resource_ids_status.extend(findings)
        return report
