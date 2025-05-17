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
from datetime import datetime, timezone, timedelta


class check_lambda_over_provisioned_memory(Check):
    def __init__(self, metadata: Optional[CheckMetadata] = None):
        super().__init__(metadata=metadata)

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client("lambda")
        cloudwatch_client = connection.client("cloudwatch")
        name = self.__class__.__name__
        report = CheckReport(name=name, check_metadata=self.metadata)
        findings: List[ResourceStatus] = []

        # Fetch all Lambda functions
        functions = []
        paginator = client.get_paginator("list_functions")
        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))

        for function in functions:
            function_name = function.get("FunctionName")
            memory_size = function.get("MemorySize", 0)

            try:
                end_time = datetime.now(timezone.utc)
                start_time = end_time - timedelta(days=7)

                metrics = cloudwatch_client.get_metric_statistics(
                    Namespace="AWS/Lambda",
                    MetricName="MaxMemoryUsed",
                    Dimensions=[{"Name": "FunctionName", "Value": function_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=["Maximum"],
                )

                datapoints = metrics.get("Datapoints", [])
                if not datapoints:
                    continue

                max_memory_used = max(dp["Maximum"] for dp in datapoints)

                if max_memory_used < memory_size * 0.5:
                    findings.append(
                        ResourceStatus(
                            status=CheckStatus.FAILED,
                            resource=GeneralResource(name=function_name),
                            resource_id=function_name,
                            message="Lambda function is likely over-provisioned.",
                            summary=f"Used: {int(max_memory_used)}MB / Allocated: {memory_size}MB - Usage < 50%",
                        )
                    )
                else:
                    findings.append(
                        ResourceStatus(
                            status=CheckStatus.PASSED,
                            resource=GeneralResource(name=function_name),
                            resource_id=function_name,
                            message="Lambda function memory usage appears appropriate.",
                            summary=f"Used: {int(max_memory_used)}MB / Allocated: {memory_size}MB - Usage is acceptable",
                        )
                    )

            except (BotoCoreError, ClientError) as e:
                # Append unknown status finding directly to report.resource_ids_status list
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource_id=function_name,
                        status=CheckStatus.UNKNOWN,
                        message="Failed to fetch Lambda metrics.",
                        exception=str(e),
                    )
                )

        # Append all collected findings to the report's resource_ids_status list
        report.resource_ids_status.extend(findings)

        return report
