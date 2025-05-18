from datetime import datetime, timezone, timedelta
import boto3 # type: ignore
import csv
import botocore.exceptions # type: ignore
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_roles_unused_90_days(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')
        threshold_days = 90
        now = datetime.now(timezone.utc)

        try:
            client.generate_credential_report()
            response = client.get_credential_report()
            content = response['Content'].decode('utf-8')

            reader = csv.DictReader(content.splitlines())

            found_roles = False
            for row in reader:
                arn = row.get("arn", "")
                if ":role/" not in arn:
                    continue  # Skip users, only check roles

                found_roles = True
                role_name = row.get("user", "Unknown")
                last_used_strs = [
                    row.get("password_last_used", "N/A"),
                    row.get("access_key_1_last_used_date", "N/A"),
                    row.get("access_key_2_last_used_date", "N/A"),
                ]

                def parse_date(d):
                    try:
                        return datetime.strptime(d, "%Y-%m-%dT%H:%M:%S+00:00").replace(tzinfo=timezone.utc)
                    except Exception:
                        return None

                last_used_dates = [parse_date(d) for d in last_used_strs if d not in ["", "N/A"]]
                most_recent = max(last_used_dates) if last_used_dates else None   # type: ignore

                if most_recent and (now - most_recent).days <= threshold_days:
                    summary = f"IAM Role '{role_name}' used recently on {most_recent.strftime('%Y-%m-%d')}."
                    status = CheckStatus.PASSED
                else:
                    summary = f"IAM Role '{role_name}' not used in last {threshold_days} days." \
                        if most_recent else f"IAM Role '{role_name}' has never been used."
                    status = CheckStatus.FAILED

                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=role_name),
                        status=status,
                        summary=summary
                    )
                )

            if not found_roles:
                report.status = CheckStatus.UNKNOWN
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="IAMRoles"),
                        status=CheckStatus.UNKNOWN,
                        summary="Credential report is empty or invalid",
                    )
                )
            else:
                failed = [r for r in report.resource_ids_status if r.status == CheckStatus.FAILED]
                passed = [r for r in report.resource_ids_status if r.status == CheckStatus.PASSED]
                if failed and not passed:
                    report.status = CheckStatus.FAILED
                elif passed and not failed:
                    report.status = CheckStatus.PASSED
                else:
                    report.status = CheckStatus.FAILED  # Mixed results treated as FAILED

        except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError, ValueError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="IAMRoles"),
                    status=CheckStatus.UNKNOWN,
                    summary="Failed to retrieve IAM credential report.",
                    exception=str(e)
                )
            )

        return report
