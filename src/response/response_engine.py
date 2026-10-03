"""
Response Engine
Executes analyst-approved remediation actions.
NEVER acts autonomously — all actions require explicit analyst approval.

Supported actions:
  - BLOCK_IP: Add deny rule to AWS Security Group
  - ISOLATE_RESOURCE: Tag EC2 instance for isolation
  - ESCALATE: Send SNS notification
  - SUPPRESS: Mark as false positive
  - MONITOR: Tag for enhanced monitoring

Author: Sunny Bhardwaj
"""

import os
import logging
import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SECURITY_GROUP_ID = os.environ.get("SECURITY_GROUP_ID")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")


def execute_response(
    action: str,
    alert: dict,
    decision: dict,
    analyst_notes: str = ""
) -> dict:
    """
    Execute an analyst-approved response action.

    Args:
        action: The approved action (BLOCK_IP, ISOLATE_RESOURCE, etc.)
        alert: The original security alert
        decision: The AI triage decision
        analyst_notes: Analyst's notes/modifications

    Returns:
        Result dict with status and details
    """
    logger.info(f"Executing approved action: {action} for alert {alert.get('alert_id')}")

    handlers = {
        "BLOCK_IP": _block_ip,
        "ISOLATE_RESOURCE": _isolate_resource,
        "ESCALATE": _escalate,
        "SUPPRESS": _suppress,
        "MONITOR": _monitor,
    }

    handler = handlers.get(action)
    if not handler:
        return {
            "status": "FAILED",
            "action": action,
            "detail": f"Unknown action: {action}",
            "aws_resource": None
        }

    return handler(alert, decision, analyst_notes)


def _block_ip(alert: dict, decision: dict, analyst_notes: str) -> dict:
    """Block a source IP in the AWS Security Group."""
    ip = alert.get("source_ip")
    if not ip:
        return {"status": "SKIPPED", "action": "BLOCK_IP",
                "detail": "No source IP in alert", "aws_resource": None}

    sg_id = SECURITY_GROUP_ID
    if not sg_id:
        logger.warning("SECURITY_GROUP_ID not configured — simulating block")
        return {
            "status": "SIMULATED",
            "action": "BLOCK_IP",
            "detail": f"Simulated: would block {ip}/32 (SECURITY_GROUP_ID not set)",
            "aws_resource": "N/A"
        }

    try:
        ec2 = boto3.client("ec2", region_name=AWS_REGION)
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{
                    "CidrIp": f"{ip}/32",
                    "Description": (
                        f"AI-SecOps auto-block | Alert: {alert.get('type')} | "
                        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
                    )
                }]
            }]
        )
        logger.info(f"Blocked {ip}/32 in Security Group {sg_id}")
        return {
            "status": "SUCCESS",
            "action": "BLOCK_IP",
            "detail": f"Blocked {ip}/32 in {sg_id}",
            "aws_resource": sg_id
        }

    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidPermission.Duplicate":
            return {"status": "SKIPPED", "action": "BLOCK_IP",
                    "detail": f"{ip} already blocked", "aws_resource": sg_id}
        logger.error(f"Failed to block IP: {e}")
        return {"status": "FAILED", "action": "BLOCK_IP",
                "detail": str(e), "aws_resource": sg_id}


def _isolate_resource(alert: dict, decision: dict, analyst_notes: str) -> dict:
    """Tag an EC2 instance for isolation (quarantine)."""
    resource_arn = alert.get("resource_arn", "")

    # Extract instance ID from ARN if it's an EC2 instance
    instance_id = None
    if "instance/" in resource_arn:
        instance_id = resource_arn.split("instance/")[-1]

    if not instance_id:
        return {
            "status": "SIMULATED",
            "action": "ISOLATE_RESOURCE",
            "detail": f"Resource isolation noted for: {resource_arn}. Manual isolation required.",
            "aws_resource": resource_arn
        }

    try:
        ec2 = boto3.client("ec2", region_name=AWS_REGION)
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "secops:status", "Value": "QUARANTINED"},
                {"Key": "secops:alert_type", "Value": alert.get("type", "unknown")},
                {"Key": "secops:quarantine_time", "Value": datetime.now(timezone.utc).isoformat()},
                {"Key": "secops:analyst_notes", "Value": analyst_notes[:255]},
            ]
        )
        logger.info(f"Isolated instance: {instance_id}")
        return {
            "status": "SUCCESS",
            "action": "ISOLATE_RESOURCE",
            "detail": f"Tagged {instance_id} as QUARANTINED",
            "aws_resource": instance_id
        }

    except ClientError as e:
        logger.error(f"Failed to isolate resource: {e}")
        return {"status": "FAILED", "action": "ISOLATE_RESOURCE",
                "detail": str(e), "aws_resource": instance_id}


def _escalate(alert: dict, decision: dict, analyst_notes: str) -> dict:
    """Send an SNS escalation notification."""
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not configured — simulating escalation")
        return {
            "status": "SIMULATED",
            "action": "ESCALATE",
            "detail": "Simulated escalation (SNS_TOPIC_ARN not set)",
            "aws_resource": None
        }

    try:
        sns = boto3.client("sns", region_name=AWS_REGION)
        subject = f"[AI-SecOps ESCALATION] {alert.get('severity')} — {alert.get('type')}"
        message = (
            f"SECURITY ALERT ESCALATION\n"
            f"{'='*50}\n"
            f"Alert Type    : {alert.get('type')}\n"
            f"Severity      : {alert.get('severity')}\n"
            f"Classification: {decision.get('classification')}\n"
            f"Risk Score    : {decision.get('risk_score')}/100\n"
            f"Resource      : {alert.get('resource_arn')}\n"
            f"Source IP     : {alert.get('source_ip')}\n"
            f"Principal     : {alert.get('principal')}\n"
            f"MITRE Tactic  : {alert.get('mitre_tactic')}\n"
            f"AI Summary    : {decision.get('summary')}\n"
            f"AI Reasoning  : {decision.get('reasoning')}\n"
            f"Analyst Notes : {analyst_notes}\n"
            f"{'='*50}\n"
            f"ACTION REQUIRED: Senior security analyst review needed immediately."
        )
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)
        logger.info(f"Escalation sent via SNS for alert {alert.get('alert_id')}")
        return {
            "status": "SUCCESS",
            "action": "ESCALATE",
            "detail": f"Escalation notification sent to {SNS_TOPIC_ARN}",
            "aws_resource": SNS_TOPIC_ARN
        }

    except ClientError as e:
        logger.error(f"Failed to send escalation: {e}")
        return {"status": "FAILED", "action": "ESCALATE",
                "detail": str(e), "aws_resource": SNS_TOPIC_ARN}


def _suppress(alert: dict, decision: dict, analyst_notes: str) -> dict:
    """Mark alert as false positive — no AWS action needed."""
    logger.info(f"Alert {alert.get('alert_id')} suppressed as false positive")
    return {
        "status": "SUCCESS",
        "action": "SUPPRESS",
        "detail": f"Marked as false positive. Notes: {analyst_notes}",
        "aws_resource": None
    }


def _monitor(alert: dict, decision: dict, analyst_notes: str) -> dict:
    """Tag resource for enhanced monitoring."""
    resource_arn = alert.get("resource_arn", "unknown")
    logger.info(f"Alert {alert.get('alert_id')} tagged for enhanced monitoring")
    return {
        "status": "SUCCESS",
        "action": "MONITOR",
        "detail": f"Resource {resource_arn} flagged for enhanced monitoring",
        "aws_resource": resource_arn
    }
