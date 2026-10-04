"""
Audit Logger — DynamoDB
Append-only audit trail of every AI decision and analyst action.
Every triage decision and human approval/rejection is logged.

Author: Sunny Bhardwaj
"""

import logging
import uuid
import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

TABLE_NAME = "ai-secops-audit-log"
REGION = "us-east-1"


def _get_table():
    """Get DynamoDB table resource."""
    dynamodb = boto3.resource("dynamodb", region_name=REGION)
    return dynamodb.Table(TABLE_NAME)


def ensure_table_exists() -> bool:
    """Create the DynamoDB audit table if it doesn't exist."""
    dynamodb = boto3.client("dynamodb", region_name=REGION)

    try:
        dynamodb.describe_table(TableName=TABLE_NAME)
        logger.info(f"DynamoDB table {TABLE_NAME} already exists")
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            logger.error(f"Error checking DynamoDB table: {e}")
            return False

    try:
        dynamodb.create_table(
            TableName=TABLE_NAME,
            KeySchema=[
                {"AttributeName": "audit_id", "KeyType": "HASH"},
                {"AttributeName": "timestamp", "KeyType": "RANGE"}
            ],
            AttributeDefinitions=[
                {"AttributeName": "audit_id", "AttributeType": "S"},
                {"AttributeName": "timestamp", "AttributeType": "S"},
                {"AttributeName": "alert_id", "AttributeType": "S"}
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "alert_id-index",
                    "KeySchema": [{"AttributeName": "alert_id", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"}
                }
            ],
            BillingMode="PAY_PER_REQUEST",
            Tags=[
                {"Key": "Project", "Value": "ai-secops-pipeline"},
                {"Key": "Purpose", "Value": "security-audit-log"}
            ]
        )
        logger.info(f"Created DynamoDB table: {TABLE_NAME}")
        return True

    except ClientError as e:
        logger.error(f"Failed to create DynamoDB table: {e}")
        return False


def log_triage_decision(alert: dict, decision: dict, runbook_context: str) -> str:
    """
    Log an AI triage decision to DynamoDB.

    Returns:
        audit_id of the logged record
    """
    audit_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    record = {
        "audit_id": audit_id,
        "timestamp": timestamp,
        "event_type": "AI_TRIAGE",
        "alert_id": alert.get("alert_id", "unknown"),
        "alert_type": alert.get("type", "unknown"),
        "alert_severity": alert.get("severity", "unknown"),
        "alert_resource": alert.get("resource_arn", "unknown"),
        "alert_source_ip": alert.get("source_ip", "unknown"),
        "alert_principal": alert.get("principal", "unknown"),
        "ai_classification": decision.get("classification"),
        "ai_risk_score": decision.get("risk_score"),
        "ai_recommended_action": decision.get("recommended_action"),
        "ai_action_detail": decision.get("action_detail"),
        "ai_summary": decision.get("summary"),
        "ai_reasoning": decision.get("reasoning"),
        "ai_confidence": decision.get("confidence"),
        "ai_model_used": decision.get("model_used", "unknown"),
        "ai_fallback": decision.get("fallback", False),
        "runbook_used": decision.get("runbook_reference", "none"),
        "workflow_status": "PENDING_REVIEW",
    }

    try:
        table = _get_table()
        table.put_item(Item=record)
        logger.info(f"Logged triage decision: {audit_id}")
        return audit_id
    except Exception as e:
        logger.error(f"Failed to log triage decision: {e}")
        # Fail-open for logging — don't block the pipeline
        return audit_id


def log_analyst_decision(
    audit_id: str,
    alert_id: str,
    analyst_action: str,
    analyst_notes: str,
    analyst_id: str = "analyst"
) -> bool:
    """
    Log the analyst's approval or rejection decision.

    Args:
        audit_id: The original triage audit_id
        alert_id: The alert being actioned
        analyst_action: APPROVED, REJECTED, MODIFIED
        analyst_notes: Analyst comments
        analyst_id: Identifier for the analyst

    Returns:
        True if logged successfully
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    record = {
        "audit_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "event_type": "ANALYST_DECISION",
        "alert_id": alert_id,
        "parent_audit_id": audit_id,
        "analyst_id": analyst_id,
        "analyst_action": analyst_action,
        "analyst_notes": analyst_notes[:1000],
        "workflow_status": analyst_action,
    }

    try:
        table = _get_table()
        table.put_item(Item=record)

        # Update the original triage record's workflow status
        table.update_item(
            Key={"audit_id": audit_id, "timestamp": timestamp},
            UpdateExpression="SET workflow_status = :status, analyst_id = :analyst",
            ExpressionAttributeValues={
                ":status": analyst_action,
                ":analyst": analyst_id
            }
        )
        logger.info(f"Logged analyst decision: {analyst_action} for alert {alert_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to log analyst decision: {e}")
        return False


def log_response_action(
    audit_id: str,
    alert_id: str,
    action_taken: str,
    action_result: str,
    aws_resource: str = None
) -> bool:
    """Log an automated response action."""
    timestamp = datetime.now(timezone.utc).isoformat()
    record = {
        "audit_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "event_type": "RESPONSE_ACTION",
        "alert_id": alert_id,
        "parent_audit_id": audit_id,
        "action_taken": action_taken,
        "action_result": action_result,
        "aws_resource": aws_resource or "N/A",
        "workflow_status": "COMPLETED",
    }

    try:
        table = _get_table()
        table.put_item(Item=record)
        logger.info(f"Logged response action: {action_taken} → {action_result}")
        return True
    except Exception as e:
        logger.error(f"Failed to log response action: {e}")
        return False


def get_recent_audit_log(limit: int = 50) -> list:
    """Fetch recent audit log entries for the UI."""
    try:
        table = _get_table()
        response = table.scan(Limit=limit)
        items = response.get("Items", [])
        return sorted(items, key=lambda x: x.get("timestamp", ""), reverse=True)
    except Exception as e:
        logger.error(f"Failed to fetch audit log: {e}")
        return []
