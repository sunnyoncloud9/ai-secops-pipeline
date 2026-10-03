"""
Alert Ingestion Layer
Simulates realistic AWS security findings from:
  - Amazon GuardDuty
  - AWS CloudTrail
  - AWS Security Hub

In production, replace with real boto3 calls to these services.
Author: Sunny Bhardwaj
"""

import uuid
import random
from datetime import datetime, timezone, timedelta
from typing import Optional


# Realistic GuardDuty finding types
GUARDDUTY_FINDINGS = [
    {
        "type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "severity": "HIGH",
        "title": "SSH brute force attack detected on EC2 instance",
        "description": "An EC2 instance is being attacked via SSH brute force from external IP.",
        "service": "guardduty",
        "resource_type": "EC2Instance",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.001 - Brute Force: Password Guessing",
    },
    {
        "type": "Recon:IAMUser/MaliciousIPCaller",
        "severity": "MEDIUM",
        "title": "API calls from known malicious IP",
        "description": "AWS API calls were made using IAM credentials from a known malicious IP address.",
        "service": "guardduty",
        "resource_type": "IAMUser",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1526 - Cloud Service Discovery",
    },
    {
        "type": "Persistence:IAMUser/AnomalousBehavior",
        "severity": "HIGH",
        "title": "Anomalous IAM user behavior detected",
        "description": "An IAM user is performing unusual actions that may indicate account compromise.",
        "service": "guardduty",
        "resource_type": "IAMUser",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1098 - Account Manipulation",
    },
    {
        "type": "CryptoCurrency:EC2/BitcoinTool.B",
        "severity": "HIGH",
        "title": "Cryptocurrency mining activity detected",
        "description": "EC2 instance is communicating with Bitcoin mining pool infrastructure.",
        "service": "guardduty",
        "resource_type": "EC2Instance",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1496 - Resource Hijacking",
    },
    {
        "type": "Exfiltration:S3/ObjectRead.Unusual",
        "severity": "CRITICAL",
        "title": "Unusual S3 data access pattern detected",
        "description": "Unusually large volume of S3 objects read, possible data exfiltration.",
        "service": "guardduty",
        "resource_type": "S3Bucket",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1530 - Data from Cloud Storage",
    },
    {
        "type": "PrivilegeEscalation:IAMUser/AnomalousBehavior",
        "severity": "CRITICAL",
        "title": "IAM privilege escalation attempt",
        "description": "IAM user attempting to escalate privileges by attaching high-permission policies.",
        "service": "guardduty",
        "resource_type": "IAMUser",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1078.004 - Valid Accounts: Cloud Accounts",
    },
]

# Realistic CloudTrail findings
CLOUDTRAIL_FINDINGS = [
    {
        "type": "CloudTrail:RootAccountUsage",
        "severity": "HIGH",
        "title": "AWS root account used",
        "description": "The AWS root account was used to perform API actions. Root usage should be avoided.",
        "service": "cloudtrail",
        "resource_type": "AWSAccount",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1078.004 - Valid Accounts: Cloud Accounts",
    },
    {
        "type": "CloudTrail:UnauthorizedAPICalls",
        "severity": "MEDIUM",
        "title": "Unauthorized API calls detected",
        "description": "Multiple unauthorized API calls detected — possible credential misuse or misconfiguration.",
        "service": "cloudtrail",
        "resource_type": "IAMUser",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1580 - Cloud Infrastructure Discovery",
    },
    {
        "type": "CloudTrail:MFADisabled",
        "severity": "MEDIUM",
        "title": "MFA disabled for IAM user",
        "description": "Multi-factor authentication was disabled for an IAM user account.",
        "service": "cloudtrail",
        "resource_type": "IAMUser",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1556 - Modify Authentication Process",
    },
    {
        "type": "CloudTrail:SecurityGroupChanged",
        "severity": "MEDIUM",
        "title": "Security group rules modified",
        "description": "Inbound rules of a security group were modified, potentially exposing resources.",
        "service": "cloudtrail",
        "resource_type": "SecurityGroup",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.007 - Impair Defenses: Disable or Modify Cloud Firewall",
    },
]

# Realistic Security Hub findings
SECURITYHUB_FINDINGS = [
    {
        "type": "SecurityHub:S3BucketPublicAccess",
        "severity": "CRITICAL",
        "title": "S3 bucket has public access enabled",
        "description": "An S3 bucket has public access enabled which may expose sensitive data.",
        "service": "securityhub",
        "resource_type": "S3Bucket",
        "mitre_tactic": "Collection",
        "mitre_technique": "T1530 - Data from Cloud Storage",
    },
    {
        "type": "SecurityHub:EC2UnencryptedVolume",
        "severity": "MEDIUM",
        "title": "EC2 EBS volume not encrypted",
        "description": "An EC2 EBS volume is not encrypted, violating data protection requirements.",
        "service": "securityhub",
        "resource_type": "EC2Volume",
        "mitre_tactic": "Collection",
        "mitre_technique": "T1005 - Data from Local System",
    },
    {
        "type": "SecurityHub:IAMPasswordPolicy",
        "severity": "LOW",
        "title": "IAM password policy does not meet requirements",
        "description": "The IAM password policy does not enforce minimum length or complexity requirements.",
        "service": "securityhub",
        "resource_type": "AWSAccount",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110 - Brute Force",
    },
    {
        "type": "SecurityHub:CloudTrailNotEnabled",
        "severity": "HIGH",
        "title": "CloudTrail logging not enabled in region",
        "description": "AWS CloudTrail is not enabled in one or more regions, creating audit blind spots.",
        "service": "securityhub",
        "resource_type": "AWSAccount",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.008 - Impair Defenses: Disable Cloud Logs",
    },
]

ALL_FINDINGS = GUARDDUTY_FINDINGS + CLOUDTRAIL_FINDINGS + SECURITYHUB_FINDINGS

SAMPLE_IPS = [
    "185.220.101.45", "194.165.16.72", "45.83.64.1",
    "91.108.4.0", "198.51.100.23", "203.0.113.42",
    "5.188.206.14", "185.156.73.2", "91.213.50.1"
]

SAMPLE_USERS = [
    "arn:aws:iam::111227927537:user/alice",
    "arn:aws:iam::111227927537:user/bob",
    "arn:aws:iam::111227927537:user/jenkins-deploy",
    "arn:aws:iam::111227927537:root",
    "arn:aws:iam::111227927537:user/terraform-runner",
]

SAMPLE_RESOURCES = [
    "arn:aws:ec2:us-east-1:111227927537:instance/i-0abc123def456",
    "arn:aws:s3:::company-prod-backups",
    "arn:aws:s3:::finance-reports-2026",
    "arn:aws:iam::111227927537:user/alice",
    "arn:aws:ec2:us-east-1:111227927537:security-group/sg-0d023a679af1608ff",
]


def generate_alert(finding_template: Optional[dict] = None) -> dict:
    """Generate a realistic security alert."""
    if finding_template is None:
        finding_template = random.choice(ALL_FINDINGS)

    now = datetime.now(timezone.utc)
    alert_id = str(uuid.uuid4())

    return {
        "alert_id": alert_id,
        "type": finding_template["type"],
        "title": finding_template["title"],
        "description": finding_template["description"],
        "severity": finding_template["severity"],
        "service": finding_template["service"],
        "resource_type": finding_template["resource_type"],
        "resource_arn": random.choice(SAMPLE_RESOURCES),
        "source_ip": random.choice(SAMPLE_IPS),
        "principal": random.choice(SAMPLE_USERS),
        "region": "us-east-1",
        "account_id": "111227927537",
        "mitre_tactic": finding_template["mitre_tactic"],
        "mitre_technique": finding_template["mitre_technique"],
        "timestamp": now.isoformat(),
        "first_seen": (now - timedelta(minutes=random.randint(1, 60))).isoformat(),
        "last_seen": now.isoformat(),
        "count": random.randint(1, 50),
        "status": "ACTIVE",
        "workflow_state": "NEW",
    }


def generate_alert_batch(size: int = 5) -> list[dict]:
    """Generate a batch of realistic security alerts."""
    return [generate_alert() for _ in range(size)]


def get_alert_by_type(alert_type: str) -> dict:
    """Get a specific alert type by name."""
    for finding in ALL_FINDINGS:
        if finding["type"] == alert_type:
            return generate_alert(finding)
    return generate_alert()
