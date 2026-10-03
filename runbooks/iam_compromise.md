# Runbook: IAM User Compromise / Anomalous Behavior

## Severity: HIGH / CRITICAL
## MITRE ATT&CK: T1078.004 — Valid Accounts: Cloud Accounts

## Overview
IAM credential compromise is one of the most critical AWS security incidents. Attackers use stolen credentials to enumerate resources, escalate privileges, exfiltrate data, or establish persistence.

## Immediate Actions (< 10 minutes)

1. **Disable the IAM user immediately**:
   ```bash
   aws iam update-login-profile --user-name <username> --no-password-reset-required
   aws iam delete-login-profile --user-name <username>
   ```

2. **Deactivate all access keys**:
   ```bash
   aws iam list-access-keys --user-name <username>
   aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <username>
   ```

3. **Revoke all active sessions**:
   ```bash
   aws iam delete-user-policy --user-name <username> --policy-name <inline-policy>
   # Add explicit deny policy to block all actions
   ```

## Investigation Steps

- What API calls were made? (CloudTrail — filter by username, last 24 hours)
- Were any new IAM users, roles, or access keys created?
- Were any S3 buckets accessed or made public?
- Were any EC2 instances launched or security groups changed?
- Were any resources created in unusual regions?
- Is the source IP associated with a known threat actor?

## CloudTrail Query
```
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<username> \
  --start-time $(date -d '24 hours ago' --iso-8601=seconds) \
  --query 'Events[*].{Time:EventTime,Event:EventName,IP:CloudTrailEvent}' \
  --output table
```

## Recommended Actions

| Scenario | Action |
|----------|--------|
| Credentials leaked in code | Disable key, rotate, scan all repos |
| Phishing suspected | Disable user, reset MFA, notify user |
| Privilege escalation attempted | Full incident response, legal notification |
| Resources created by attacker | Terminate attacker-created resources |

## Long-term Remediation

- Enforce MFA for all IAM users
- Use IAM roles instead of long-term access keys
- Enable AWS CloudTrail with log file validation
- Implement IAM Access Analyzer
- Rotate access keys every 90 days
- Use AWS Secrets Manager for application credentials

## Escalation
Always escalate to CISO if: data exfiltration suspected, new admin users created, billing anomalies detected.
