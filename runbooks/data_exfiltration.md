# Runbook: Data Exfiltration (S3 / EC2)

## Severity: CRITICAL
## MITRE ATT&CK: T1530 — Data from Cloud Storage

## Overview
Data exfiltration from AWS typically targets S3 buckets, RDS databases, or EC2 instance storage. GuardDuty detects unusual S3 read patterns, large volume data access, or communication with known exfiltration infrastructure.

## Immediate Actions (< 5 minutes)

1. **Block S3 access immediately**:
   - Apply a bucket policy that denies all s3:GetObject for the offending principal
   - Enable S3 Block Public Access on the account level if not already enabled

2. **Identify what data was accessed**:
   ```bash
   aws s3api list-objects --bucket <bucket-name> --query 'Contents[*].Key' > accessed_objects.txt
   ```

3. **Check S3 server access logs** or CloudTrail for the exact objects accessed

4. **Preserve evidence**:
   - Do NOT delete logs or terminate instances yet
   - Export CloudTrail events for the relevant time window

## Investigation Steps

- What bucket(s) were accessed?
- What objects were accessed? (S3 access logs, CloudTrail)
- What principal made the requests? (IAM user, role, or public access?)
- What was the total data volume transferred?
- Was data transferred to an external IP or another AWS account?
- Is the bucket supposed to be publicly accessible?

## Data Classification Questions

- Does the bucket contain PII, PHI, or PCI data?
- Are there regulatory notification requirements (GDPR 72hr, HIPAA, etc.)?
- What is the business impact of this data being exposed?

## Recommended Actions

| Scenario | Action |
|----------|--------|
| Public bucket accessed | Remove public access, block IPs, notify legal |
| Compromised credentials | Disable credentials, audit all access |
| Insider threat | Preserve evidence, notify HR and legal |
| Misconfigured permissions | Fix ACLs, implement least privilege |

## Regulatory Notification Checklist

- [ ] Legal team notified
- [ ] CISO notified
- [ ] GDPR notification window tracked (72 hours from discovery)
- [ ] Affected users identified
- [ ] Data volume and type documented

## Long-term Remediation

- Enable S3 Block Public Access at account level
- Enable S3 server access logging on all buckets
- Use S3 bucket policies with explicit deny for public access
- Implement Macie for sensitive data discovery
- Use VPC endpoints for S3 access to avoid internet routing

## Escalation
IMMEDIATE escalation to CISO and Legal if PII, PHI, or PCI data involved.
