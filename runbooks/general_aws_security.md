# Runbook: General AWS Security Best Practices & Triage Guide

## Overview
This runbook provides general guidance for triaging and responding to AWS security findings across all severity levels.

## Severity Classification

| Severity | Response Time | Description |
|----------|--------------|-------------|
| CRITICAL | < 15 minutes | Active data breach, privilege escalation, ransomware |
| HIGH | < 1 hour | Active attack, compromised credentials, crypto mining |
| MEDIUM | < 4 hours | Policy violations, anomalous behavior, misconfigurations |
| LOW | < 24 hours | Best practice violations, informational findings |

## Universal Triage Steps

1. **Verify the finding** — Is this a true positive or false positive?
2. **Assess blast radius** — What resources are affected?
3. **Contain immediately** — Stop the bleeding before investigating
4. **Preserve evidence** — Logs, snapshots, network captures
5. **Investigate root cause** — How did this happen?
6. **Remediate** — Fix the vulnerability, not just the symptom
7. **Document and learn** — Post-incident review

## Common False Positive Indicators

- Scheduled maintenance windows
- Known penetration testing activities
- Legitimate third-party security scanners
- Dev/test environment activities mistakenly flagged
- New AWS service launching in the account

## Evidence Collection Checklist

- [ ] CloudTrail events for the relevant time window
- [ ] VPC Flow Logs for the affected resources
- [ ] GuardDuty finding details (full JSON)
- [ ] IAM user/role activity report
- [ ] Resource configuration at time of incident (AWS Config)
- [ ] Any relevant application logs

## Escalation Matrix

| Condition | Escalate To |
|-----------|-------------|
| Data breach suspected | CISO + Legal + affected team leads |
| Critical production systems affected | On-call engineering + CISO |
| Regulatory data involved | Legal + Compliance + CISO |
| Insider threat | HR + Legal + CISO (not the user's manager) |
| Nation-state TTPs | CISO + AWS Support + FBI (if applicable) |

## AWS Security Contacts

- AWS Security: https://aws.amazon.com/security/vulnerability-reporting/
- AWS Abuse: abuse@amazonaws.com
- AWS Support: Open a case for security events

## Response Communication Template

```
INCIDENT SUMMARY
Time Detected: [timestamp]
Alert Type: [finding type]
Severity: [CRITICAL/HIGH/MEDIUM/LOW]
Resources Affected: [list]
Current Status: [Investigating / Contained / Remediated]
Next Steps: [list]
```
