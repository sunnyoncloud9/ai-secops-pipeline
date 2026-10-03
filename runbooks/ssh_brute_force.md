# Runbook: SSH Brute Force Attack (GuardDuty: UnauthorizedAccess:EC2/SSHBruteForce)

## Severity: HIGH
## MITRE ATT&CK: T1110.001 — Brute Force: Password Guessing

## Overview
SSH brute force attacks attempt to gain unauthorized access to EC2 instances by systematically trying username/password combinations. GuardDuty detects this by analyzing VPC Flow Logs for repeated failed SSH connection attempts.

## Immediate Actions (< 15 minutes)

1. **Block the source IP** in the EC2 Security Group:
   - Remove inbound SSH (port 22) rule for the offending IP
   - Add explicit DENY rule for the source IP CIDR

2. **Verify instance integrity**:
   - Check `/var/log/auth.log` or `/var/log/secure` for successful logins
   - Run `last` to see recent login history
   - Check for new user accounts or SSH keys added

3. **Rotate credentials if compromise suspected**:
   - Rotate any SSH key pairs on the instance
   - Rotate any IAM credentials if the instance has an instance profile

## Investigation Steps

- How many connection attempts? (GuardDuty finding count)
- Is SSH exposed to 0.0.0.0/0? (Security group misconfiguration)
- Is the target instance publicly facing? (Should it be?)
- Has the source IP appeared in other findings?

## Recommended Actions

| Scenario | Action |
|----------|--------|
| Ongoing attack, no successful login | Block IP, restrict SSH to VPN only |
| Successful login detected | Isolate instance, full forensic investigation |
| Instance shouldn't have SSH | Remove SSH rule entirely |
| Recurring from same IP | Add to WAF IP blocklist |

## Long-term Remediation

- Replace SSH with AWS Systems Manager Session Manager (no SSH required)
- Restrict SSH to known IP ranges or VPN only
- Enable EC2 Instance Connect for temporary access
- Enable GuardDuty for all regions

## Escalation
Escalate to Senior Security Engineer if: successful login detected, lateral movement observed, or data exfiltration suspected.
