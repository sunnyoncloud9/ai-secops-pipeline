# Runbook: Cryptocurrency Mining (GuardDuty: CryptoCurrency:EC2/BitcoinTool)

## Severity: HIGH
## MITRE ATT&CK: T1496 — Resource Hijacking

## Overview
Crypto mining on EC2 instances indicates a compromised instance being used to mine cryptocurrency at the account owner's expense. This typically follows successful exploitation or credential compromise.

## Immediate Actions (< 15 minutes)

1. **Isolate the EC2 instance**:
   - Attach a restrictive security group that blocks all outbound traffic
   - Do NOT terminate yet — preserve forensic evidence

2. **Take a snapshot**:
   ```bash
   aws ec2 create-snapshot --volume-id <volume-id> --description "forensic-snapshot-$(date +%Y%m%d)"
   ```

3. **Identify the mining process**:
   - Check running processes: `ps aux | grep -E 'xmrig|minerd|cgminer|bfgminer'`
   - Check network connections: `netstat -tlnp | grep <mining_port>`

## Investigation Steps

- How did the attacker gain access? (SSH brute force, web shell, RCE vulnerability)
- What mining software is installed and where?
- Were any files modified or backdoors installed?
- Are other instances in the same VPC affected?
- What is the estimated cost impact from resource usage?

## Recommended Actions

| Scenario | Action |
|----------|--------|
| Instance compromised via SSH | Isolate, snapshot, terminate, rebuild |
| Web application vulnerability | Patch vulnerability, rotate credentials, rebuild |
| Compromised AMI | Report AMI, replace all instances from it |
| Insider threat | Evidence preservation, HR and legal notification |

## Long-term Remediation

- Implement GuardDuty in all regions
- Use EC2 Instance Metadata Service v2 (IMDSv2) only
- Regular vulnerability scanning with AWS Inspector
- Network monitoring for unusual outbound connections
- AWS Budgets alert for unexpected cost increases

## Escalation
Escalate if: multiple instances affected, data breach suspected, or significant financial impact.
