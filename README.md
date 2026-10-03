# 🛡️ AI-SecOps Pipeline v2.0

> AI-assisted security operations pipeline — ingests AWS security findings (GuardDuty, CloudTrail, Security Hub), triages them with Amazon Bedrock + RAG against security runbooks, and routes each alert through a human-in-the-loop analyst approval step before any action is taken.

[![CI](https://github.com/sunnyoncloud9/ai-secops-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/sunnyoncloud9/ai-secops-pipeline/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Amazon Bedrock](https://img.shields.io/badge/Amazon-Bedrock-orange.svg?logo=amazonaws)](https://aws.amazon.com/bedrock/)
[![OWASP GenAI Top 10 2025](https://img.shields.io/badge/OWASP-GenAI%20Top%2010%202025-orange.svg)](https://genai.owasp.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## ⚡ Quick Start

```bash
git clone https://github.com/sunnyoncloud9/ai-secops-pipeline.git
cd ai-secops-pipeline
pip install -r requirements.txt
cp .env.example .env
# Add AWS credentials to .env
make run
```

Open **http://localhost:8000** — click **+ Ingest Alerts** to pull in simulated GuardDuty/CloudTrail/Security Hub findings and see the full pipeline in action.

---

## 📌 Overview

**AI-SecOps Pipeline v2** is a complete rewrite that transforms a basic LLM scanner into a production-grade AI-assisted security operations system.

**The pipeline:**
1. **Ingests** realistic AWS security findings (GuardDuty, CloudTrail, Security Hub)
2. **Retrieves** relevant runbook sections via RAG (FAISS + sentence transformers)
3. **Triages** each alert using Amazon Bedrock (Claude Sonnet) with the runbook context
4. **Presents** the AI recommendation to a human analyst via a web UI
5. **Executes** only analyst-approved actions (block IP, isolate resource, escalate, suppress)
6. **Logs** every AI decision and analyst action to DynamoDB for audit compliance

The pipeline itself is hardened against the **OWASP GenAI Top 10 2025** — prompt injection prevention, output validation, fail-closed fallback, and system prompt protection are built into every layer.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│   Alert Ingestion Layer                                  │
│   Simulated GuardDuty + CloudTrail + Security Hub       │
│   16 realistic finding types across 3 AWS services      │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│   RAG Engine (FAISS + sentence-transformers)            │
│   Retrieves relevant runbook sections per alert type    │
│   5 runbooks: SSH, IAM, Exfiltration, Mining, General  │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│   Amazon Bedrock — Claude Sonnet                        │
│   Triage with runbook context                           │
│   Returns: risk score, classification, action, reasoning│
│   OWASP GenAI 2025 hardened:                            │
│   ├── LLM01: Prompt injection sanitization              │
│   ├── LLM05: Structured output enforcement              │
│   ├── LLM06: No autonomous actions                      │
│   └── LLM07: System prompt protection                   │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│   Human-in-the-Loop Web UI (FastAPI + HTML)             │
│   Analyst reviews: alert + AI recommendation            │
│   Analyst approves or rejects before any action         │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│   Response Engine                                       │
│   Executes approved actions:                            │
│   BLOCK_IP → AWS Security Group deny rule               │
│   ISOLATE_RESOURCE → EC2 quarantine tag                 │
│   ESCALATE → SNS notification                           │
│   SUPPRESS → Mark false positive                        │
│   MONITOR → Tag for enhanced monitoring                 │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│   Audit Log (DynamoDB)                                  │
│   Immutable record of every AI decision + analyst action│
│   Compliance-ready trail for SOC-2, ISO 27001           │
└─────────────────────────────────────────────────────────┘
```

---

## 🔐 OWASP GenAI Top 10 2025 Coverage

| ID | Vulnerability | Coverage |
|----|--------------|---------|
| LLM01 | Prompt Injection | ✅ Input sanitization removes injection patterns before Bedrock call |
| LLM02 | Sensitive Information Disclosure | ✅ Output validation strips sensitive data patterns |
| LLM03 | Supply Chain | ✅ Dependency audit in CI (pip-audit + Bandit) |
| LLM04 | Data and Model Poisoning | 🔜 Planned — runbook integrity checks |
| LLM05 | Improper Output Handling | ✅ Strict schema enforcement, allow-listed action values |
| LLM06 | Excessive Agency | ✅ Human-in-the-loop required — AI cannot act autonomously |
| LLM07 | System Prompt Leakage | ✅ System prompt never exposed to user inputs or logged |
| LLM08 | Vector and Embedding Weaknesses | 🔜 Planned — FAISS index integrity validation |
| LLM09 | Misinformation | 🔜 Planned — confidence scoring and source attribution |
| LLM10 | Unbounded Consumption | ✅ max_tokens limits, rate limiting, batch size controls |

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | SOC Dashboard |
| GET | `/health` | Health check |
| POST | `/api/ingest?batch_size=N` | Ingest and triage N alerts |
| GET | `/api/alert/{id}` | Alert detail + analyst review UI |
| POST | `/api/alert/{id}/approve` | Approve AI recommendation + execute action |
| POST | `/api/alert/{id}/reject` | Reject as false positive |
| GET | `/audit` | Immutable audit log |
| GET | `/api/audit` | Audit log as JSON |
| GET | `/scanner` | OWASP GenAI Top 10 2025 scanner UI |
| POST | `/api/scanner/run` | Run OWASP scan against a system prompt |
| GET | `/docs` | FastAPI Swagger UI |

---

## 🧩 Alert Types Covered

**GuardDuty:**
- SSH Brute Force (EC2)
- Malicious IP API Calls (IAM)
- Anomalous IAM Behavior
- Cryptocurrency Mining (EC2)
- Unusual S3 Data Access (Exfiltration)
- IAM Privilege Escalation

**CloudTrail:**
- Root Account Usage
- Unauthorized API Calls
- MFA Disabled
- Security Group Modified

**Security Hub:**
- S3 Public Access Enabled
- Unencrypted EBS Volume
- IAM Password Policy Violation
- CloudTrail Not Enabled

---

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| Amazon Bedrock (Claude Sonnet) | AI-powered alert triage |
| FAISS + sentence-transformers | RAG vector store for runbook retrieval |
| FastAPI | REST API + web UI |
| Jinja2 | HTML templates |
| DynamoDB | Immutable audit log |
| AWS Security Groups | IP blocking |
| AWS SNS | Escalation notifications |
| Python 3.11 | Core application |

---

## 📁 Project Structure

```
ai-secops-pipeline/
├── src/
│   ├── ingestion/
│   │   └── alert_generator.py      # Realistic AWS security findings simulation
│   ├── rag/
│   │   └── rag_engine.py           # FAISS vector store + runbook retrieval
│   ├── bedrock/
│   │   └── triage_engine.py        # Amazon Bedrock AI triage (OWASP hardened)
│   ├── hitl/                       # Human-in-the-loop (handled in main.py)
│   ├── response/
│   │   └── response_engine.py      # AWS response actions (IP block, isolate, SNS)
│   ├── audit/
│   │   └── audit_logger.py         # DynamoDB immutable audit trail
│   ├── scanner/
│   │   └── owasp_scanner.py        # OWASP GenAI Top 10 2025 scanner
│   └── main.py                     # FastAPI application
├── runbooks/
│   ├── ssh_brute_force.md
│   ├── iam_compromise.md
│   ├── data_exfiltration.md
│   ├── crypto_mining.md
│   └── general_aws_security.md
├── templates/
│   ├── dashboard.html              # SOC dashboard
│   ├── alert_detail.html           # Human-in-the-loop review UI
│   ├── audit_log.html              # Audit log viewer
│   └── scanner.html                # OWASP scanner UI
├── tests/
│   └── test_pipeline.py            # 21 unit tests (no AWS needed)
├── .github/workflows/ci.yml
├── .env.example
├── Makefile
├── requirements.txt
└── README.md
```

---

## ⚙️ Configuration

```bash
cp .env.example .env
```

Required:
```
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=anthropic.claude-sonnet-4-5-20250929-v1:0
```

Optional (for response actions):
```
SECURITY_GROUP_ID=sg-xxxxxxxxxx     # For IP blocking
SNS_TOPIC_ARN=arn:aws:sns:...       # For escalations
DYNAMODB_TABLE=ai-secops-audit-log  # Auto-created on startup
```

---

## 🔐 Security Notes

- System prompt never logged or exposed to user inputs
- All alert fields sanitized before Bedrock API call
- LLM output validated against strict allow-lists
- AI cannot take autonomous actions — human approval required for every response
- Audit log is append-only (DynamoDB)
- AWS credentials via environment variables — use IAM roles in production

---

## 👤 Author

**Sunny Bhardwaj** — Security Engineer
[github.com/sunnyoncloud9](https://github.com/sunnyoncloud9) • [linkedin.com/in/bhardwajsunny](https://linkedin.com/in/bhardwajsunny)

---

*Part of a multi-phase security engineering portfolio*
