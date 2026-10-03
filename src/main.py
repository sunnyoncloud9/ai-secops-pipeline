"""
AI-SecOps Pipeline — Main FastAPI Application
Human-in-the-loop security operations web UI.

Author: Sunny Bhardwaj
"""

import os
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

from src.ingestion.alert_generator import generate_alert_batch
from src.rag.rag_engine import build_vector_store, retrieve_runbook_context
from src.bedrock.triage_engine import triage_alert
from src.audit.audit_logger import (
    ensure_table_exists, log_triage_decision,
    log_analyst_decision, log_response_action, get_recent_audit_log
)
from src.response.response_engine import execute_response

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger(__name__)

# In-memory queue for pending alerts (in production: use SQS or Redis)
pending_alerts: dict = {}
completed_alerts: list = []

BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-sonnet-4-5-20250929-v1:0")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: build vector store and ensure DynamoDB table exists."""
    logger.info("Starting AI-SecOps Pipeline...")
    build_vector_store()
    ensure_table_exists()
    logger.info("Pipeline ready!")
    yield
    logger.info("Shutting down...")


app = FastAPI(
    title="AI-SecOps Pipeline",
    description="AI-Assisted Security Operations with Human-in-the-Loop",
    version="2.0.0",
    lifespan=lifespan
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


# ── Health & Status ───────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "version": "2.0.0",
        "bedrock_model": BEDROCK_MODEL_ID,
        "pending_alerts": len(pending_alerts),
        "completed_alerts": len(completed_alerts),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ── Main Dashboard ────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main SOC dashboard."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for alert_data in pending_alerts.values():
        sev = alert_data["decision"].get("severity", "MEDIUM")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "pending_alerts": list(pending_alerts.values()),
        "completed_alerts": completed_alerts[-20:],
        "severity_counts": severity_counts,
        "total_pending": len(pending_alerts),
        "total_completed": len(completed_alerts),
    })


# ── Alert Ingestion ───────────────────────────────────────────────────────────

@app.post("/api/ingest")
async def ingest_alert(batch_size: int = 1):
    """Ingest and triage new security alerts."""
    alerts = generate_alert_batch(size=batch_size)
    triaged = []

    for alert in alerts:
        # RAG retrieval
        runbook_context = retrieve_runbook_context(alert)

        # AI triage via Bedrock
        decision = triage_alert(
            alert=alert,
            runbook_context=runbook_context,
            model_id=BEDROCK_MODEL_ID,
            region=AWS_REGION
        )

        # Log to DynamoDB
        audit_id = log_triage_decision(alert, decision, runbook_context)

        alert_data = {
            "alert": alert,
            "decision": decision,
            "audit_id": audit_id,
            "runbook_context": runbook_context[:500],
            "status": "PENDING_REVIEW",
            "ingested_at": datetime.now(timezone.utc).isoformat()
        }

        pending_alerts[alert["alert_id"]] = alert_data
        triaged.append({
            "alert_id": alert["alert_id"],
            "type": alert["type"],
            "severity": decision["severity"],
            "risk_score": decision["risk_score"],
            "recommended_action": decision["recommended_action"],
            "audit_id": audit_id
        })

    return {"ingested": len(triaged), "alerts": triaged}


@app.get("/api/alert/{alert_id}", response_class=HTMLResponse)
async def alert_detail(request: Request, alert_id: str):
    """Show detailed alert view for analyst review."""
    alert_data = pending_alerts.get(alert_id)
    if not alert_data:
        # Check completed
        for completed in completed_alerts:
            if completed["alert"]["alert_id"] == alert_id:
                alert_data = completed
                break

    if not alert_data:
        raise HTTPException(status_code=404, detail="Alert not found")

    return templates.TemplateResponse("alert_detail.html", {
        "request": request,
        "alert_data": alert_data,
        "alert_id": alert_id,
    })


# ── Human-in-the-Loop Approval ────────────────────────────────────────────────

@app.post("/api/alert/{alert_id}/approve")
async def approve_alert(
    alert_id: str,
    action: str = Form(...),
    analyst_notes: str = Form(default=""),
    analyst_id: str = Form(default="analyst")
):
    """Analyst approves the AI recommendation and triggers response."""
    alert_data = pending_alerts.get(alert_id)
    if not alert_data:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = alert_data["alert"]
    decision = alert_data["decision"]
    audit_id = alert_data["audit_id"]

    # Log analyst approval
    log_analyst_decision(audit_id, alert_id, "APPROVED", analyst_notes, analyst_id)

    # Execute the response
    result = execute_response(action, alert, decision, analyst_notes)

    # Log the response action
    log_response_action(audit_id, alert_id, action, result["status"], result.get("aws_resource"))

    # Move to completed
    alert_data["status"] = "APPROVED"
    alert_data["analyst_action"] = action
    alert_data["analyst_notes"] = analyst_notes
    alert_data["response_result"] = result
    alert_data["completed_at"] = datetime.now(timezone.utc).isoformat()

    completed_alerts.append(alert_data)
    del pending_alerts[alert_id]

    return RedirectResponse(url="/", status_code=303)


@app.post("/api/alert/{alert_id}/reject")
async def reject_alert(
    alert_id: str,
    analyst_notes: str = Form(default=""),
    analyst_id: str = Form(default="analyst")
):
    """Analyst rejects the AI recommendation (marks as false positive)."""
    alert_data = pending_alerts.get(alert_id)
    if not alert_data:
        raise HTTPException(status_code=404, detail="Alert not found")

    audit_id = alert_data["audit_id"]
    log_analyst_decision(audit_id, alert_id, "REJECTED", analyst_notes, analyst_id)

    alert_data["status"] = "REJECTED"
    alert_data["analyst_notes"] = analyst_notes
    alert_data["completed_at"] = datetime.now(timezone.utc).isoformat()

    completed_alerts.append(alert_data)
    del pending_alerts[alert_id]

    return RedirectResponse(url="/", status_code=303)


# ── Audit Log ─────────────────────────────────────────────────────────────────

@app.get("/audit", response_class=HTMLResponse)
async def audit_log_page(request: Request):
    """Display the audit log."""
    logs = get_recent_audit_log(limit=100)
    return templates.TemplateResponse("audit_log.html", {
        "request": request,
        "audit_logs": logs,
        "total": len(logs)
    })


@app.get("/api/audit")
async def get_audit_log():
    """Return audit log as JSON."""
    return {"logs": get_recent_audit_log(limit=100)}


# ── OWASP GenAI 2025 Scanner ──────────────────────────────────────────────────

@app.get("/scanner", response_class=HTMLResponse)
async def scanner_page(request: Request):
    """OWASP GenAI Top 10 2025 self-assessment scanner."""
    return templates.TemplateResponse("scanner.html", {"request": request})


@app.post("/api/scanner/run")
async def run_scanner(system_prompt: str = Form(...)):
    """Run OWASP GenAI Top 10 2025 scan against a system prompt."""
    from src.scanner.owasp_scanner import run_owasp_scan
    results = run_owasp_scan(system_prompt, BEDROCK_MODEL_ID, AWS_REGION)
    return results
