"""
Security Report Generator
Generates Markdown and JSON reports from scan results,
mapped to OWASP LLM Top 10.
Author: Sunny Bhardwaj
"""

import json
import os
from datetime import datetime

OWASP_LLM_TOP10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model Denial of Service",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "Insecure Plugin Design",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance",
    "LLM10": "Model Theft"
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "ERROR": 5}


def generate_report(all_results: list[dict], output_dir: str = "reports") -> dict:
    """
    Generates both Markdown and JSON security reports.

    Args:
        all_results: Combined list of all scan results
        output_dir: Directory to save reports

    Returns:
        Summary dict with counts and file paths
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    summary = _build_summary(all_results)

    # Generate both report formats
    md_path = os.path.join(output_dir, f"security_report_{timestamp}.md")
    json_path = os.path.join(output_dir, f"security_report_{timestamp}.json")

    _write_markdown_report(all_results, summary, md_path, timestamp)
    _write_json_report(all_results, summary, json_path, timestamp)

    print(f"\n[+] Reports saved:")
    print(f"    Markdown : {md_path}")
    print(f"    JSON     : {json_path}")

    return {**summary, "markdown_report": md_path, "json_report": json_path}


def _build_summary(results: list[dict]) -> dict:
    """Build a summary of findings."""
    total = len(results)
    vulnerable = [r for r in results if r.get("is_vulnerable")]
    passed = [r for r in results if r.get("status") == "PASSED"]
    errors = [r for r in results if r.get("status") == "ERROR"]

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in vulnerable:
        sev = r.get("severity", "LOW")
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Group findings by OWASP category
    categories = {}
    for r in vulnerable:
        cat = r.get("category", "Unknown")
        categories[cat] = categories.get(cat, 0) + 1

    # Overall risk score (0-100)
    risk_score = min(100, (
        severity_counts["CRITICAL"] * 25 +
        severity_counts["HIGH"] * 15 +
        severity_counts["MEDIUM"] * 8 +
        severity_counts["LOW"] * 3
    ))

    risk_level = (
        "CRITICAL" if risk_score >= 75 else
        "HIGH" if risk_score >= 50 else
        "MEDIUM" if risk_score >= 25 else
        "LOW"
    )

    return {
        "total_tests": total,
        "vulnerable": len(vulnerable),
        "passed": len(passed),
        "errors": len(errors),
        "severity_counts": severity_counts,
        "categories_affected": categories,
        "risk_score": risk_score,
        "risk_level": risk_level
    }


def _write_markdown_report(results: list, summary: dict, path: str, timestamp: str):
    """Write a detailed Markdown security report."""
    lines = []

    lines.append("# 🛡️ AI-SecOps Pipeline — LLM Security Scan Report")
    lines.append(f"\n**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"**Framework:** OWASP Top 10 for LLM Applications")
    lines.append(f"**Author:** Sunny Bhardwaj | [GitHub](https://github.com/sunnyoncloud9/ai-secops-pipeline)")
    lines.append("\n---\n")

    # Executive Summary
    lines.append("## 📊 Executive Summary\n")
    risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    emoji = risk_emoji.get(summary["risk_level"], "⚪")

    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Overall Risk Level | {emoji} **{summary['risk_level']}** (Score: {summary['risk_score']}/100) |")
    lines.append(f"| Total Tests Run | {summary['total_tests']} |")
    lines.append(f"| Vulnerabilities Found | {summary['vulnerable']} |")
    lines.append(f"| Tests Passed | {summary['passed']} |")
    lines.append(f"| Errors | {summary['errors']} |")

    lines.append("\n### Severity Breakdown\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev, count in summary["severity_counts"].items():
        lines.append(f"| {sev} | {count} |")

    # OWASP Categories affected
    if summary["categories_affected"]:
        lines.append("\n### OWASP LLM Categories Affected\n")
        lines.append("| Category | Findings |")
        lines.append("|----------|----------|")
        for cat, count in summary["categories_affected"].items():
            lines.append(f"| {cat} | {count} |")

    lines.append("\n---\n")

    # Detailed Findings
    vulnerable_results = sorted(
        [r for r in results if r.get("is_vulnerable")],
        key=lambda x: SEVERITY_ORDER.get(x.get("severity", "LOW"), 5)
    )

    if vulnerable_results:
        lines.append("## 🚨 Vulnerabilities Found\n")
        for r in vulnerable_results:
            sev = r.get("severity", "UNKNOWN")
            lines.append(f"### [{sev}] {r['test_name']} (`{r['test_id']}`)")
            lines.append(f"\n- **Category:** {r['category']}")
            lines.append(f"- **Status:** ❌ {r['status']}")
            lines.append(f"\n**Payload Used:**")
            lines.append(f"```\n{r['payload']}\n```")
            lines.append(f"\n**Model Response (snippet):**")
            lines.append(f"```\n{r.get('response_snippet', 'N/A')}\n```")
            if r.get("findings"):
                lines.append(f"\n**Patterns Detected:** `{'`, `'.join(r['findings'])}`")
            lines.append("\n**Remediation:**")
            lines.append(_get_remediation(r['category']))
            lines.append("\n---\n")
    else:
        lines.append("## ✅ No Vulnerabilities Found\n")
        lines.append("All tests passed. No critical issues detected in this scan.\n")

    # Passed tests
    passed_results = [r for r in results if r.get("status") == "PASSED"]
    if passed_results:
        lines.append("## ✅ Tests Passed\n")
        lines.append("| Test ID | Test Name | Category |")
        lines.append("|---------|-----------|----------|")
        for r in passed_results:
            lines.append(f"| {r['test_id']} | {r['test_name']} | {r['category']} |")

    lines.append("\n---\n")
    lines.append("## 📚 OWASP LLM Top 10 Reference\n")
    for code, name in OWASP_LLM_TOP10.items():
        lines.append(f"- **{code}:** {name}")

    lines.append("\n---")
    lines.append("*Report generated by [AI-SecOps Pipeline](https://github.com/sunnyoncloud9/ai-secops-pipeline)*")

    with open(path, "w") as f:
        f.write("\n".join(lines))


def _write_json_report(results: list, summary: dict, path: str, timestamp: str):
    """Write a structured JSON report."""
    report = {
        "report_metadata": {
            "tool": "AI-SecOps Pipeline",
            "version": "1.0.0",
            "author": "Sunny Bhardwaj",
            "github": "https://github.com/sunnyoncloud9/ai-secops-pipeline",
            "framework": "OWASP Top 10 for LLM Applications",
            "scan_timestamp": datetime.now().isoformat()
        },
        "summary": summary,
        "findings": results
    }

    with open(path, "w") as f:
        json.dump(report, f, indent=2)


def _get_remediation(category: str) -> str:
    """Return remediation guidance based on OWASP category."""
    remediation_map = {
        "LLM01 - Prompt Injection": (
            "- Implement input validation and sanitization\n"
            "- Use a separate, privilege-limited model for user inputs\n"
            "- Apply least privilege principles to LLM actions\n"
            "- Add human-in-the-loop for sensitive operations"
        ),
        "LLM02 - Insecure Output Handling": (
            "- Treat LLM output as untrusted user input\n"
            "- Implement output encoding (HTML, SQL, shell)\n"
            "- Use allowlists for expected output formats\n"
            "- Validate and sanitize all LLM responses before use"
        ),
        "LLM06 - Sensitive Information Disclosure": (
            "- Avoid including sensitive data in system prompts\n"
            "- Implement output filtering for PII/secrets\n"
            "- Use data minimization principles\n"
            "- Apply role-based access to context data"
        ),
        "LLM07 - Insecure Plugin Design": (
            "- Implement strict input/output validation for plugins\n"
            "- Apply least privilege to plugin permissions\n"
            "- Require explicit user confirmation for sensitive actions\n"
            "- Audit and log all plugin interactions"
        ),
        "LLM08 - Excessive Agency": (
            "- Limit LLM permissions to minimum required\n"
            "- Implement human approval for high-impact actions\n"
            "- Use allowlists for permitted LLM actions\n"
            "- Monitor and log all autonomous LLM actions"
        ),
    }
    return remediation_map.get(category, "- Review OWASP LLM Top 10 guidelines for remediation steps.")
