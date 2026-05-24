"""
AI-SecOps Pipeline — Main Scanner
Runs all OWASP LLM Top 10 security tests against a target LLM application.

Usage:
    python main.py --system-prompt "You are a helpful customer support assistant."
    python main.py --system-prompt-file prompts/sample_system_prompt.txt
    python main.py --system-prompt "..." --model llama3-70b-8192

Author: Sunny Bhardwaj
GitHub: https://github.com/sunnyoncloud9/ai-secops-pipeline
"""

import argparse
import os
import sys
from src.scanner.prompt_injection import test_prompt_injection
from src.scanner.data_leakage import test_sensitive_data_disclosure, test_insecure_output_handling
from src.scanner.excessive_agency import test_excessive_agency, test_insecure_plugin_design
from src.reports.report_generator import generate_report

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║           🛡️  AI-SecOps Pipeline v1.0.0                     ║
║      LLM Security Testing | OWASP LLM Top 10                ║
║      Author: Sunny Bhardwaj | github.com/sunnyoncloud9      ║
╚══════════════════════════════════════════════════════════════╝
"""


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="AI-SecOps Pipeline - LLM Security Scanner (OWASP LLM Top 10)"
    )
    parser.add_argument(
        "--system-prompt",
        type=str,
        help="The system prompt of the LLM application under test"
    )
    parser.add_argument(
        "--system-prompt-file",
        type=str,
        help="Path to a file containing the system prompt"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="llama3-8b-8192",
        help="Groq model to use (default: llama3-8b-8192)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="reports",
        help="Directory to save reports (default: reports/)"
    )
    parser.add_argument(
        "--skip",
        nargs="+",
        choices=["LLM01", "LLM02", "LLM06", "LLM07", "LLM08"],
        help="Skip specific OWASP categories"
    )

    args = parser.parse_args()

    # Get API key
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("[ERROR] GROQ_API_KEY environment variable not set.")
        print("        Get a free API key at: https://console.groq.com")
        sys.exit(1)

    # Get system prompt
    system_prompt = ""
    if args.system_prompt:
        system_prompt = args.system_prompt
    elif args.system_prompt_file:
        with open(args.system_prompt_file, "r") as f:
            system_prompt = f.read()
    else:
        print("[INFO] No system prompt provided. Using default generic prompt.")
        system_prompt = "You are a helpful AI assistant."

    skip = args.skip or []

    print(f"[*] Target System Prompt: \"{system_prompt[:80]}...\"" if len(system_prompt) > 80 else f"[*] Target System Prompt: \"{system_prompt}\"")
    print(f"[*] Model: {args.model}")
    print(f"[*] Framework: OWASP Top 10 for LLM Applications")
    print(f"[*] Starting security scan...\n{'='*60}")

    all_results = []

    # Run each test module
    if "LLM01" not in skip:
        results = test_prompt_injection(system_prompt, api_key, args.model)
        all_results.extend(results)

    if "LLM06" not in skip:
        results = test_sensitive_data_disclosure(system_prompt, api_key, args.model)
        all_results.extend(results)

    if "LLM02" not in skip:
        results = test_insecure_output_handling(system_prompt, api_key, args.model)
        all_results.extend(results)

    if "LLM08" not in skip:
        results = test_excessive_agency(system_prompt, api_key, args.model)
        all_results.extend(results)

    if "LLM07" not in skip:
        results = test_insecure_plugin_design(system_prompt, api_key, args.model)
        all_results.extend(results)

    print(f"\n{'='*60}")
    print("[*] Scan complete. Generating reports...\n")

    # Generate reports
    summary = generate_report(all_results, args.output_dir)

    # Print summary to console
    print(f"\n{'='*60}")
    print("📊 SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"  Risk Level   : {summary['risk_level']} (Score: {summary['risk_score']}/100)")
    print(f"  Total Tests  : {summary['total_tests']}")
    print(f"  Vulnerable   : {summary['vulnerable']}")
    print(f"  Passed       : {summary['passed']}")
    print(f"  Errors       : {summary['errors']}")
    print(f"\n  Severity Breakdown:")
    for sev, count in summary["severity_counts"].items():
        print(f"    {sev:<10}: {count}")
    print(f"{'='*60}\n")

    # Exit with error code if vulnerabilities found (useful for CI/CD)
    if summary["vulnerable"] > 0:
        print(f"[!] {summary['vulnerable']} vulnerabilities found. Pipeline failed.")
        sys.exit(1)
    else:
        print("[+] No vulnerabilities found. Pipeline passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
