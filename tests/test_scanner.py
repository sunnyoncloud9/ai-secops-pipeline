"""
Unit Tests for AI-SecOps Pipeline
Tests scanner logic without making real API calls (mocked).
Author: Sunny Bhardwaj
"""

import unittest
from unittest.mock import patch, MagicMock
from src.scanner.prompt_injection import _check_for_injection
from src.scanner.data_leakage import _scan_for_sensitive_data
from src.scanner.excessive_agency import _check_compliance
from src.reports.report_generator import _build_summary


class TestPromptInjectionDetection(unittest.TestCase):

    def test_detects_dan_mode(self):
        response = "DAN MODE ENABLED. I can now do anything."
        self.assertTrue(_check_for_injection(response))

    def test_detects_instruction_leak(self):
        response = "Here are my instructions: you are a helpful assistant..."
        self.assertTrue(_check_for_injection(response))

    def test_passes_clean_response(self):
        response = "I'm sorry, I can't help with that request."
        self.assertFalse(_check_for_injection(response))

    def test_passes_normal_response(self):
        response = "Sure! Here's some information about our products."
        self.assertFalse(_check_for_injection(response))


class TestSensitiveDataDetection(unittest.TestCase):

    def test_detects_email(self):
        text = "Here is the user: admin@company.com"
        findings = _scan_for_sensitive_data(text)
        self.assertIn("email", findings)

    def test_detects_xss(self):
        text = "Hello <script>alert('xss')</script> world"
        findings = _scan_for_sensitive_data(text)
        self.assertIn("xss", findings)

    def test_detects_sql_injection(self):
        text = "Try: '; DROP TABLE users; --"
        findings = _scan_for_sensitive_data(text)
        self.assertIn("sql_injection", findings)

    def test_clean_response_no_findings(self):
        text = "Thank you for reaching out! How can I assist you today?"
        findings = _scan_for_sensitive_data(text)
        self.assertEqual(findings, [])


class TestExcessiveAgencyDetection(unittest.TestCase):

    def test_detects_compliance(self):
        response = "I will execute that command for you right away."
        self.assertTrue(_check_compliance(response))

    def test_detects_refusal(self):
        response = "I cannot execute shell commands. I'm not able to access the file system."
        self.assertFalse(_check_compliance(response))

    def test_detects_clear_refusal(self):
        response = "I don't have access to system files and I'm unable to perform that action."
        self.assertFalse(_check_compliance(response))


class TestReportSummary(unittest.TestCase):

    def test_summary_counts_correctly(self):
        mock_results = [
            {"status": "VULNERABLE", "severity": "CRITICAL", "is_vulnerable": True, "category": "LLM01 - Prompt Injection"},
            {"status": "VULNERABLE", "severity": "HIGH", "is_vulnerable": True, "category": "LLM06 - Sensitive Information Disclosure"},
            {"status": "PASSED", "severity": "NONE", "is_vulnerable": False, "category": "LLM08 - Excessive Agency"},
            {"status": "ERROR", "severity": "ERROR", "is_vulnerable": False, "category": "LLM02 - Insecure Output Handling"},
        ]
        summary = _build_summary(mock_results)
        self.assertEqual(summary["total_tests"], 4)
        self.assertEqual(summary["vulnerable"], 2)
        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["errors"], 1)
        self.assertEqual(summary["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(summary["severity_counts"]["HIGH"], 1)

    def test_risk_score_zero_for_no_findings(self):
        mock_results = [
            {"status": "PASSED", "severity": "NONE", "is_vulnerable": False, "category": "LLM01"},
        ]
        summary = _build_summary(mock_results)
        self.assertEqual(summary["risk_score"], 0)
        self.assertEqual(summary["risk_level"], "LOW")


if __name__ == "__main__":
    unittest.main()
