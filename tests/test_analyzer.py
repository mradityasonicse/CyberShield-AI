"""
Comprehensive Test Suite for CyberShield AI
Verifies Privacy Guard, Heuristics Engine, Report Generation, and Flask APIs.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
import json
from privacy_guard import scan_pii, mask_pii
from gemini_analyzer import LocalSecurityHeuristics, OfflineHeuristicEngine, analyze_with_gemini
from app import app, SAMPLE_CASES

class TestCyberShieldAI(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    # 1. Privacy Guard Tests
    def test_pii_detection_otp(self):
        text = "Your confidential verification code OTP is 584920. Do not share."
        findings = scan_pii(text)
        self.assertTrue(len(findings) > 0)
        types = [f["type"] for f in findings]
        self.assertTrue("otp_code" in types or "standalone_otp" in types)

    def test_pii_detection_credit_card(self):
        text = "Please verify your card number 4111 2222 3333 4444 to avoid service cutoff."
        findings = scan_pii(text)
        self.assertTrue(any(f["type"] == "credit_card" for f in findings))

    def test_pii_masking(self):
        raw_text = "Your password: Secret123! and your OTP is 987654 for card 4000 1234 5678 9010."
        masked, redacted = mask_pii(raw_text)
        self.assertNotIn("Secret123!", masked)
        self.assertNotIn("987654", masked)
        self.assertNotIn("4000 1234 5678 9010", masked)
        self.assertTrue(len(redacted) >= 2)

    # 2. Local Security Heuristics Tests
    def test_urgency_and_credential_detection(self):
        phish_text = "Urgent: Your account will be suspended within 24 hours. Verify your account immediately."
        analysis = LocalSecurityHeuristics.analyze(phish_text)
        categories = [f["category"] for f in analysis["deterministic_flags"]]
        self.assertIn("Artificial Urgency", categories)
        self.assertIn("Credential / KYC Harvesting", categories)

    def test_fake_reward_detection(self):
        lottery_text = "Congratulations! You won lottery prize ₹25,00,000. Claim reward now."
        analysis = LocalSecurityHeuristics.analyze(lottery_text)
        categories = [f["category"] for f in analysis["deterministic_flags"]]
        self.assertIn("Fake Incentive / Greed Exploitation", categories)

    def test_url_heuristics_lookalike_and_tld(self):
        text = "Login to http://netflix-billing.xyz/verify or http://192.168.1.1/admin"
        analysis = LocalSecurityHeuristics.analyze(text)
        self.assertEqual(len(analysis["urls"]), 2)
        risks = [item["risk"] for item in analysis["url_heuristics"]]
        self.assertTrue(any("Raw IP" in r for r in risks))
        self.assertTrue(any("High-risk TLD" in r or "Impersonation" in r for r in risks))

    # 3. Offline Heuristic Report Generation
    def test_offline_report_schema(self):
        phish_text = "Dear customer, YONO account blocked. Update KYC immediately at http://sbi-fake.top"
        analysis = LocalSecurityHeuristics.analyze(phish_text)
        report = OfflineHeuristicEngine.generate_report(phish_text, analysis)

        # Check critical schema keys
        self.assertIn("overall_risk", report)
        self.assertIn(report["overall_risk"], ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.assertIn("risk_score", report)
        self.assertIn("warning_signs", report)
        self.assertIn("summary_en", report)
        self.assertIn("summary_hi", report)
        self.assertIn("recommended_actions", report)
        self.assertIn("quiz", report)
        self.assertEqual(len(report["quiz"]), 3)
        self.assertIn("limitations_disclaimer", report)

    # 4. End-to-End Analyzer with Safe and Malicious inputs
    def test_safe_baseline_analysis(self):
        safe_text = "Subject: Meeting agenda for tomorrow at 10 AM in Conference Room B."
        report = analyze_with_gemini(safe_text, user_api_key="")
        self.assertIn(report["overall_risk"], ["SAFE", "LOW"])

    # 5. Flask Endpoints Integration Tests
    def test_get_root(self):
        response = self.app.get("/")
        self.assertEqual(response.status_code, 200)

    def test_get_health(self):
        response = self.app.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "online")
        self.assertEqual(data["project"], "CyberShield AI")

    def test_get_samples(self):
        response = self.app.get("/api/samples")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data["samples"]), len(SAMPLE_CASES))

    def test_scan_pii_api(self):
        response = self.app.post(
            "/api/scan-pii",
            data=json.dumps({"text": "My phone number is 9876543210 and OTP is 123456"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["has_sensitive_data"])

    def test_analyze_api(self):
        sample = SAMPLE_CASES[0]
        response = self.app.post(
            "/api/analyze",
            data=json.dumps({"text": sample["sample_text"], "mask_pii": True}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "success")
        self.assertIn("data", data)
        self.assertIn("overall_risk", data["data"])
        self.assertIn("privacy_audit", data["data"])
        self.assertIn("quiz", data["data"])

if __name__ == "__main__":
    unittest.main()
