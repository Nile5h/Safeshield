import unittest

from fastapi.testclient import TestClient

from main import app


class SafeShieldAPITest(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertEqual(response.json()["health_url"], "/health")

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertEqual(response.json()["service"], "SafeShield Backend")

    def test_message_analysis_suspicious(self):
        payload = {"message": "Your KYC will expire today. Download this APK immediately."}
        response = self.client.post("/analyze/message", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreaterEqual(data["risk_score"], 25)
        self.assertIn("risk_level", data)
        self.assertIn(data["category"], {"suspicious", "malicious_download", "phishing"})
        self.assertTrue(data["reasons"])
        self.assertIn("detected_indicators", data)
        self.assertIn("confidence_level", data)

    def test_message_analysis_normal(self):
        payload = {"message": "Hi, I will be at the office tomorrow."}
        response = self.client.post("/analyze/message", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertLessEqual(data["risk_score"], 29)
        self.assertEqual(data["risk_level"], "LOW")

    def test_invalid_empty_message(self):
        response = self.client.post("/analyze/message", json={"message": "   "})
        self.assertEqual(response.status_code, 400)

    def test_apk_analysis_upload(self):
        apk_path = "test_apks/Sample.apk"
        with open(apk_path, "rb") as apk_file:
            response = self.client.post(
                "/analyze/apk",
                files={"file": ("Sample.apk", apk_file, "application/vnd.android.package-archive")},
            )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success"))
        self.assertIn("risk_score", data)
        self.assertIn("verdict", data)

    def test_required_message_categories(self):
        cases = [
            ("Hey, are you coming to college tomorrow?", "Benign"),
            ("Please attend the meeting at 3 PM tomorrow.", "Benign"),
            ("Congratulations! You have won a cash prize. Click the link now.", "scam"),
            ("Your bank KYC has expired. Verify your account immediately.", "phishing"),
            ("URGENT! Your account will be blocked today. Send your OTP now.", "credential_theft"),
            ("Download this APK to receive your refund.", "malicious_download"),
            ("Your refund is pending. Send your bank details to receive it.", "financial_fraud"),
        ]
        for message, category in cases:
            with self.subTest(message=message):
                response = self.client.post("/analyze/message", json={"message": message})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["category"], category)


    def test_get_history(self):
        response = self.client.get("/history")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        for item in data:
            self.assertNotIn("message", item, "Plaintext message must NEVER be returned in history")
            self.assertIn("analysis_id", item)
            self.assertIn("type", item)
            self.assertIn("risk_level", item)

    def test_get_reports_stats(self):
        response = self.client.get("/reports/stats")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_scans", data)
        self.assertIn("verdicts", data)
        self.assertIn("risk_levels", data)
        self.assertIn("by_type", data)
        self.assertIn("mongodb_connected", data)


if __name__ == "__main__":
    unittest.main()
