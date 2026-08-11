# validation/breach_scenarios.py
# Facebook 2021 and T-Mobile 2023 breach replica validation

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import requests
import json
import time
from typing import Dict, List


class BreachValidator:
    """
    Validates framework against real-world breach patterns.
    Tests replica APIs that mimic Facebook 2021 and T-Mobile 2023.
    """

    def __init__(self, base_url: str = "http://localhost:9000",
                 token_header: str = "Authorization", token_prefix: str = "Bearer"):
        self.base_url = base_url
        self.token_header = token_header or "Authorization"
        self.token_prefix = token_prefix if token_prefix is not None else "Bearer"
        self.results = []

    def _auth(self, token):
        from core.auth_handler import build_token_header
        return build_token_header(token, self.token_header, self.token_prefix)

    def _post(self, endpoint: str, body: dict, token: str = None) -> requests.Response:
        headers = {"Content-Type": "application/json"}
        if token:
            headers.update(self._auth(token))
        try:
            return requests.post(
                self.base_url + endpoint, json=body,
                headers=headers, timeout=10, verify=False
            )
        except Exception:
            return None

    def _get(self, endpoint: str, token: str = None) -> requests.Response:
        headers = {"Content-Type": "application/json"}
        if token:
            headers.update(self._auth(token))
        try:
            return requests.get(
                self.base_url + endpoint,
                headers=headers, timeout=10, verify=False
            )
        except Exception:
            return None

    def _login(self, email: str, password: str) -> str:
        resp = self._post("/auth/login", {"email": email, "password": password})
        if resp and resp.status_code == 200:
            return resp.json().get("token")
        return None

    def validate_facebook_2021(self) -> Dict:
        """
        Facebook 2021  BOLA via phone number lookup API
        533 million users scraped via contact importer
        Maps to: API1:2023 BOLA + API4:2023 Rate Limiting
        """
        print("\n   BREACH VALIDATION: Facebook 2021 ")
        print("  [*] Pattern: BOLA via bulk contact lookup (API1 + API4)")

        result = {
            "breach": "Facebook 2021",
            "owasp_ids": ["API1:2023", "API4:2023"],
            "description": "533M users scraped via BOLA in phone number lookup API",
            "tests": [],
            "detected": False,
        }

        # Login as Bob (User B)
        token_b = self._login("bob@test.com", "password123")
        if not token_b:
            result["error"] = "Could not authenticate"
            return result

        # Test 1: Bob accesses Alice's vehicle (BOLA pattern)
        resp = self._get("/vehicles/1", token=token_b)
        test1 = {
            "test": "Cross-user object access (BOLA)",
            "endpoint": "GET /vehicles/1",
            "token": "User B (Bob)",
            "expected": "403 Forbidden",
            "actual": resp.status_code if resp else "No response",
            "vulnerable": resp and resp.status_code == 200,
        }
        result["tests"].append(test1)
        print(f"  [*] BOLA test: {test1['actual']} (expected 403)")

        # Test 2: Bulk access simulation (rate limit)
        print("  [*] Simulating bulk scraping (rate limit test)...")
        successes = 0
        for i in range(20):
            r = self._get("/vehicles/1", token=token_b)
            if r and r.status_code == 200:
                successes += 1

        test2 = {
            "test": "Bulk request rate limiting",
            "requests_sent": 20,
            "successful": successes,
            "expected": "429 after threshold",
            "actual": f"{successes}/20 succeeded",
            "vulnerable": successes >= 18,
        }
        result["tests"].append(test2)
        print(f"  [*] Rate limit test: {successes}/20 requests succeeded")

        result["detected"] = any(t["vulnerable"] for t in result["tests"])
        status = "[OK] DETECTED" if result["detected"] else "[X] NOT DETECTED"
        print(f"  [{status}] Facebook 2021 pattern {'DETECTED' if result['detected'] else 'NOT DETECTED'}")

        return result

    def validate_tmobile_2023(self) -> Dict:
        """
        T-Mobile 2023  Broken Authentication on customer API
        $350M FCC settlement  unauthenticated API endpoint
        Maps to: API2:2023 Broken Auth + API8:2023 Misconfiguration
        """
        print("\n   BREACH VALIDATION: T-Mobile 2023 ")
        print("  [*] Pattern: Unauthenticated endpoint + misconfiguration (API2 + API8)")

        result = {
            "breach": "T-Mobile 2023",
            "owasp_ids": ["API2:2023", "API8:2023"],
            "description": "Customer data exposed via unauthenticated API endpoint",
            "tests": [],
            "detected": False,
        }

        # Test 1: Access health/config without auth (T-Mobile pattern)
        resp = self._get("/health")
        sensitive_keywords = ["password", "secret", "database", "key", "debug"]
        resp_text = resp.text.lower() if resp else ""
        found_sensitive = [k for k in sensitive_keywords if k in resp_text]

        test1 = {
            "test": "Unauthenticated access to sensitive endpoint",
            "endpoint": "GET /health",
            "auth_required": False,
            "response_status": resp.status_code if resp else None,
            "sensitive_data_exposed": found_sensitive,
            "vulnerable": resp and resp.status_code == 200 and len(found_sensitive) > 0,
        }
        result["tests"].append(test1)
        print(f"  [*] Auth test: HTTP {test1['response_status']}  sensitive fields: {found_sensitive}")

        # Test 2: Admin endpoint without admin role
        token_user = self._login("alice@test.com", "password123")
        resp2 = self._get("/admin/users", token=token_user)

        test2 = {
            "test": "Privilege escalation to admin endpoint",
            "endpoint": "GET /admin/users",
            "token": "Regular user token",
            "expected": "403 Forbidden",
            "actual": resp2.status_code if resp2 else "No response",
            "vulnerable": resp2 and resp2.status_code == 200,
        }
        result["tests"].append(test2)
        print(f"  [*] BFLA test: HTTP {test2['actual']} (expected 403)")

        result["detected"] = any(t["vulnerable"] for t in result["tests"])
        status = "[OK] DETECTED" if result["detected"] else "[X] NOT DETECTED"
        print(f"  [{status}] T-Mobile 2023 pattern {'DETECTED' if result['detected'] else 'NOT DETECTED'}")

        return result

    def run_all(self) -> List[Dict]:
        print("\n" + "="*60)
        print("  BREACH SCENARIO VALIDATION")
        print("="*60)

        fb_result = self.validate_facebook_2021()
        tm_result = self.validate_tmobile_2023()

        self.results = [fb_result, tm_result]

        # Summary
        detected = sum(1 for r in self.results if r["detected"])
        print(f"\n  Breach Scenarios Detected: {detected}/{len(self.results)}")

        return self.results
