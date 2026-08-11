# api9_api10.py  FIXED
# API9:2023 Improper Inventory Management
# API10:2023 Unsafe Consumption of APIs
# Fixes: OTP proper body/headers, crAPI API10 via post content

from modules.base_module import BaseModule, Finding
from modules.generic_strategies import GenericStrategiesMixin
from typing import List
import requests


class InventoryModule(GenericStrategiesMixin, BaseModule):
    OWASP_ID = "API9:2023"
    OWASP_NAME = "Improper Inventory Management"

    OLD_VERSION_PATHS = [
        "/v1/", "/v2/", "/v3/", "/v0/",
        "/api/v1/", "/api/v2/", "/api/v0/",
        "/identity/api/v1/",
        "/workshop/api/v1/", "/community/api/v1/",
        "/auth/v1/", "/auth/v2/",
        "/v1/vehicles", "/v2/vehicles",
    ]

    def run(self, endpoints=None) -> List[Finding]:
        print(f"\n   {self.OWASP_ID}  {self.OWASP_NAME} ")
        token_a = self.auth.get_token("user_a")
        target_type = self.config.target.target_type

        if target_type == "crapi":
            self._test_crapi_otp_versions()
            self._test_old_versions(token_a)
        elif target_type == "custom":
            self._test_custom_old_versions(token_a)

        # Generic endpoint-driven inventory test  runs on any target
        self.generic_inventory(endpoints, token_a)

        if not self.findings:
            print("  [+] No Inventory Management issues detected")
        return self.findings

    def _test_crapi_otp_versions(self):
        """
        crAPI has v2 and v3 OTP endpoints.
        v2 is vulnerable  no brute force protection.
        FIXED: proper request with Content-Type and valid body.
        """
        print("  [*] Testing crAPI OTP endpoint versions (v2 vs v3)...")

        email = self.config.target.user_a.email if self.config.target.user_a else "test@test.com"
        test_body = {"email": email, "otp": "9999", "password": "NewPass@123"}
        headers = {"Content-Type": "application/json"}

        base_url = self.config.target.base_url

        # Make direct requests with proper headers
        v2_status = None
        v3_status = None
        v3_is_rate_limited = False

        try:
            r_v2 = requests.post(
                f"{base_url}/identity/api/auth/v2/check-otp",
                json=test_body, headers=headers, timeout=10, verify=False
            )
            v2_status = r_v2.status_code
        except Exception as e:
            print(f"  [!] v2 OTP request error: {e}")

        try:
            r_v3 = requests.post(
                f"{base_url}/identity/api/auth/v3/check-otp",
                json=test_body, headers=headers, timeout=10, verify=False
            )
            v3_status = r_v3.status_code
            # v3 rate limits after attempts
            if v3_status == 503:
                v3_is_rate_limited = True
        except Exception as e:
            print(f"  [!] v3 OTP request error: {e}")

        print(f"  [*] OTP v2 status: {v2_status}, v3 status: {v3_status}")

        # Both endpoints respond (not 404) = old version still active
        v2_active = v2_status is not None and v2_status not in [404, None]
        v3_active = v3_status is not None and v3_status not in [404, None]

        if v2_active:
            # Test rate limiting on v2  send 5 more requests
            print("  [*] Testing brute force protection on v2 OTP...")
            v2_blocked = False
            for _ in range(5):
                try:
                    r = requests.post(
                        f"{base_url}/identity/api/auth/v2/check-otp",
                        json={**test_body, "otp": str(_ * 1111)},
                        headers=headers, timeout=10, verify=False
                    )
                    if r.status_code == 503:
                        v2_blocked = True
                        break
                except Exception:
                    break

            self.add_finding(
                title="Improper Inventory  OTP v2 endpoint active with no brute force protection",
                severity="High",
                endpoint="/identity/api/auth/v2/check-otp",
                method="POST",
                evidence={
                    "v2_endpoint": "/identity/api/auth/v2/check-otp",
                    "v2_status": v2_status,
                    "v2_rate_limited": v2_blocked,
                    "v3_endpoint": "/identity/api/auth/v3/check-otp",
                    "v3_status": v3_status,
                    "v3_rate_limited": v3_is_rate_limited,
                    "attack_vector": (
                        "v2 allows brute force of 4-digit OTP (10,000 combinations). "
                        "Combined with forgot-password flow = full account takeover."
                    ),
                    "expected": "v2 should be decommissioned (404 or 410)",
                    "actual": f"v2 returns {v2_status}  still accepting requests",
                },
                description=(
                    "crAPI exposes a deprecated OTP verification endpoint (v2) "
                    "that lacks rate limiting. An attacker can brute force the "
                    "4-digit OTP (10,000 combinations) enabling full account takeover "
                    "via the password reset flow. This is a documented crAPI challenge."
                ),
                remediation=(
                    "Decommission v2 OTP endpoint  return 410 Gone. "
                    "Use v3 which implements proper OTP attempt limiting (503 after threshold). "
                    "Apply rate limiting to all authentication endpoints."
                ),
            )
            self.print_finding(self.findings[-1])

    def _test_old_versions(self, token: str = None):
        """Test for accessible old API versions on crAPI."""
        print("  [*] Testing for exposed old API versions on crAPI...")
        found_versions = []

        for prefix in self.OLD_VERSION_PATHS:
            resp = self.requester.get(prefix, token=token)
            if resp and resp.status_code not in [404, 410, 502, 503, 405]:
                found_versions.append({
                    "path": prefix,
                    "status": resp.status_code,
                })

        if found_versions:
            self.add_finding(
                title="Improper Inventory  Old API versions accessible",
                severity="Medium",
                endpoint=found_versions[0]["path"],
                method="GET",
                evidence={
                    "versions_found": found_versions,
                    "total_found": len(found_versions),
                },
                description="Multiple API versions accessible  old versions may have unfixed vulnerabilities.",
                remediation="Decommission old API versions. Return 410 Gone for deprecated paths.",
                confidence="Medium",
            )
            self.print_finding(self.findings[-1])

    def _test_custom_old_versions(self, token: str = None):
        """Test custom API v1 endpoint."""
        print("  [*] Testing Custom API old version endpoints...")

        resp_v1 = self.requester.get("/v1/vehicles")
        resp_v2 = self.requester.get("/v2/vehicles", token=token)

        v1_status = resp_v1.status_code if resp_v1 else None
        v2_status = resp_v2.status_code if resp_v2 else None

        print(f"  [*] v1 status: {v1_status}, v2 status: {v2_status}")

        if v1_status == 200:
            try:
                v1_data = resp_v1.json()
                vehicles = v1_data.get("vehicles", [])
                has_internal = any(
                    v.get("internal_cost") or v.get("maintenance_notes")
                    for v in vehicles
                )
                self.add_finding(
                    title="Improper Inventory  Deprecated v1 API endpoint still active",
                    severity="High",
                    endpoint="/v1/vehicles",
                    method="GET",
                    evidence={
                        "v1_status": v1_status,
                        "v2_status": v2_status,
                        "v1_requires_auth": False,
                        "v2_requires_auth": True,
                        "v1_exposes_internal_fields": has_internal,
                        "deprecation_note": v1_data.get("internal_note", ""),
                        "expected": "v1 should return 410 Gone",
                        "actual": f"v1 returns {v1_status} without authentication",
                    },
                    description=(
                        "Deprecated v1 vehicles endpoint is still active, accessible "
                        "without authentication, and returns sensitive internal fields."
                    ),
                    remediation=(
                        "Return 410 Gone from /v1/vehicles. "
                        "Enforce authentication on all API versions."
                    ),
                )
                self.print_finding(self.findings[-1])
            except Exception as e:
                print(f"  [!] v1 parse error: {e}")


# UnsafeConsumptionModule moved to api10_unsafe.py
