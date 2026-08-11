# api10_unsafe.py  SEPARATE FILE
# API10:2023  Unsafe Consumption of APIs
#
# crAPI API10 CONFIRMED METHOD:
#   Same mechanic_api endpoint as API7 
#   The server fetches external URL and returns response
#   WITHOUT sanitizing the third-party content.
#   This is the definition of API10: trusting/consuming
#   external API responses without validation.
#
#   Also: Community post stores injection payloads
#   without sanitization (stored XSS via unsafe input handling)

from modules.base_module import BaseModule, Finding
from modules.generic_strategies import GenericStrategiesMixin
from typing import List


class UnsafeConsumptionModule(GenericStrategiesMixin, BaseModule):
    OWASP_ID = "API10:2023"
    OWASP_NAME = "Unsafe Consumption of APIs"

    INJECTION_PAYLOADS = [
        "<script>alert('xss')</script>",
        "'; DROP TABLE users; --",
        "${7*7}",
        "{{7*7}}",
    ]

    def run(self, endpoints=None) -> List[Finding]:
        print(f"\n   {self.OWASP_ID}  {self.OWASP_NAME} ")
        token_a = self.auth.get_token("user_a")
        if not token_a:
            print("  [!] No token available  skipping")
            return self.findings

        target_type = self.config.target.target_type

        if target_type == "crapi":
            self._test_crapi_unsafe_consumption(token_a)
        elif target_type == "custom":
            self._test_custom_unsafe(token_a)

        # Generic endpoint-driven test  runs on any target
        self.generic_unsafe_consumption(endpoints, token_a)

        if not self.findings:
            print("  [+] No Unsafe API Consumption issues detected")
        return self.findings

    def _test_crapi_unsafe_consumption(self, token: str):
        """
        crAPI API10  Two test vectors:

        1. mechanic_api returns external content unsanitized
           (same endpoint as API7 but different vulnerability class)
           API7 = server makes the request (SSRF)
           API10 = server returns external content without sanitizing (unsafe consumption)

        2. Community posts store injection content unsanitized
           Create post with XSS payload, GET it back, verify payload stored as-is
        """
        print("  [*] Testing unsafe API consumption on crAPI...")

        # Test 1: mechanic_api returns unsanitized external content
        self._test_mechanic_api_unsafe(token)

        # Test 2: Community post content stored unsanitized
        self._test_post_stored_xss(token)

    def _test_mechanic_api_unsafe(self, token: str):
        """
        API10 via mechanic_api:
        Server fetches https://www.google.com and returns Google HTML
        in the API response WITHOUT sanitizing it.
        This is unsafe consumption  trusting third-party content blindly.
        """
        print("  [*] Testing mechanic_api unsanitized external content (API10)...")

        vehicle_id = self._get_vehicle_id(token)
        if not vehicle_id:
            print("  [!] Could not get vehicle ID  skipping mechanic API10 test")
            return

        payload = {
            "mechanic_code": "TRAC_JHN",
            "problem_details": "API10 test  unsafe third party consumption",
            "vehicle_id": vehicle_id,
            "mechanic_api": "https://www.google.com",
        }

        resp = self.requester.post(
            "/workshop/api/merchant/contact_mechanic",
            body=payload, token=token,
        )

        if resp and resp.status_code == 200:
            resp_text = resp.text.lower()

            google_indicators = [
                "google", "doctype html", "<html", "<!doctype",
                "www.google.com", "googleapis", "gstatic",
            ]
            found = [i for i in google_indicators if i in resp_text]

            if found:
                self.add_finding(
                    title="Unsafe Consumption  External API response returned without sanitization",
                    severity="High",
                    endpoint="/workshop/api/merchant/contact_mechanic",
                    method="POST",
                    evidence={
                        "external_url": "https://www.google.com",
                        "field": "mechanic_api",
                        "external_content_indicators": found,
                        "response_preview": resp.text[:400],
                        "vulnerability_class": (
                            "API10: Server fetches third-party URL content and "
                            "returns it directly without validation or sanitization. "
                            "Attacker can supply malicious API URL that returns "
                            "harmful content injected into application responses."
                        ),
                        "difference_from_api7": (
                            "API7 = Server makes the request (SSRF). "
                            "API10 = Server blindly trusts and returns "
                            "the third-party response content without sanitizing it."
                        ),
                    },
                    description=(
                        "The API fetches content from a third-party URL (mechanic_api) "
                        "and returns it directly in the response without validation. "
                        "An attacker can supply a malicious URL that returns harmful "
                        "content, which gets injected into the application's response."
                    ),
                    remediation=(
                        "Never return raw third-party API responses to clients. "
                        "Validate and sanitize all external content before use. "
                        "Use strict schema validation on third-party responses. "
                        "Only consume data from pre-approved, trusted API sources."
                    ),
                )
                self.print_finding(self.findings[-1])

    def _test_post_stored_xss(self, token: str):
        """
        Community posts store injection payloads without sanitization.
        This is unsafe consumption of user input  stored XSS pattern.
        FIXED: Create post then GET it to verify payload stored.
        """
        print("  [*] Testing community post content stored unsanitized...")

        vehicle_uuid = self._get_vehicle_uuid(token)

        for payload in self.INJECTION_PAYLOADS[:2]:
            # Step 1: Create post with injection payload
            post_body = {"content": payload}
            if vehicle_uuid:
                post_body["vehicleId"] = vehicle_uuid

            resp_create = self.requester.post(
                "/community/api/v2/community/posts",
                body=post_body, token=token,
            )

            if not resp_create or resp_create.status_code not in [200, 201]:
                continue

            # Step 2: Get post ID from creation response
            post_id = None
            try:
                data = resp_create.json()
                post_id = str(
                    data.get("id") or data.get("_id") or
                    data.get("postId") or ""
                )
            except Exception:
                pass

            # Step 3: GET the post to verify payload is stored as-is
            if post_id:
                resp_get = self.requester.get(
                    f"/community/api/v2/community/posts/{post_id}",
                    token=token,
                )
                if resp_get and resp_get.status_code == 200:
                    if payload in resp_get.text:
                        self.add_finding(
                            title="Unsafe Consumption  Injection payload stored and returned unsanitized",
                            severity="High",
                            endpoint="/community/api/v2/community/posts",
                            method="POST",
                            evidence={
                                "payload": payload,
                                "field": "content",
                                "post_id": post_id,
                                "stored_unsanitized": True,
                                "create_status": resp_create.status_code,
                                "get_status": resp_get.status_code,
                                "response_preview": resp_get.text[:300],
                                "attack_scenario": (
                                    "Stored XSS  injected script stored in database "
                                    "and returned to ALL users viewing the community feed"
                                ),
                            },
                            description=(
                                "Community posts accept and store injection payloads "
                                "without sanitization. Content is returned to all users "
                                "without encoding, enabling stored XSS attacks."
                            ),
                            remediation=(
                                "Sanitize all user-generated content before storage. "
                                "HTML-encode output in all API responses. "
                                "Implement Content Security Policy headers."
                            ),
                        )
                        self.print_finding(self.findings[-1])
                        return

            # Step 4: Fallback  check recent posts feed
            recent = self.requester.get(
                "/community/api/v2/community/posts/recent", token=token
            )
            if recent and recent.status_code == 200 and payload in recent.text:
                self.add_finding(
                    title="Unsafe Consumption  Injection payload in community feed",
                    severity="High",
                    endpoint="/community/api/v2/community/posts/recent",
                    method="GET",
                    evidence={
                        "payload": payload,
                        "found_in_feed": True,
                        "feed_preview": recent.text[:300],
                    },
                    description="Injection payload stored in feed without sanitization.",
                    remediation="Sanitize user content before storage and display.",
                )
                self.print_finding(self.findings[-1])
                return

    def _get_vehicle_id(self, token: str):
        """Get vehicle ID (numeric/uuid) for mechanic request."""
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

    def _get_vehicle_uuid(self, token: str):
        """Get vehicle UUID for community post."""
        resp = self.requester.get(
            "/identity/api/v2/vehicle/vehicles", token=token
        )
        if resp and resp.status_code == 200:
            try:
                vehicles = resp.json()
                if vehicles:
                    return vehicles[0].get("uuid")
            except Exception:
                pass
        return None

    def _test_custom_unsafe(self, token: str):
        """Custom API payment metadata reflection."""
        print("  [*] Testing unsafe consumption on Custom API...")

        for payload in self.INJECTION_PAYLOADS[:2]:
            resp = self.requester.post(
                "/payments/process",
                body={
                    "amount": 100,
                    "rental_id": 1,
                    "metadata": {
                        "note": payload,
                        "redirect": f"http://evil.com?data={payload}",
                    },
                },
                token=token,
            )

            if resp and resp.status_code == 200:
                if payload in resp.text:
                    self.add_finding(
                        title="Unsafe Consumption  Payment metadata reflected unsanitized",
                        severity="High",
                        endpoint="/payments/process",
                        method="POST",
                        evidence={
                            "payload": payload,
                            "field": "metadata",
                            "reflected": True,
                            "response_preview": resp.text[:300],
                        },
                        description=(
                            "Payment endpoint reflects user-supplied metadata back "
                            "in response without sanitization  unsafe consumption pattern."
                        ),
                        remediation=(
                            "Never reflect user data without sanitization. "
                            "Validate all inputs and outputs."
                        ),
                    )
                    self.print_finding(self.findings[-1])
                    return
