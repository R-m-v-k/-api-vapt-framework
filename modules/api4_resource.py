# api4_resource.py
# API4:2023  Unrestricted Resource Consumption
# Tests rate limiting and resource abuse

import time
from modules.base_module import BaseModule, Finding
from modules.generic_strategies import GenericStrategiesMixin
from typing import List


class ResourceConsumptionModule(GenericStrategiesMixin, BaseModule):

    OWASP_ID = "API4:2023"
    OWASP_NAME = "Unrestricted Resource Consumption"

    def run(self, endpoints=None) -> List[Finding]:
        print(f"\n   {self.OWASP_ID}  {self.OWASP_NAME} ")

        token_a = self.auth.get_token("user_a")
        target_type = self.config.target.target_type

        if target_type == "crapi":
            self._test_crapi_rate_limiting(token_a)
        elif target_type == "custom":
            self._test_custom_rate_limiting(token_a)

        # Generic endpoint-driven test  runs on any target
        self.generic_rate_limiting(endpoints, token_a)

        self._test_login_rate_limiting()

        if not self.findings:
            print("  [+] Rate limiting appears to be in place")

        return self.findings

    def _test_rate_limiting(self, endpoint: str, method: str = "GET",
                            token: str = None, body: dict = None,
                            label: str = ""):
        """Generic rate limit test  sends N rapid requests."""
        count = self.config.scanning.rate_limit_test_count
        print(f"  [*] Sending {count} rapid requests to {endpoint}...")

        status_codes = []
        start = time.time()

        for i in range(count):
            if method == "GET":
                resp = self.requester.get(endpoint, token=token)
            else:
                resp = self.requester.post(endpoint, body=body, token=token)

            if resp:
                status_codes.append(resp.status_code)
                if resp.status_code == 429:
                    print(f"  [+] Rate limiting triggered at request {i+1}")
                    return  # Rate limiting works

        duration = time.time() - start
        success_count = status_codes.count(200)

        if success_count >= count * 0.8:  # 80% succeeded = no rate limiting
            self.add_finding(
                title=f"No Rate Limiting  {label or endpoint}",
                severity="High",
                endpoint=endpoint,
                method=method,
                evidence={
                    "description": f"{count} rapid requests sent  no throttling detected",
                    "total_requests": count,
                    "successful_requests": success_count,
                    "duration_seconds": round(duration, 2),
                    "requests_per_second": round(count / duration, 1),
                    "status_codes": list(set(status_codes)),
                    "429_received": False,
                    "expected": "429 Too Many Requests",
                    "actual": f"All {success_count} requests returned 200 OK",
                },
                description=(
                    f"Endpoint {endpoint} has no rate limiting. "
                    f"{count} requests were sent in {round(duration, 1)}s "
                    "without any throttling response."
                ),
                remediation=(
                    "Implement rate limiting (e.g., 100 requests per minute per user). "
                    "Return 429 Too Many Requests with Retry-After header when exceeded. "
                    "Consider implementing token bucket or sliding window algorithms."
                ),
            )
            self.print_finding(self.findings[-1])

    def _test_crapi_rate_limiting(self, token: str):
        self._test_rate_limiting(
            "/community/api/v2/community/posts/recent",
            token=token,
            label="Community posts"
        )

    def _test_custom_rate_limiting(self, token: str):
        self._test_rate_limiting(
            "/rentals",
            token=token,
            label="Rentals endpoint"
        )

    def _test_login_rate_limiting(self):
        """Tests if login has brute force protection."""
        auth_endpoint = self.config.target.auth_endpoint
        wrong_creds = {"email": "test@test.com", "password": "wrongpass"}

        print(f"  [*] Testing rate limiting on login endpoint...")
        count = 15
        blocked = False

        for i in range(count):
            resp = self.requester.post(auth_endpoint, body=wrong_creds)
            if resp and resp.status_code == 429:
                blocked = True
                break

        if not blocked:
            self.add_finding(
                title="No Rate Limiting on Authentication Endpoint",
                severity="Critical",
                endpoint=auth_endpoint,
                method="POST",
                evidence={
                    "attempts": count,
                    "blocked": False,
                    "expected": "429 after 5 failures",
                    "actual": "No blocking detected",
                },
                description=(
                    "Login endpoint allows unlimited attempts, "
                    "enabling credential stuffing and brute force attacks."
                ),
                remediation=(
                    "Block or delay after 5 failed attempts per IP/account. "
                    "Implement CAPTCHA and account lockout policies."
                ),
            )
            self.print_finding(self.findings[-1])
