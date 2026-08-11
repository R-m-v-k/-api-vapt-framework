# api3_bopla.py
# API3:2023  Broken Object Property Level Authorization
# Tests mass assignment and excessive data exposure

from modules.base_module import BaseModule, Finding
from typing import List


class BOPLAModule(BaseModule):

    OWASP_ID = "API3:2023"
    OWASP_NAME = "Broken Object Property Level Authorization"

    SENSITIVE_FIELDS = [
        "role", "admin", "is_admin", "balance", "credit",
        "credit_card", "password", "internal_cost",
        "maintenance_notes", "available_credit",
    ]


    def _safe_json(self, resp):
        """Safe JSON parse  returns None instead of crashing."""
        if not resp:
            return None
        try:
            if not resp.text or len(resp.text.strip()) == 0:
                return None
            ct = resp.headers.get("Content-Type","")
            if "text/html" in ct:
                return None
            return resp.json()
        except Exception:
            return None

    def run(self, endpoints=None) -> List[Finding]:
        print(f"\n   {self.OWASP_ID}  {self.OWASP_NAME} ")

        token_a = self.auth.get_token("user_a")
        if not token_a:
            print("  [!] No token available  skipping")
            return self.findings

        target_type = self.config.target.target_type

        # Always run generic tests first (works on any API)
        self._test_generic_exposure(token_a, endpoints)
        self._test_generic_mass_assignment(token_a, endpoints)

        # Run target-specific tests if applicable
        if target_type == "crapi":
            self._test_crapi_mass_assignment(token_a)
            self._test_crapi_excessive_exposure(token_a)

        if not self.findings:
            print("  [+] No BOPLA vulnerabilities detected")

        return self.findings

    def _test_generic_exposure(self, token: str, endpoints=None):
        """
        Generic excessive data exposure test  works on any API.
        Checks if authenticated responses contain sensitive fields
        that should not be returned to end users.
        """
        print("  [*] Testing for excessive data exposure...")

        # Build list of GET endpoints to check
        check_paths = []
        if endpoints:
            check_paths = [ep.get("path","") for ep in endpoints
                          if ep.get("method","GET") == "GET"
                          and "{" not in ep.get("path","")
                          and ep.get("path","") not in ["", "/"]][:10]

        if not check_paths:
            # Generic paths to try
            check_paths = [
                "/api/v1/me", "/api/me", "/api/v1/profile",
                "/api/v1/users", "/api/users",
                "/api/modules", "/api/v1/modules",
                "/api/v1/dashboard",
                "/identity/api/v2/user/dashboard",
            ]

        sensitive_keywords = [
            "password", "hash", "salt", "secret", "internal",
            "credit_score", "pin", "ssn", "account_number",
            "private_key", "api_key", "jwt_secret",
        ]

        for path in check_paths:
            resp = self.requester.get(path, token=token)
            data = self._safe_json(resp)
            if not data:
                continue

            data_str = str(data).lower()
            found = [k for k in sensitive_keywords if k in data_str]

            if found:
                self.add_finding(
                    title=f"Excessive Exposure  {path} returns sensitive fields",
                    severity="High",
                    endpoint=path,
                    method="GET",
                    evidence={
                        "sensitive_fields_found": found,
                        "all_keys": list(data.keys()) if isinstance(data, dict) else "list",
                        "note": "Fields present in response that should never be exposed via API",
                    },
                    description=(
                        f"Endpoint {path} returns sensitive internal fields: "
                        f"{', '.join(found)}. These should never be exposed in API responses."
                    ),
                    remediation=(
                        "Define explicit response allowlists. "
                        "Strip sensitive fields before returning data. "
                        "Use separate DTOs for internal vs external representations."
                    ),
                )
                self.print_finding(self.findings[-1])

    def _test_generic_mass_assignment(self, token: str, endpoints=None):
        """
        Generic mass assignment test  works on any API.
        Tries to inject privileged fields into PUT/PATCH requests.
        """
        print("  [*] Testing for mass assignment vulnerabilities...")

        # Find PUT/PATCH endpoints from spec
        update_endpoints = []
        if endpoints:
            update_endpoints = [ep for ep in endpoints
                               if ep.get("method","") in ["PUT","PATCH"]
                               and "auth" not in ep.get("path","").lower()
                               and "login" not in ep.get("path","").lower()][:5]

        if not update_endpoints:
            # Common profile update endpoints
            update_endpoints = [
                {"path": "/api/v1/me", "method": "PUT"},
                {"path": "/api/me", "method": "PUT"},
                {"path": "/api/v1/profile", "method": "PUT"},
                {"path": "/api/auth/me", "method": "PUT"},
            ]

        # Privileged fields to try injecting
        privilege_payload = {
            "role": "admin",
            "isAdmin": True,
            "admin": True,
            "balance": 99999.99,
            "credits": 99999,
            "verified": True,
            "approved": True,
        }

        for ep in update_endpoints:
            path = ep.get("path","") if isinstance(ep, dict) else ep
            method = ep.get("method","PUT") if isinstance(ep, dict) else "PUT"

            resp = self.requester.send(method, path, body=privilege_payload, token=token)
            data = self._safe_json(resp)
            if not data or resp.status_code not in [200, 201]:
                continue

            # Check if any privileged fields were accepted
            accepted = []
            data_str = str(data).lower()
            for field in ["role", "isadmin", "admin", "balance", "verified"]:
                if field in data_str and (
                    '"admin"' in data_str or
                    "99999" in data_str or
                    '"true"' in data_str
                ):
                    accepted.append(field)

            if accepted:
                self.add_finding(
                    title=f"Mass Assignment  Privileged fields accepted at {path}",
                    severity="Critical",
                    endpoint=path,
                    method=method,
                    evidence={
                        "payload_sent": privilege_payload,
                        "fields_possibly_accepted": accepted,
                        "response_status": resp.status_code,
                        "response_preview": str(data)[:200],
                    },
                    description=(
                        f"Update endpoint {path} may accept privileged fields "
                        f"(role, admin, balance)  enabling privilege escalation."
                    ),
                    remediation=(
                        "Whitelist only allowed fields. "
                        "Never allow role/admin/balance via user-facing update endpoints."
                    ),
                )
                self.print_finding(self.findings[-1])

    def _test_crapi_mass_assignment(self, token: str):
        """Test video name update for mass assignment."""
        print("  [*] Testing mass assignment on crAPI...")

        # Get video ID from dashboard first
        dash = self.requester.get("/identity/api/v2/user/dashboard", token=token)
        if not dash or dash.status_code != 200:
            return

        video_id = dash.json().get("video_id", 0)
        if not video_id:
            return

        # Try updating video with extra privileged fields
        payload = {
            "video_name": "test_video",
            "conversion_params": "; ls -la",  # Command injection attempt
            "user_id": 1,
        }

        resp = self.requester.put(
            f"/identity/api/v2/user/videos/{video_id}",
            body=payload,
            token=token,
        )

        if resp and resp.status_code == 200:
            try:
                resp_data = resp.json()
                if resp_data is None: return
            except Exception: return
            # Check if extra fields were accepted
            if "conversion_params" in str(resp_data) or "user_id" in str(resp_data):
                self.add_finding(
                    title="Mass Assignment  Video update accepts extra fields",
                    severity="High",
                    endpoint=f"/identity/api/v2/user/videos/{video_id}",
                    method="PUT",
                    evidence={
                        "payload_sent": payload,
                        "response_status": resp.status_code,
                        "response_preview": str(resp_data)[:300],
                        "extra_fields_accepted": True,
                    },
                    description=(
                        "Video update endpoint accepts additional fields beyond "
                        "video_name, including potentially dangerous conversion_params."
                    ),
                    remediation=(
                        "Implement strict input validation. Only accept whitelisted "
                        "fields. Reject any unexpected properties in the request body."
                    ),
                )
                self.print_finding(self.findings[-1])

    def _test_crapi_excessive_exposure(self, token: str):
        """Check dashboard for excessive data exposure."""
        print("  [*] Testing excessive data exposure on crAPI...")

        resp = self.requester.get("/identity/api/v2/user/dashboard", token=token)
        if not resp or resp.status_code != 200:
            return

        data = self._safe_json(resp)


        if data is None:


            return
        exposed = [f for f in self.SENSITIVE_FIELDS if f in data]

        if "available_credit" in data and "video_id" in data:
            self.add_finding(
                title="Excessive Data Exposure  Dashboard reveals internal fields",
                severity="Medium",
                endpoint="/identity/api/v2/user/dashboard",
                method="GET",
                evidence={
                    "exposed_fields": list(data.keys()),
                    "sensitive_fields_found": exposed,
                    "response_preview": str(data)[:300],
                },
                description=(
                    "Dashboard endpoint returns more data than necessary, "
                    "including internal fields like video_id and available_credit "
                    "that may expose business logic."
                ),
                remediation=(
                    "Return only fields required by the client. "
                    "Use response filtering/serialization to strip internal fields."
                ),
                confidence="Medium",
            )
            self.print_finding(self.findings[-1])

    def _test_custom_mass_assignment(self, token: str):
        """Test custom API mass assignment on user update."""
        print("  [*] Testing mass assignment on Custom API...")

        payload = {
            "name": "Alice Updated",
            "role": "admin",
            "balance": 99999.0,
            "credit_card": "0000000000000000",
        }

        resp = self.requester.put("/users/1", body=payload, token=token)

        if resp and resp.status_code == 200:
            data = self._safe_json(resp)

            if data is None:

                return
            user_data = data.get("user", {})

            if user_data.get("role") == "admin" or user_data.get("balance") == 99999.0:
                # Reset the user back to avoid breaking other tests
                self.requester.put("/users/1",
                    body={"role": "user", "balance": 500.0},
                    token=token)
                self.add_finding(
                    title="Mass Assignment  User role/balance modified via API",
                    severity="Critical",
                    endpoint="/users/1",
                    method="PUT",
                    evidence={
                        "payload_sent": payload,
                        "response_status": resp.status_code,
                        "role_changed": user_data.get("role") == "admin",
                        "balance_changed": user_data.get("balance") == 99999.0,
                        "response_data": user_data,
                    },
                    description=(
                        "User update endpoint accepts privileged fields (role, balance) "
                        "without authorization checks, allowing privilege escalation."
                    ),
                    remediation=(
                        "Whitelist only updateable fields (name, phone). "
                        "Never allow role or balance to be set via user-facing endpoints."
                    ),
                )
                self.print_finding(self.findings[-1])

    def _test_custom_excessive_exposure(self, token: str):
        """Check custom API for excessive data exposure."""
        print("  [*] Testing excessive data exposure on Custom API...")

        resp = self.requester.get("/vehicles/1", token=token)
        if not resp or resp.status_code != 200:
            return

        data = self._safe_json(resp)


        if data is None:


            return
        sensitive_exposed = [f for f in ["internal_cost", "maintenance_notes"] if f in data]

        if sensitive_exposed:
            self.add_finding(
                title="Excessive Data Exposure  Internal vehicle fields exposed",
                severity="High",
                endpoint="/vehicles/1",
                method="GET",
                evidence={
                    "sensitive_fields_exposed": sensitive_exposed,
                    "response_data": data,
                },
                description=(
                    "Vehicle endpoint returns sensitive internal fields "
                    "(internal_cost, maintenance_notes) that should never "
                    "be visible to end users."
                ),
                remediation=(
                    "Filter API responses to exclude internal fields. "
                    "Use separate DTOs for internal and external representations."
                ),
            )
            self.print_finding(self.findings[-1])
