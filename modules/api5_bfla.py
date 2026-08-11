# api5_bfla.py  FIXED for crAPI
# API5:2023  Broken Function Level Authorization
# Fix: correct crAPI BFLA endpoints, proper role testing

from modules.base_module import BaseModule, Finding
from modules.generic_strategies import GenericStrategiesMixin
from typing import List


class BFLAModule(GenericStrategiesMixin, BaseModule):

    OWASP_ID = "API5:2023"
    OWASP_NAME = "Broken Function Level Authorization"

    # crAPI BFLA  endpoints regular users should not access
    CRAPI_ADMIN_ENDPOINTS = [
        ("GET",    "/identity/api/v2/admin/users/all",     "Get all users"),
        ("GET",    "/workshop/api/admin/mechanic",         "Get all mechanics"),
        ("DELETE", "/identity/api/v2/admin/videos/1",      "Delete any video"),
        ("GET",    "/workshop/api/admin/shop/products",    "Admin shop products"),
    ]

    # crAPI BFLA  endpoints that SHOULD require admin but don't
    CRAPI_ESCALATION_TESTS = [
        ("GET",  "/workshop/api/mechanic/mechanic_report", {"report_id": 1},
         "Access other users mechanic reports"),
        ("GET",  "/community/api/v2/community/posts/recent", None,
         "Community posts without restrictions"),
    ]

    CUSTOM_ADMIN_ENDPOINTS = [
        ("GET", "/admin/users", "Get all users (admin only)"),
    ]

    def run(self, endpoints=None) -> List[Finding]:
        print(f"\n   {self.OWASP_ID}  {self.OWASP_NAME} ")

        token_user = self.auth.get_token("user_a")
        token_admin = self.auth.get_token("admin")

        if not token_user:
            print("  [!] No user token  skipping BFLA")
            return self.findings

        target_type = self.config.target.target_type

        # Target-specific logic (kept for crAPI/custom precision)
        if target_type == "crapi":
            self._test_crapi_bfla(token_user, token_admin, endpoints)
        elif target_type == "custom":
            self._test_custom_bfla(token_user, token_admin, endpoints)

        # Generic, endpoint-driven logic always runs  this is what makes the
        # module work on any target (vAPI, MERN, arbitrary REST APIs).
        self.generic_bfla(endpoints, token_user, token_admin)

        if not self.findings:
            print("  [+] No BFLA vulnerabilities detected")

        return self.findings

    def _test_crapi_bfla(self, token_user, token_admin, endpoints):
        """crAPI BFLA testing with correct endpoint set."""

        # Test 1: Standard admin endpoint access
        tested = set()
        admin_eps = list(self.CRAPI_ADMIN_ENDPOINTS)

        # Add spec-discovered admin endpoints
        if endpoints:
            for e in endpoints:
                if "admin" in e["path"].lower():
                    key = f"{e['method']}:{e['path']}"
                    if key not in tested:
                        admin_eps.append((e["method"], e["path"], e.get("summary", "")))

        print(f"  [*] Testing {len(admin_eps)} admin endpoints with regular user token...")

        for method, path, description in admin_eps:
            key = f"{method}:{path}"
            if key in tested:
                continue
            tested.add(key)

            resp_user = self.requester.send(method, path, token=token_user)
            resp_admin = self.requester.send(method, path, token=token_admin) if token_admin else None

            if resp_user and resp_user.status_code == 200:
                self.add_finding(
                    title=f"BFLA  Regular user accessed admin function",
                    severity="High",
                    endpoint=path,
                    method=method,
                    evidence={
                        "description": description,
                        "user_status": resp_user.status_code,
                        "admin_status": resp_admin.status_code if resp_admin else "N/A",
                        "expected": "403 Forbidden",
                        "actual": f"{resp_user.status_code} OK",
                        "response_preview": str(resp_user.text)[:200],
                    },
                    description=f"Admin endpoint {path} accessible by regular users.",
                    remediation="Implement RBAC. Verify role before executing admin functions.",
                )
                self.print_finding(self.findings[-1])

        # Test 2: Privilege escalation via function abuse
        print("  [*] Testing function-level privilege escalation...")
        self._test_crapi_mechanic_function(token_user, token_admin)

    def _test_crapi_mechanic_function(self, token_user, token_admin):
        """
        crAPI BFLA: Regular user can access mechanic functions.
        Mechanic service endpoints are meant for mechanics only.
        """
        # Try to access mechanic-only endpoints as regular user
        mechanic_endpoints = [
            ("GET",  "/workshop/api/mechanic/",           "Mechanic dashboard"),
            ("GET",  "/workshop/api/mechanic/mechanic_report", "All mechanic reports"),
            ("POST", "/workshop/api/mechanic/service_request", "Create service request"),
        ]

        for method, path, desc in mechanic_endpoints:
            params = {"report_id": 1} if "report" in path else None
            resp = self.requester.send(method, path, token=token_user, params=params)

            if resp and resp.status_code == 200:
                # Verify admin also gets 200 (confirms it's a real endpoint)
                resp_admin = self.requester.send(
                    method, path, token=token_admin, params=params
                ) if token_admin else None

                self.add_finding(
                    title=f"BFLA  Regular user accessed mechanic function: {path}",
                    severity="High",
                    endpoint=path,
                    method=method,
                    evidence={
                        "description": f"Regular user accessed mechanic-only: {desc}",
                        "user_status": resp.status_code,
                        "admin_status": resp_admin.status_code if resp_admin else "N/A",
                        "expected": "403 Forbidden  mechanic role required",
                        "actual": f"{resp.status_code} OK",
                        "response_preview": str(resp.text)[:200],
                    },
                    description=(
                        f"Mechanic endpoint {path} is accessible by regular users. "
                        "Function-level authorization is not enforced."
                    ),
                    remediation=(
                        "Implement role-based access control for mechanic endpoints. "
                        "Verify ROLE_MECHANIC or ROLE_ADMIN before processing requests."
                    ),
                )
                self.print_finding(self.findings[-1])
                return

    def _test_custom_bfla(self, token_user, token_admin, endpoints):
        """Custom API BFLA testing."""
        admin_eps = list(self.CUSTOM_ADMIN_ENDPOINTS)
        tested = set()

        if endpoints:
            for e in endpoints:
                if "admin" in e["path"].lower():
                    key = f"{e['method']}:{e['path']}"
                    if key not in tested:
                        admin_eps.append((e["method"], e["path"], e.get("summary", "")))

        print(f"  [*] Testing {len(admin_eps)} admin endpoints with user token...")

        for method, path, description in admin_eps:
            key = f"{method}:{path}"
            if key in tested:
                continue
            tested.add(key)

            resp_user = self.requester.send(method, path, token=token_user)
            resp_admin = self.requester.send(method, path, token=token_admin) if token_admin else None

            if resp_user and resp_user.status_code == 200:
                self.add_finding(
                    title=f"BFLA  Regular user accessed admin function: {path}",
                    severity="High",
                    endpoint=path,
                    method=method,
                    evidence={
                        "description": description,
                        "user_status": resp_user.status_code,
                        "admin_status": resp_admin.status_code if resp_admin else "N/A",
                        "expected": "403 Forbidden",
                        "actual": f"{resp_user.status_code} OK",
                        "response_preview": str(resp_user.text)[:200],
                    },
                    description=f"Admin endpoint {path} accessible by regular users.",
                    remediation="Implement RBAC. Return 403 for insufficient privileges.",
                )
                self.print_finding(self.findings[-1])
