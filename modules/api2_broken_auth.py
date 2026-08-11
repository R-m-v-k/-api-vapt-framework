# modules/api2_broken_auth.py  GENERALISED v2.1
# API2:2023  Broken Authentication
#
# FIXES in v2.1:
#   - Only flags endpoints that ACTUALLY EXIST on the target
#     (must return 200 + JSON, not HTML 404/redirect)
#   - Skips guessed paths that return 404/301/HTML
#   - Uses discovered endpoints from OpenAPI spec first
#   - Falls back to probing only if spec not available

from modules.base_module import BaseModule, Finding
from typing import List
import base64
import json
import time


class BrokenAuthModule(BaseModule):

    OWASP_ID = "API2:2023"
    OWASP_NAME = "Broken Authentication"

    # Endpoints that should always require auth if they return data
    SENSITIVE_PATHS = [
        "/api/v1/users", "/api/v2/users", "/api/users",
        "/api/v1/profile", "/api/v1/me", "/api/me",
        "/api/v1/dashboard", "/api/dashboard",
        "/api/v1/admin", "/api/admin",
        "/api/v1/orders", "/api/v1/items",
        "/api/v1/documents", "/api/v1/files",
        "/api/v1/customers", "/api/v1/accounts",
        "/api/v1/settings", "/api/v1/config",
        "/identity/api/v2/user/dashboard",
        "/workshop/api/merchant/service_requests",
        "/community/api/v2/community/posts/recent",
        "/api/users", "/api/modules", "/api/attendance",
        "/api/enrollments",
    ]

    # Health/debug endpoints  no auth needed but should not leak secrets
    HEALTH_PATHS = [
        "/api/health", "/health", "/api/v1/health",
        "/api/status", "/api/debug", "/api/info",
        "/actuator/health", "/actuator/env",
    ]

    def run(self, endpoints=None) -> List[Finding]:
        print(f"\n   {self.OWASP_ID}  {self.OWASP_NAME} ")

        # Test 1: Unauthenticated access  only on REAL endpoints
        self._test_unauthenticated_access(endpoints)

        # Test 2: JWT analysis
        token_a = self.auth.get_token("user_a")
        if token_a:
            self._analyse_jwt(token_a)
            self._test_jwt_none_algorithm(token_a, endpoints)

        # Test 3: Brute force protection
        self._test_brute_force()

        # Test 4: User enumeration
        self._test_user_enumeration()

        if not self.findings:
            print("  [+] No Broken Authentication issues detected")

        return self.findings

    def _is_real_api_response(self, resp) -> bool:
        """
        Returns True ONLY if the response is a real JSON API response.
        Rejects:
          - HTML pages (404 pages, login redirects, frontend SPA)
          - Empty responses
          - Plain text
          - XML
        """
        if not resp:
            return False
        if resp.status_code != 200:
            return False
        if not resp.text or len(resp.text.strip()) == 0:
            return False

        content_type = resp.headers.get("Content-Type", "").lower()

        # HTML = definitely not an API endpoint -> skip
        if "text/html" in content_type:
            return False

        # JSON content type -> parse and verify it has data
        if "application/json" in content_type:
            try:
                data = resp.json()
                # Empty object or array = not interesting
                if isinstance(data, dict) and len(data) == 0:
                    return False
                if isinstance(data, list) and len(data) == 0:
                    return False
                return True
            except Exception:
                return False

        # No content type header -> try JSON parse
        try:
            data = resp.json()
            if isinstance(data, (dict, list)) and data:
                return True
        except Exception:
            pass

        return False

    def _test_unauthenticated_access(self, endpoints=None):
        """
        Tests endpoints WITHOUT authentication token.
        Only flags endpoints that:
          1. Actually exist (not 404)
          2. Return real JSON data (not HTML pages)
          3. Are not legitimately public (login, health)
        """
        print("  [*] Testing unauthenticated endpoint access...")

        test_paths = []

        # PRIORITY 1: Use OpenAPI spec-discovered endpoints
        # These are REAL endpoints on the target  no guessing
        if endpoints:
            for ep in endpoints:
                path = ep.get("path", "")
                method = ep.get("method", "GET")
                if method == "GET" and path:
                    test_paths.append(path)
            if test_paths:
                print(f"  [*] Testing {len(test_paths)} spec-discovered endpoints...")
            else:
                print("  [*] No spec found  probing known sensitive paths only...")

        # PRIORITY 2: Only add sensitive paths if no spec found
        # Do not add /v1/, /v2/, /v3/ variations blindly
        if not test_paths:
            test_paths.extend(self.SENSITIVE_PATHS)

        # Always check health endpoints regardless
        test_paths.extend(self.HEALTH_PATHS)

        # Deduplicate
        test_paths = list(dict.fromkeys(test_paths))

        # Paths that are legitimately public  skip
        skip_paths = {
            "/api/auth/login", "/auth/login", "/login", "/signin",
            "/api/auth/register", "/register", "/api/auth/token",
            "/api/health", "/health", "/api/status", "/status",
        }

        found_unauth = []

        for path in test_paths:
            # Skip login/register/public endpoints
            if path.lower().rstrip("/") in {p.lower() for p in skip_paths}:
                continue

            resp = self.requester.get(path, token=None)

            # Must get 200 + real JSON  not HTML 404
            if not self._is_real_api_response(resp):
                continue

            # Real finding  this endpoint returns JSON data without auth
            try:
                data = resp.json()
                sensitive = self._find_sensitive_fields(data)
            except Exception:
                sensitive = []

            found_unauth.append({
                "path": path,
                "status": resp.status_code,
                "sensitive_fields": sensitive,
                "response_size": len(resp.text),
                "content_type": resp.headers.get("Content-Type", ""),
            })
            print(f"  * No auth required: GET {path} -> {resp.status_code}")

        for ep in found_unauth:
            self.add_finding(
                title=f"Broken Auth  {ep['path']} returns data without authentication",
                severity="Critical",
                endpoint=ep["path"],
                method="GET",
                evidence={
                    "authentication_header": "ABSENT",
                    "response_status": ep["status"],
                    "content_type": ep["content_type"],
                    "expected": "401 Unauthorized",
                    "actual": f"{ep['status']} OK  JSON data returned without token",
                    "sensitive_fields_in_response": ep.get("sensitive_fields", []),
                    "response_size_bytes": ep.get("response_size", 0),
                    "note": "Confirmed real endpoint  not a guessed path",
                },
                description=(
                    f"Endpoint {ep['path']} returns data to unauthenticated requests. "
                    f"No Authorization header required. "
                    f"T-Mobile 2023 breach pattern: unauthenticated endpoints exposed "
                    f"37 million customer records."
                ),
                remediation=(
                    "Add authentication middleware to this endpoint. "
                    "Return HTTP 401 for all requests without a valid token."
                ),
            )
            self.print_finding(self.findings[-1])

        # Also check health endpoints for secret leakage
        self._test_health_endpoint_leakage()

        if not found_unauth:
            print("  [+] All tested endpoints require authentication")

    def _test_health_endpoint_leakage(self):
        """Check if health endpoint leaks internal info (API8-adjacent)."""
        for path in self.HEALTH_PATHS:
            resp = self.requester.get(path, token=None)
            if not resp or resp.status_code != 200:
                continue
            try:
                data = resp.json()
                text = json.dumps(data).lower()
                secrets = ["password", "secret", "key", "database", "db_url",
                          "redis", "jwt_secret", "api_key", "token"]
                found = [s for s in secrets if s in text]
                if found:
                    self.add_finding(
                        title=f"Broken Auth / Misconfig  {path} exposes credentials without auth",
                        severity="Critical",
                        endpoint=path,
                        method="GET",
                        evidence={
                            "auth_required": False,
                            "sensitive_keywords_found": found,
                            "response_preview": str(data)[:300],
                            "expected": "Either 401 or {status: ok} only",
                            "actual": f"Credentials/config exposed: {found}",
                        },
                        description=f"Health endpoint {path} exposes internal credentials without authentication.",
                        remediation="Remove all sensitive data from health endpoints. Return only {status: ok}.",
                    )
                    self.print_finding(self.findings[-1])
            except Exception:
                continue

    def _find_sensitive_fields(self, data) -> list:
        keywords = ["password", "pin", "secret", "token", "key", "ssn",
                   "credit", "phone", "email", "address", "dob", "birth",
                   "account", "balance", "salary", "private"]
        found = []
        def search(obj, depth=0):
            if depth > 3:
                return
            if isinstance(obj, dict):
                for k in obj.keys():
                    if any(kw in k.lower() for kw in keywords):
                        found.append(k)
                    search(obj[k], depth + 1)
            elif isinstance(obj, list):
                for item in obj[:2]:
                    search(item, depth + 1)
        search(data)
        return list(set(found))

    def _analyse_jwt(self, token: str):
        print("  [*] Analysing JWT token structure...")
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            def decode_b64(p):
                p += "=" * (4 - len(p) % 4)
                return json.loads(base64.urlsafe_b64decode(p))

            header = decode_b64(parts[0])
            payload = decode_b64(parts[1])
            alg = header.get("alg", "")

            if alg.lower() == "none":
                self.add_finding(
                    title="Broken Auth  JWT uses 'none' algorithm",
                    severity="Critical",
                    endpoint=self.config.target.auth_endpoint,
                    method="POST",
                    evidence={"jwt_header": header, "algorithm": alg},
                    description="JWT signed with 'none'  no signature validation.",
                    remediation="Reject 'none' algorithm. Use RS256 or HS256.",
                )
                self.print_finding(self.findings[-1])

            if "exp" not in payload:
                self.add_finding(
                    title="Broken Auth  JWT has no expiry claim",
                    severity="High",
                    endpoint=self.config.target.auth_endpoint,
                    method="POST",
                    evidence={"jwt_payload_keys": list(payload.keys()), "missing": "exp"},
                    description="JWT tokens never expire  stolen tokens valid forever.",
                    remediation="Add exp claim. Set expiry to 15-60 minutes.",
                )
                self.print_finding(self.findings[-1])

            if "sub" not in payload and "user_id" not in payload and "id" not in payload and "userId" not in payload:
                self.add_finding(
                    title="Broken Auth  JWT missing subject claim",
                    severity="Medium",
                    endpoint=self.config.target.auth_endpoint,
                    method="POST",
                    evidence={"jwt_payload_keys": list(payload.keys())},
                    description="JWT missing subject (sub) claim  user identity unclear.",
                    remediation="Include sub claim with user identifier.",
                )
                self.print_finding(self.findings[-1])

        except Exception as e:
            print(f"  [!] JWT analysis error: {e}")

    def _test_jwt_none_algorithm(self, token: str, endpoints=None):
        """Test if API accepts a forged JWT with 'none' algorithm."""
        print("  [*] Testing JWT 'none' algorithm attack...")
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            header_none = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            none_token = f"{header_none}.{parts[1]}."

            # Use discovered endpoints first, then fall back to known paths
            test_paths = []
            if endpoints:
                test_paths = [ep.get("path","") for ep in endpoints
                             if ep.get("method","GET") == "GET"
                             and ep.get("path","") not in ["/", ""]][:5]

            if not test_paths:
                test_paths = [
                    "/api/v1/users", "/api/v1/me", "/api/me",
                    "/identity/api/v2/user/dashboard",
                    "/api/users", "/api/modules",
                ]

            for path in test_paths:
                resp = self.requester.get(path, token=none_token)
                if resp and resp.status_code == 200 and self._is_real_api_response(resp):
                    self.add_finding(
                        title="Broken Auth  JWT 'None' Algorithm Attack Successful",
                        severity="Critical",
                        endpoint=path,
                        method="GET",
                        evidence={
                            "attack": "JWT none algorithm",
                            "forged_token_prefix": header_none[:20] + "...",
                            "response_status": resp.status_code,
                            "expected": "401 Unauthorized",
                            "actual": f"{resp.status_code} OK  forged token accepted",
                        },
                        description="API accepts JWT with 'none' algorithm  signature bypassed.",
                        remediation="Whitelist allowed algorithms. Reject 'none'.",
                    )
                    self.print_finding(self.findings[-1])
                    return

        except Exception as e:
            print(f"  [!] JWT none test error: {e}")

    def _test_brute_force(self):
        """Test login endpoint for rate limiting."""
        print("  [*] Testing brute force protection on login endpoint...")
        auth_ep = self.config.target.auth_endpoint
        user_id = (self.config.target.user_a.email
                  if self.config.target.user_a else "test@test.com")
        role_val = (self.config.target.user_a.role
                   if self.config.target.user_a else "user")
        template = self.config.target.auth_body_template

        blocked = False
        for i in range(10):
            try:
                body_str = template \
                    .replace("{email}", user_id) \
                    .replace("{username}", user_id) \
                    .replace("{password}", f"wrongpass{i}") \
                    .replace("{role}", role_val)
                body = json.loads(body_str)
            except Exception:
                body = {"email": user_id, "password": f"wrongpass{i}"}

            resp = self.requester.post(auth_ep, body=body)
            if resp and resp.status_code == 429:
                blocked = True
                print(f"  [+] Rate limiting triggered at attempt {i+1}")
                break

        if not blocked:
            self.add_finding(
                title="Broken Auth  No brute force protection on login",
                severity="High",
                endpoint=auth_ep,
                method="POST",
                evidence={
                    "attempts_made": 10,
                    "blocked": False,
                    "expected": "429 Too Many Requests after ~5 failures",
                    "actual": "All 10 requests processed without throttling",
                },
                description="Login allows unlimited failed attempts  credential stuffing possible.",
                remediation="Rate limit: block after 5 failures per IP. Add exponential backoff.",
            )
            self.print_finding(self.findings[-1])

    def _test_user_enumeration(self):
        """Test for different error messages revealing user existence."""
        print("  [*] Testing for user enumeration via error messages...")
        auth_ep = self.config.target.auth_endpoint
        user_id = (self.config.target.user_a.email
                  if self.config.target.user_a else "test@test.com")
        role_val = (self.config.target.user_a.role
                   if self.config.target.user_a else "user")
        template = self.config.target.auth_body_template

        def make_body(uid, pwd):
            try:
                s = template \
                    .replace("{email}", uid).replace("{username}", uid) \
                    .replace("{password}", pwd).replace("{role}", role_val)
                return json.loads(s)
            except Exception:
                return {"email": uid, "password": pwd}

        r1 = self.requester.post(auth_ep, body=make_body("xyz_nonexistent_abc123", "WrongPass"))
        r2 = self.requester.post(auth_ep, body=make_body(user_id, "DefinitelyWrong999"))

        if r1 and r2:
            status_diff = r1.status_code != r2.status_code
            msg1, msg2 = "", ""
            try:
                msg1 = str(r1.json())[:100]
                msg2 = str(r2.json())[:100]
            except Exception:
                pass
            msg_diff = msg1 != msg2

            if status_diff or msg_diff:
                self.add_finding(
                    title="Broken Auth  User enumeration via different error messages",
                    severity="Medium",
                    endpoint=auth_ep,
                    method="POST",
                    evidence={
                        "nonexistent_status": r1.status_code,
                        "nonexistent_response": msg1,
                        "valid_email_wrong_pass_status": r2.status_code,
                        "valid_email_wrong_pass_response": msg2,
                        "different_status_codes": status_diff,
                        "different_messages": msg_diff,
                    },
                    description="Login returns different responses for nonexistent vs wrong-password, enabling email enumeration.",
                    remediation="Return identical 401 for ALL login failures.",
                )
                self.print_finding(self.findings[-1])
