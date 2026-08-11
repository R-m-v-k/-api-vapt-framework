# api8_misconfig.py  API8:2023 Security Misconfiguration
import json
from modules.base_module import BaseModule, Finding
from typing import List


class MisconfigModule(BaseModule):
    OWASP_ID = "API8:2023"
    OWASP_NAME = "Security Misconfiguration"

    SENSITIVE_KEYWORDS = [
        "password", "secret", "key", "token", "credential",
        "database", "db_url", "debug", "stack_trace", "traceback",
        "internal", "private", "admin", "root",
    ]

    SECURITY_HEADERS = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-XSS-Protection",
    ]

    DEBUG_PATHS = [
        "/health", "/status", "/debug", "/info",
        "/actuator", "/actuator/health", "/actuator/env",
        "/_debug", "/console", "/phpinfo.php",
    ]

    def run(self, endpoints=None) -> List[Finding]:
        print(f"\n   {self.OWASP_ID}  {self.OWASP_NAME} ")
        token_a = self.auth.get_token("user_a")

        self._test_debug_endpoints()
        self._test_cors(token_a)
        self._test_security_headers()
        self._test_verbose_errors(token_a)

        if not self.findings:
            print("  [+] No Security Misconfiguration vulnerabilities detected")
        return self.findings

    def _test_debug_endpoints(self):
        print("  [*] Testing for exposed debug/info endpoints...")
        for path in self.DEBUG_PATHS:
            resp = self.requester.get(path)
            if not resp or resp.status_code != 200:
                continue

            #  SPA-fallback / content-type gate 
            # Many apps (React/Vue/Express SPAs) return HTTP 200 with the
            # frontend index.html for any unknown path. Scanning that HTML for
            # words like "debug"/"secret" yields a false positive on every probe.
            # A genuine exposed debug/config endpoint returns JSON, not a web page.
            ctype = (resp.headers.get("Content-Type", "") or "").lower()
            if "text/html" in ctype:
                continue  # SPA fallback page  not a real debug endpoint
            body = resp.text or ""
            stripped = body.lstrip()
            if stripped[:15].lower().startswith("<!doctype") or stripped[:6].lower().startswith("<html"):
                continue  # HTML document  reject
            # Require the response to actually parse as JSON before we trust it.
            try:
                data = resp.json()
            except Exception:
                continue
            if not data:
                continue

            # Only match sensitive keywords against the JSON payload, and require
            # a keyword that implies real config exposure (not just the word
            # "status" that a health check legitimately returns).
            resp_text = json.dumps(data).lower()
            found = [k for k in self.SENSITIVE_KEYWORDS if k in resp_text]
            # Guard against health endpoints that merely say {"status":"ok"}:
            trivial = {"status", "ok", "time", "version", "uptime", "healthy"}
            meaningful = [k for k in found if k not in trivial]
            if meaningful:
                self.add_finding(
                    title=f"Security Misconfiguration  Sensitive data at {path}",
                    severity="Critical",
                    endpoint=path,
                    method="GET",
                    evidence={
                        "path": path,
                        "status_code": resp.status_code,
                        "content_type": ctype,
                        "sensitive_keywords_found": meaningful,
                        "response_preview": body[:400],
                        "auth_required": False,
                        "note": "Confirmed JSON response (not SPA fallback)",
                    },
                    description=(
                        f"Endpoint {path} publicly exposes sensitive configuration "
                        f"data including: {', '.join(meaningful)}"
                    ),
                    remediation=(
                        "Disable or restrict access to debug/health endpoints in production. "
                        "Never expose credentials, secrets, or internal config publicly."
                    ),
                )
                self.print_finding(self.findings[-1])

    def _test_cors(self, token: str = None):
        print("  [*] Testing CORS configuration...")
        resp = self.requester.send(
            "GET", "/",
            headers={"Origin": "https://evil.com"},
            token=token
        )

        if resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                self.add_finding(
                    title="Security Misconfiguration  Wildcard CORS origin",
                    severity="High",
                    endpoint="/",
                    method="GET",
                    evidence={
                        "Access-Control-Allow-Origin": acao,
                        "Access-Control-Allow-Credentials": acac,
                        "origin_sent": "https://evil.com",
                    },
                    description=(
                        "CORS is configured to allow all origins (*).\n"
                        "Any website can make cross-origin requests to this API."
                    ),
                    remediation=(
                        "Restrict CORS to specific trusted origins. "
                        "Never use wildcard (*) with credentials. "
                        "Validate Origin header against an allowlist."
                    ),
                )
                self.print_finding(self.findings[-1])

    def _test_security_headers(self):
        print("  [*] Checking security headers...")
        resp = self.requester.get("/")
        if not resp:
            return

        missing = [h for h in self.SECURITY_HEADERS if h not in resp.headers]
        if missing:
            self.add_finding(
                title="Security Misconfiguration  Missing security headers",
                severity="Medium",
                endpoint="/",
                method="GET",
                evidence={
                    "missing_headers": missing,
                    "present_headers": dict(resp.headers),
                },
                description=f"Security headers missing: {', '.join(missing)}",
                remediation=(
                    "Add all recommended security headers. "
                    "Use helmet.js (Node) or equivalent middleware."
                ),
                confidence="High",
            )
            self.print_finding(self.findings[-1])

    def _test_verbose_errors(self, token: str = None):
        print("  [*] Testing for verbose error messages...")
        # Send malformed request to trigger error
        resp = self.requester.get("/nonexistent-endpoint-xyz-12345")
        if resp and resp.status_code in [404, 500]:
            resp_text = resp.text.lower()
            keywords = ["traceback", "stack trace", "exception", "error at line",
                        "sqlalchemy", "django", "flask", "fastapi", "uvicorn"]
            found = [k for k in keywords if k in resp_text]
            if found:
                self.add_finding(
                    title="Security Misconfiguration  Verbose error messages",
                    severity="Medium",
                    endpoint="/nonexistent-endpoint-xyz",
                    method="GET",
                    evidence={
                        "status_code": resp.status_code,
                        "verbose_indicators": found,
                        "response_preview": resp.text[:300],
                    },
                    description="Error responses reveal internal framework details.",
                    remediation=(
                        "Return generic error messages to clients. "
                        "Log detailed errors server-side only."
                    ),
                )
                self.print_finding(self.findings[-1])
