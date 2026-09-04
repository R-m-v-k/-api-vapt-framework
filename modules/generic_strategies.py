import re
import time
from typing import List, Dict, Optional


# Keyword heuristics  how we recognise the *purpose* of an endpoint from its
# path/params alone, inspired by functionality->vulnerability association
# (Du et al., VOAPI2, USENIX Security 2024). This is what lets detection
# generalise without hardcoding routes.
ADMIN_WORDS   = ["admin", "administrator", "manage", "management", "internal",
                 "backoffice", "root", "superuser", "privileged", "staff"]
WRITE_METHODS = ["POST", "PUT", "PATCH", "DELETE"]
ID_WORDS      = ["id", "uuid", "guid", "pk", "_id", "objectid", "key", "no", "num"]
URL_PARAM_WORDS = ["url", "uri", "link", "src", "href", "callback", "webhook",
                   "redirect", "next", "dest", "target", "fetch", "load",
                   "import", "proxy", "site", "domain", "host", "feed", "endpoint"]
CONSUME_WORDS = ["import", "fetch", "proxy", "external", "integration", "webhook",
                 "callback", "sync", "pull", "consume", "gateway", "payment"]
BUSINESS_WORDS = ["coupon", "promo", "discount", "voucher", "order", "purchase",
                  "checkout", "cart", "payment", "transfer", "redeem", "apply",
                  "booking", "reserve", "vote", "like", "invite"]
VERSION_RE = re.compile(r"/(v\d+|api/v\d+|beta|alpha|test|dev|internal|legacy|old|deprecated)(/|$)", re.I)

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://127.0.0.1:22",                         # internal port
    "http://localhost:80",
    "http://metadata.google.internal/",            # GCP metadata
    "file:///etc/passwd",                          # local file scheme
]


class GenericStrategiesMixin:
    """Mixin of target-agnostic detection strategies. Mixed into each module."""


    def _norm(self, endpoints) -> List[Dict]:
        """Return the endpoint list in a consistent shape (never None)."""
        out = []
        for e in (endpoints or []):
            if not isinstance(e, dict):
                continue
            out.append({
                "path": e.get("path", ""),
                "method": (e.get("method", "GET") or "GET").upper(),
                "path_params": e.get("path_params", []),
                "has_id_param": e.get("has_id_param", False),
                "summary": e.get("summary", ""),
                "requires_auth": e.get("requires_auth", True),
            })
        return out

    def _fill_path(self, path: str, value="1") -> str:
        """Replace {id} / :id / <id> placeholders with a concrete value."""
        p = re.sub(r"\{[^}/]+\}", str(value), path)
        p = re.sub(r":[A-Za-z_][A-Za-z0-9_]*", str(value), p)
        p = re.sub(r"<[^>/]+>", str(value), p)
        return p

    def _looks_admin(self, path: str, summary: str = "") -> bool:
        hay = (path + " " + (summary or "")).lower()
        return any(w in hay for w in ADMIN_WORDS)

    #  API5  Broken Function Level Authorization (generic) 

    def generic_bfla(self, endpoints, token_user, token_admin=None):
        """
        Generic BFLA: any endpoint whose path/summary looks administrative or
        privileged is requested with a NON-privileged user token. If it returns
        2xx to the regular user, that's a function-level authorization failure.
        If an admin token is available, we confirm the endpoint is genuinely
        privileged (admin gets 2xx) to reduce false positives.
        """
        eps = self._norm(endpoints)
        admin_like = [e for e in eps if self._looks_admin(e["path"], e["summary"])]
        if not admin_like:
            print("  [*] Generic BFLA: no admin-like endpoints in discovered set")
            return
        print(f"  [*] Generic BFLA: testing {len(admin_like)} admin-like endpoint(s) with a regular-user token...")
        seen = set()
        for e in admin_like:
            method, path = e["method"], self._fill_path(e["path"])
            key = f"{method}:{path}"
            if key in seen:
                continue
            seen.add(key)

            resp_user = self.requester.send(method, path, token=token_user)
            if not resp_user or resp_user.status_code not in (200, 201, 202, 204):
                continue

            # Optional admin confirmation: is this really a privileged endpoint?
            admin_confirms = True
            if token_admin:
                resp_admin = self.requester.send(method, path, token=token_admin)
                admin_confirms = bool(resp_admin and resp_admin.status_code in (200, 201, 202, 204))

            if admin_confirms:
                self.add_finding(
                    title="BFLA  Regular user invoked privileged function",
                    severity="High",
                    endpoint=path,
                    method=method,
                    evidence={
                        "detection": "generic (keyword-identified admin endpoint)",
                        "matched_on": "path/summary admin keyword",
                        "regular_user": self.config.target.user_a.email,
                        "user_status": resp_user.status_code,
                        "admin_confirmed_privileged": bool(token_admin),
                        "expected": "403 Forbidden for non-admin user",
                        "actual": f"{resp_user.status_code} returned to regular user",
                    },
                    description=(
                        f"The endpoint {method} {path} appears to expose a privileged/"
                        f"administrative function, yet a standard user token receives a "
                        f"successful response. Function-level authorization is not enforced."
                    ),
                    remediation=(
                        "Enforce role/permission checks on privileged endpoints server-side. "
                        "Reject non-privileged callers with HTTP 403 regardless of endpoint knowledge."
                    ),
                    confidence="High" if token_admin else "Medium",
                )
                self.print_finding(self.findings[-1])

    #  API4  Unrestricted Resource Consumption (generic) 

    def generic_rate_limiting(self, endpoints, token, attempts=30):
        """
        Generic rate-limiting: pick a discovered GET list-endpoint (no id param)
        and fire N rapid authenticated requests. If none is throttled (no 429),
        the endpoint lacks resource-consumption controls.
        """
        eps = self._norm(endpoints)
        candidates = [e for e in eps
                      if e["method"] == "GET" and not e["has_id_param"]
                      and not re.search(r"\{|:|<", e["path"])
                      and not self._looks_admin(e["path"], e["summary"])]
        if not candidates:
            # fall back to any GET list endpoint if only admin-like ones exist
            candidates = [e for e in eps
                          if e["method"] == "GET" and not e["has_id_param"]
                          and not re.search(r"\{|:|<", e["path"])]
        if not candidates:
            print("  [*] Generic rate-limit: no suitable list endpoint discovered")
            return
        target = candidates[0]["path"]
        print(f"  [*] Generic rate-limit: sending {attempts} rapid requests to {target}...")
        statuses = []
        for _ in range(attempts):
            r = self.requester.get(target, token=token)
            statuses.append(r.status_code if r else None)
            if r is not None and r.status_code == 429:
                break
        throttled = any(s == 429 for s in statuses)
        completed = sum(1 for s in statuses if s in (200, 201))
        if not throttled and completed >= max(10, attempts // 2):
            self.add_finding(
                title="Unrestricted Resource Consumption  no rate limiting",
                severity="High",
                endpoint=target,
                method="GET",
                evidence={
                    "detection": "generic",
                    "requests_sent": len(statuses),
                    "successful": completed,
                    "any_429": throttled,
                    "expected": "429 Too Many Requests after a threshold",
                    "actual": "all requests completed without throttling",
                },
                description=(
                    f"The endpoint {target} served {completed} rapid requests with no "
                    f"throttling (no HTTP 429). This permits scraping, brute force, and "
                    f"denial-of-service by resource exhaustion."
                ),
                remediation="Apply per-user/per-IP rate limiting at the gateway or middleware.",
                confidence="High",
            )
            self.print_finding(self.findings[-1])

    #  API7  SSRF (generic) 

    def generic_ssrf(self, endpoints, token):
        """
        Generic SSRF: find endpoints whose parameters look like they accept a
        URL, then submit a callback URL WE control (the target's own base URL /
        a known-good internal path). Detection is by confirming the SERVER
        fetched it  evidenced by a success status and/or the fetched content
        being reflected  rather than by expecting cloud-metadata strings, which
        only appear when the scanner host happens to be on that cloud.
        """
        eps = self._norm(endpoints)
        candidates = []
        for e in eps:
            hay = (e["path"] + " " + e["summary"]).lower()
            # Tighter match: the path/summary must actually reference a URL-ish
            # concept, not merely be a write method. This avoids probing dozens
            # of unrelated write endpoints (the "39 endpoints" over-match).
            param_hit = any(w in hay for w in URL_PARAM_WORDS)
            consume_hit = any(w in hay for w in CONSUME_WORDS)
            if param_hit or consume_hit:
                candidates.append(e)
        if not candidates:
            print("  [*] Generic SSRF: no URL-accepting endpoints identified")
            return
        print(f"  [*] Generic SSRF: probing {len(candidates)} URL-accepting endpoint(s) with an internal callback...")

        # A callback the server can reach and that returns a stable marker: the
        # target's OWN base URL is guaranteed reachable from the server itself.
        base = self.requester.base_url.rstrip("/")
        callbacks = [f"{base}/health", f"{base}/api-docs", "http://127.0.0.1:80",
                     "http://169.254.169.254/latest/meta-data/"]
        # field names commonly used for a URL input  tried ONE AT A TIME, because
        # many APIs validate their body schema and reject unexpected extra fields.
        url_fields = ["url", "image_url", "imageUrl", "avatar_url", "avatarUrl",
                      "uri", "link", "src", "href", "webhook", "callback",
                      "import_url", "fetch_url", "remote", "source_url"]

        for e in candidates[:15]:
            method = e["method"] if e["method"] in WRITE_METHODS else "POST"
            path = self._fill_path(e["path"])
            fired = False
            for cb in callbacks[:2]:          # internal callbacks first (deterministic)
                if fired:
                    break
                for field in url_fields:      # ONE field per request
                    body = {field: cb}
                    resp = self.requester.send(method, path, token=token, body=body)
                    if not resp:
                        continue
                    text = ""
                    try:
                        text = resp.text[:3000]
                    except Exception:
                        pass
                    looks_fetched = resp.status_code in (200, 201) and any(
                        m in text.lower() for m in ["fetched_status", "preview",
                                                    "\"status\":\"ok\"", "status\":\"ok",
                                                    "swagger-ui", "content_type",
                                                    "content-type", "fetched"])
                    if looks_fetched:
                        self.add_finding(
                            title="SSRF  server fetched attacker-controlled URL",
                            severity="Critical",
                            endpoint=path,
                            method=method,
                            evidence={
                                "detection": "generic (internal callback fetch confirmed)",
                                "url_field": field,
                                "callback_url": cb,
                                "response_status": resp.status_code,
                                "server_fetch_evidence": text[:300],
                                "expected": "URL validation / deny internal targets",
                                "actual": "server retrieved the supplied internal URL",
                            },
                            description=(
                                f"The endpoint {method} {path} accepted a client-supplied URL "
                                f"in field '{field}' and the server fetched it ({cb}). An attacker "
                                f"can make the server issue requests to internal services (SSRF)."
                            ),
                            remediation=(
                                "Validate and allow-list outbound URLs. Block internal ranges "
                                "(127.0.0.0/8, 169.254.0.0/16, RFC1918) and non-HTTP schemes."
                            ),
                            confidence="High",
                        )
                        self.print_finding(self.findings[-1])
                        fired = True
                        break

    #  API6  Unrestricted Access to Sensitive Business Flows (generic) 

    def generic_business_logic(self, endpoints, token):
        """
        Generic business-flow abuse: find endpoints whose purpose is a sensitive
        business action (coupon/promo/order/payment/vote...) and test two
        classic abuses that need no domain knowledge:
          (a) repeatability  the same action succeeds many times in a row
              (e.g. a coupon/promo that never gets marked redeemed);
          (b) negative-value  numeric fields accept negative quantities/amounts.
        """
        eps = self._norm(endpoints)
        flows = []
        for e in eps:
            hay = (e["path"] + " " + e["summary"]).lower()
            if e["method"] in WRITE_METHODS and any(w in hay for w in BUSINESS_WORDS):
                flows.append(e)
        if not flows:
            print("  [*] Generic business-logic: no sensitive-flow endpoints identified")
            return
        print(f"  [*] Generic business-logic: testing {len(flows)} sensitive-flow endpoint(s)...")

        # Try to discover a real code to reuse (e.g. from a /coupons list endpoint)
        discovered_code = None
        for e in eps:
            if e["method"] == "GET" and "coupon" in e["path"].lower() and not e["has_id_param"]:
                r = self.requester.get(self._fill_path(e["path"]), token=token)
                try:
                    data = r.json() if r else None
                    if isinstance(data, list) and data:
                        discovered_code = (data[0].get("code") or data[0].get("coupon")
                                           or data[0].get("promo_code"))
                except Exception:
                    pass
                if discovered_code:
                    break

        SUCCESS_WORDS = ["applied", "success", "redeemed", "accepted", "ok",
                         "discount", "valid", "added", "created"]

        def _is_success(r):
            if not r or r.status_code not in (200, 201):
                return False
            try:
                t = (r.text or "").lower()
            except Exception:
                return False
            # success if a positive word appears AND no failure word dominates
            fail = any(w in t for w in ["invalid", "expired", "already", "limit",
                                        "denied", "error", "not allowed"])
            return (any(w in t for w in SUCCESS_WORDS)) and not fail

        for e in flows[:6]:
            method = e["method"] if e["method"] in WRITE_METHODS else "POST"
            path = self._fill_path(e["path"])

            # (a) repeatability  reuse the SAME code/action several times
            code_val = discovered_code or "WELCOME10"
            ok = 0
            for _ in range(5):
                r = self.requester.send(method, path, token=token,
                                        body={"code": code_val, "coupon": code_val,
                                              "promo": code_val, "promo_code": code_val,
                                              "quantity": 1, "amount": 1})
                if _is_success(r):
                    ok += 1
            if ok >= 3:
                self.add_finding(
                    title="Business Flow Abuse  repeatable sensitive action",
                    severity="High",
                    endpoint=path,
                    method=method,
                    evidence={
                        "detection": "generic (repeatability test)",
                        "code_used": code_val,
                        "successful_repeats": f"{ok}/5",
                        "expected": "action limited / one-time / idempotent",
                        "actual": f"{ok}/5 repeated submissions accepted",
                    },
                    description=(
                        f"The sensitive business action {method} {path} succeeded {ok}/5 times "
                        f"on repeated submission of the same input, indicating no redemption / "
                        f"idempotency / anti-automation control (e.g. a coupon reusable indefinitely)."
                    ),
                    remediation="Track single-use tokens/redemptions server-side; add anti-automation controls.",
                    confidence="High" if ok >= 4 else "Medium",
                )
                self.print_finding(self.findings[-1])

            # (b) negative-value
            r = self.requester.send(method, path, token=token,
                                    body={"quantity": -5, "amount": -100, "price": -1})
            if r and r.status_code in (200, 201):
                self.add_finding(
                    title="Business Flow Abuse  negative value accepted",
                    severity="High",
                    endpoint=path,
                    method=method,
                    evidence={
                        "detection": "generic (negative-value test)",
                        "response_status": r.status_code,
                        "expected": "reject negative quantity/amount",
                        "actual": "negative value processed",
                    },
                    description=(
                        f"The endpoint {method} {path} accepted a negative quantity/amount, "
                        f"which can invert a business transaction (e.g. a credit instead of a charge)."
                    ),
                    remediation="Validate numeric business inputs server-side; reject non-positive values.",
                    confidence="Medium",
                )
                self.print_finding(self.findings[-1])

    #  API9  Improper Inventory Management (generic) 

    def generic_inventory(self, endpoints, token):
        """
        Generic inventory: from discovered endpoints, detect (a) multiple live
        API versions where an older one behaves differently, and (b) exposed
        documentation/spec endpoints reachable without auth.
        """
        eps = self._norm(endpoints)

        # (a) exposed docs/specs
        doc_paths = ["/swagger-ui", "/swagger", "/api-docs", "/api/docs", "/redoc",
                     "/openapi.json", "/swagger.json", "/v2/api-docs", "/graphql"]
        for dp in doc_paths:
            r = self.requester.get(dp, token=None)  # no auth on purpose
            if r and r.status_code == 200 and len((r.text or "")) > 50:
                self.add_finding(
                    title="Improper Inventory  API documentation exposed without auth",
                    severity="Medium",
                    endpoint=dp,
                    method="GET",
                    evidence={"detection": "generic", "status": r.status_code,
                              "expected": "docs restricted in production",
                              "actual": "documentation publicly reachable"},
                    description=f"API documentation/spec at {dp} is reachable without authentication.",
                    remediation="Restrict or remove documentation endpoints in production.",
                    confidence="Medium",
                )
                self.print_finding(self.findings[-1])
                break

        # (b) versioned duplicates
        versioned = {}
        for e in eps:
            m = VERSION_RE.search(e["path"])
            if m:
                base = VERSION_RE.sub("/", e["path"])
                versioned.setdefault(base, set()).add(m.group(1).lower())
        multi = {b: v for b, v in versioned.items() if len(v) > 1}
        if multi:
            example = next(iter(multi.items()))
            self.add_finding(
                title="Improper Inventory  multiple live API versions",
                severity="Medium",
                endpoint=example[0],
                method="GET",
                evidence={"detection": "generic", "versions_seen": sorted(example[1]),
                          "expected": "deprecated versions retired",
                          "actual": "multiple versions coexist"},
                description=(
                    "Multiple API versions are exposed simultaneously "
                    f"({', '.join(sorted(example[1]))}); older versions often lack the "
                    "security controls of the current one."
                ),
                remediation="Retire deprecated versions; inventory and gate all exposed versions.",
                confidence="Medium",
            )
            self.print_finding(self.findings[-1])
        if not multi:
            print("  [*] Generic inventory: no multi-version pattern in discovered set")

    #  API10  Unsafe Consumption of APIs (generic) 

    def generic_unsafe_consumption(self, endpoints, token):
        """
        Generic unsafe consumption: for endpoints that appear to consume external
        data (import/fetch/webhook/payment/gateway keywords), inject payloads and
        check whether they are reflected/processed unsanitised.
        """
        eps = self._norm(endpoints)
        candidates = [e for e in eps
                      if e["method"] in WRITE_METHODS
                      and any(w in (e["path"] + " " + e["summary"]).lower()
                              for w in CONSUME_WORDS)]
        if not candidates:
            print("  [*] Generic unsafe-consumption: no external-data endpoints identified")
            return
        print(f"  [*] Generic unsafe-consumption: testing {len(candidates)} endpoint(s)...")
        # A neutral, unlikely-to-be-stripped marker. Apps often sanitise <script>
        # but reflect other tags/strings verbatim, so we use a distinctive token
        # plus a benign HTML tag to catch unescaped reflection.
        marker = "ASTRA_RFL_7Q2<b>x</b>"
        payloads = {"message": marker, "data": marker, "value": marker,
                    "response": marker, "callback": marker, "result": marker,
                    "name": marker, "rider_name": marker, "status": "delivered",
                    "note": marker, "comment": marker}
        for e in candidates[:8]:
            method = e["method"] if e["method"] in WRITE_METHODS else "POST"
            path = self._fill_path(e["path"])
            resp = self.requester.send(method, path, token=token, body=payloads)
            if not resp:
                continue
            text = ""
            try:
                text = resp.text
            except Exception:
                pass
            # Reflected if our marker token comes back (escaped or not); flag as
            # unsafe if the raw tag survived (no output encoding).
            if resp.status_code in (200, 201) and "ASTRA_RFL_7Q2" in (text or ""):
                raw_tag_reflected = "<b>x</b>" in text
                self.add_finding(
                    title="Unsafe Consumption  external data reflected unsanitised",
                    severity="Medium",
                    endpoint=path,
                    method=method,
                    evidence={
                        "detection": "generic (reflection probe)",
                        "marker": marker,
                        "reflected": True,
                        "raw_html_survived": raw_tag_reflected,
                        "response_preview": (text or "")[:300],
                        "expected": "validate/encode consumed data",
                        "actual": "injected payload reflected"
                                  + (" with raw HTML intact" if raw_tag_reflected else ""),
                    },
                    description=(
                        f"The endpoint {method} {path} consumes external/third-party data and "
                        f"reflected an injected payload"
                        + (" without output encoding (raw HTML preserved)" if raw_tag_reflected
                           else "") +
                        f", risking propagation of malicious data from a compromised upstream service."
                    ),
                    remediation="Validate, sanitise, and output-encode data received from external services before use.",
                    confidence="High" if raw_tag_reflected else "Medium",
                )
                self.print_finding(self.findings[-1])
