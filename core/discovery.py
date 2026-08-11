# discovery.py
# Endpoint Discovery Module
# Tries OpenAPI spec first, then crawls common paths

import requests
import json
from typing import List, Dict, Optional

# Common OpenAPI spec locations to check
OPENAPI_PATHS = [
    "/openapi.json",
    "/api-docs",
    "/api/docs",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/docs/openapi.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/api/openapi.json",
]

# Common API version prefixes to probe
VERSION_PREFIXES = [
    "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/api",
]

# Common endpoint suffixes to try
COMMON_ENDPOINTS = [
    "/users", "/user", "/profile", "/me",
    "/admin", "/admin/users", "/admin/dashboard",
    "/vehicles", "/vehicle",
    "/rentals", "/orders", "/items",
    "/health", "/status", "/debug", "/info",
    "/login", "/auth/login", "/signin",
    "/posts", "/community",
    "/payments", "/billing",
    "/videos", "/files", "/uploads",
]


def _is_json(text):
    """Check if text is valid JSON with content."""
    if not text or len(text.strip()) < 2:
        return False
    t = text.strip()
    return (t.startswith("{") or t.startswith("[")) and len(t) > 5


class EndpointDiscovery:
    """
    Discovers API endpoints via:
    1. OpenAPI/Swagger spec parsing (preferred)
    2. Common endpoint probing (fallback)
    """

    def __init__(self, base_url: str, token: Optional[str] = None, timeout: int = 10,
                 openapi_paths: list = None,
                 token_header: str = "Authorization", token_prefix: str = "Bearer",
                 endpoints_file: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.custom_openapi_paths = openapi_paths or []
        self.token = token
        self.timeout = timeout
        self.token_header = token_header or "Authorization"
        self.token_prefix = token_prefix if token_prefix is not None else "Bearer"
        self.endpoints_file = endpoints_file
        self.endpoints: List[Dict] = []
        self.spec_found = False

    def _auth(self, token):
        from core.auth_handler import build_token_header
        return build_token_header(token, self.token_header, self.token_prefix)

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.token:
            h.update(self._auth(self.token))
        return h

    def _get(self, path: str) -> Optional[requests.Response]:
        try:
            url = self.base_url + path
            return requests.get(
                url,
                headers=self._headers(),
                timeout=self.timeout,
                verify=False,
            )
        except Exception:
            return None

    def discover_from_spec(self) -> List[Dict]:
        """
        Tries known OpenAPI spec locations and parses if found.
        """
        print("  [*] Checking for OpenAPI/Swagger specification...")

        for path in OPENAPI_PATHS:
            resp = self._get(path)
            if resp and resp.status_code == 200:
                try:
                    spec = resp.json()
                    if "paths" in spec:
                        print(f"  [+] OpenAPI spec found at: {path}")
                        self.spec_found = True
                        return self._parse_openapi_spec(spec)
                except Exception:
                    continue

        print("  [!] No OpenAPI spec found  falling back to endpoint probing")
        return []

    def _parse_openapi_spec(self, spec: Dict) -> List[Dict]:
        """
        Parses OpenAPI spec and extracts all endpoints
        with their methods, parameters, and auth requirements.
        """
        endpoints = []
        paths = spec.get("paths", {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ["get", "post", "put", "delete", "patch"]:
                    # Extract parameters
                    params = details.get("parameters", [])
                    path_params = [
                        p["name"] for p in params
                        if p.get("in") == "path"
                    ]

                    # Check if auth is required
                    security = details.get("security", spec.get("security", []))
                    requires_auth = len(security) > 0 if security is not None else True

                    # Get tags for categorization
                    tags = details.get("tags", [])

                    endpoints.append({
                        "path": path,
                        "method": method.upper(),
                        "operation_id": details.get("operationId", ""),
                        "summary": details.get("summary", ""),
                        "tags": tags,
                        "path_params": path_params,
                        "requires_auth": requires_auth,
                        "has_id_param": any(
                            any(id_word in p.lower() for id_word in ["id", "uuid", "vid", "key"])
                            for p in path_params
                        ),
                    })

        print(f"  [+] Discovered {len(endpoints)} endpoints from spec")
        return endpoints

    def discover_by_probing(self, token: Optional[str] = None) -> List[Dict]:
        """
        Probes common endpoint patterns when no spec is available.
        """
        print("  [*] Probing common API endpoints...")
        found = []
        probe_token = token or self.token

        headers = {"Content-Type": "application/json"}
        if probe_token:
            headers.update(self._auth(probe_token))

        for prefix in [""] + VERSION_PREFIXES:
            for suffix in COMMON_ENDPOINTS:
                path = prefix + suffix
                try:
                    url = self.base_url + path
                    resp = requests.get(
                        url, headers=headers,
                        timeout=5, verify=False
                    )
                    # Skip 404 and error codes
                    if resp.status_code in [404, 405, 502, 503]:
                        continue

                    ct = resp.headers.get("Content-Type", "").lower()

                    # Skip HTML responses  SPA apps return 200 HTML for all paths
                    # We only want real API endpoints that return JSON or 401
                    if resp.status_code == 200 and "text/html" in ct:
                        continue

                    # Accept: 401 (auth required), 403 (forbidden), or 200+JSON
                    is_real = (
                        resp.status_code in [401, 403] or
                        (resp.status_code == 200 and "application/json" in ct) or
                        (resp.status_code == 200 and _is_json(resp.text))
                    )

                    if is_real:
                        found.append({
                            "path": path,
                            "method": "GET",
                            "status_code": resp.status_code,
                            "requires_auth": resp.status_code == 401,
                            "has_id_param": False,
                            "summary": f"Discovered via probing (HTTP {resp.status_code})",
                        })
                except Exception:
                    continue

        print(f"  [+] Probing found {len(found)} accessible endpoints")
        return found

    def get_endpoints_by_tag(self, tag_keyword: str) -> List[Dict]:
        """Filter endpoints by tag keyword."""
        return [
            e for e in self.endpoints
            if any(tag_keyword.lower() in t.lower() for t in e.get("tags", []))
        ]

    def get_endpoints_with_id_params(self) -> List[Dict]:
        """Returns endpoints that have ID parameters  BOLA candidates."""
        return [e for e in self.endpoints if e.get("has_id_param")]

    def get_admin_endpoints(self) -> List[Dict]:
        """Returns endpoints that appear to be admin-only  BFLA candidates."""
        return [
            e for e in self.endpoints
            if "admin" in e["path"].lower() or
               any("admin" in t.lower() for t in e.get("tags", []))
        ]

    def run(self, token: Optional[str] = None) -> List[Dict]:
        """
        Full discovery run. Sources are combined so ASTRA tests the union of:
          1. A user-supplied endpoints file (if given)   authoritative real routes
          2. A served OpenAPI/Swagger spec (if present)
          3. Common-path probing (fallback)
        Results are merged and de-duplicated on (method, path); the user file
        takes precedence on metadata. This lets ASTRA test ANY API: with a spec
        it is automatic, and without one the user provides the routes directly.
        """
        print("\n   ENDPOINT DISCOVERY ")
        if token:
            self.token = token

        from core.endpoint_loader import merge_endpoints

        user_endpoints = []
        if self.endpoints_file:
            try:
                from core.endpoint_loader import load_endpoints_file
                user_endpoints = load_endpoints_file(self.endpoints_file)
                print(f"  [+] Loaded {len(user_endpoints)} endpoint(s) from file: "
                      f"{self.endpoints_file}")
            except (FileNotFoundError, ValueError) as e:
                print(f"  [!] Could not read endpoints file  {e}")
                print("  [!] Continuing with spec/probing only.")

        # Try served spec next
        spec_endpoints = self.discover_from_spec()

        # Probe common paths only if neither of the above gave us anything,
        # OR always merge when we DO have user/spec endpoints (union behaviour).
        probe_endpoints = []
        if user_endpoints or spec_endpoints:
            # We already have real routes; probing is a light supplement.
            probe_endpoints = self.discover_by_probing(token)
        else:
            print("  [!] No spec and no endpoints file  probing common paths.")
            probe_endpoints = self.discover_by_probing(token)

        # Merge: user file first (authoritative), then spec, then probing.
        self.endpoints = merge_endpoints(user_endpoints, spec_endpoints, probe_endpoints)

        src_bits = []
        if user_endpoints: src_bits.append(f"{len(user_endpoints)} from file")
        if spec_endpoints: src_bits.append(f"{len(spec_endpoints)} from spec")
        if probe_endpoints: src_bits.append(f"{len(probe_endpoints)} from probing")
        print(f"  [+] Total unique endpoints to test: {len(self.endpoints)}"
              + (f"  ({', '.join(src_bits)})" if src_bits else ""))

        return self.endpoints
