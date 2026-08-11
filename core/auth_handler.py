# core/auth_handler.py  Generalised Multi-User Auth v2.0
#
# Supports any API authentication format:
#   - JSON body with email/password
#   - Custom body templates from config
#   - Auto-detects token field name
#   - Supports any token prefix (Bearer, Token, JWT, etc.)

import json
import requests
import urllib3
from typing import Optional, Dict
urllib3.disable_warnings()


def build_token_header(token: str,
                       header_name: str = "Authorization",
                       prefix: str = "Bearer") -> Dict[str, str]:
    """
    Construct an auth header for ANY API scheme.

    - header_name: the HTTP header the target reads the token from.
        Default "Authorization" (the conventional bearer scheme), but many
        APIs use a custom header such as "token", "x-access-token",
        "x-auth-token", or "api-key".
    - prefix: the value prefix. Default "Bearer". Set to "" (empty) for APIs
        that expect the raw token with no scheme word, e.g. a header of
        literally  token: <jwt>.

    Examples:
        build_token_header(t)                          -> {"Authorization": "Bearer <t>"}
        build_token_header(t, "token", "")             -> {"token": "<t>"}
        build_token_header(t, "x-access-token", "")    -> {"x-access-token": "<t>"}
    """
    if not token:
        return {}
    # Treat an empty / "none" / "raw" prefix as "no scheme word"
    p = (prefix or "").strip()
    if p.lower() in ("", "none", "raw", "no", "-"):
        value = token
    else:
        value = f"{p} {token}"
    return {header_name: value}


class AuthHandler:

    def __init__(self, target_config):
        self.config = target_config
        self.token_a: Optional[str] = None
        self.token_b: Optional[str] = None
        self.token_c: Optional[str] = None
        self.token_admin: Optional[str] = None
        self.user_a_id: Optional[str] = None
        self.user_b_id: Optional[str] = None

    def _login(self, email: str, password: str, role: str = "") -> Optional[str]:
        """
        Generalised login  uses auth_body_template from config.
        Supports any API auth format.
        Auto-detects token in response.
        """
        url = self.config.base_url + self.config.auth_endpoint

        # Build body from template
        try:
            body_str = self.config.auth_body_template \
                .replace("{email}", email) \
                .replace("{username}", email) \
                .replace("{password}", password) \
                .replace("{role}", role or "")
            body = json.loads(body_str)
        except Exception:
            body = {"email": email, "password": password}

        try:
            resp = requests.post(
                url, json=body,
                headers={"Content-Type": "application/json"},
                timeout=self.config.__class__.__name__ and 10,
                verify=False,
            )
        except Exception as e:
            print(f"    [!] Login request failed: {e}")
            return None

        if resp.status_code not in [200, 201]:
            print(f"    [!] Login failed for {email}: HTTP {resp.status_code}")
            try:
                print(f"        Response: {resp.text[:150]}")
            except Exception:
                pass
            return None

        # Auto-detect token from response
        try:
            data = resp.json()
            token = self._extract_token(data)
            if token:
                return token
            print(f"    [!] Login OK but no token found in: {list(data.keys()) if isinstance(data, dict) else type(data)}")
        except Exception as e:
            print(f"    [!] Login response parse error: {e}")

        return None

    def _extract_token(self, data: dict) -> Optional[str]:
        """
        Generalised token extraction.
        Tries config token_field first, then common field names.
        """
        if not isinstance(data, dict):
            return None

        # Try configured field first
        configured = self.config.token_field
        if configured and data.get(configured):
            return str(data[configured])

        # Try all common token field names
        common_fields = [
            "token", "access_token", "accessToken",
            "jwt", "JWT", "id_token", "idToken",
            "auth_token", "authToken", "bearer",
            "Authorization", "authorization",
            "sessionToken", "session_token",
        ]
        for field in common_fields:
            if data.get(field):
                return str(data[field])

        # Try nested data/result objects
        for wrapper in ["data", "result", "response", "auth"]:
            nested = data.get(wrapper)
            if isinstance(nested, dict):
                result = self._extract_token(nested)
                if result:
                    return result

        return None

    def _extract_user_id(self, email: str) -> Optional[str]:
        """Try to get user ID after login for BOLA testing."""
        url = self.config.base_url + self.config.auth_endpoint
        body_str = self.config.auth_body_template \
            .replace("{email}", email) \
            .replace("{password}", "")
        try:
            body = json.loads(body_str)
            # Get user password from config
            for user_key in ["user_a", "user_b", "user_c", "admin"]:
                u = getattr(self.config, user_key, None)
                if u and u.email == email:
                    body_str = self.config.auth_body_template \
                        .replace("{email}", email) \
                        .replace("{password}", u.password)
                    body = json.loads(body_str)
                    break

            resp = requests.post(
                url, json=body,
                headers={"Content-Type": "application/json"},
                timeout=10, verify=False,
            )
            if resp.status_code in [200, 201]:
                data = resp.json()
                for id_field in ["user_id", "userId", "id", "account_number", "sub"]:
                    if data.get(id_field):
                        return str(data[id_field])
        except Exception:
            pass
        return None

    def initialize_sessions(self) -> bool:
        print("  [*] Initialising multi-user sessions...")

        user_a = self.config.user_a
        user_b = self.config.user_b

        if not user_a or not user_b:
            print("  [!] Need user_a and user_b in config")
            return False

        print(f"  [*] Logging in as User A ({user_a.email})...")
        self.token_a = self._login(user_a.email, user_a.password, user_a.role or "")
        print(f"  [{'+'if self.token_a else '!'}] User A: {'authenticated' if self.token_a else 'FAILED'}")

        print(f"  [*] Logging in as User B ({user_b.email})...")
        self.token_b = self._login(user_b.email, user_b.password, user_b.role or "")
        print(f"  [{'+'if self.token_b else '!'}] User B: {'authenticated' if self.token_b else 'FAILED'}")

        if self.config.user_c:
            self.token_c = self._login(self.config.user_c.email, self.config.user_c.password, self.config.user_c.role or "")
            print(f"  [{'+'if self.token_c else '!'}] User C: {'authenticated' if self.token_c else 'FAILED'}")

        if self.config.admin:
            self.token_admin = self._login(self.config.admin.email, self.config.admin.password, self.config.admin.role or "")
            print(f"  [{'+'if self.token_admin else '!'}] Admin: {'authenticated' if self.token_admin else 'FAILED'}")

        if self.token_a and self.token_b:
            # Try to get user IDs for BOLA evidence
            self.user_a_id = self._extract_user_id(user_a.email)
            self.user_b_id = self._extract_user_id(user_b.email)
            print("  [+] Multi-user session manager ready\n")
            return True

        print("  [!] Authentication failed  check credentials in config.yaml")
        return False

    def get_token(self, user: str) -> Optional[str]:
        return {
            "user_a":    self.token_a,
            "user_b":    self.token_b,
            "user_c":    self.token_c,
            "admin":     self.token_admin,
        }.get(user)

    def get_auth_header(self, user: str) -> Dict:
        token = self.get_token(user)
        if not token:
            return {}
        header_name = getattr(self.config, "token_header", "Authorization") or "Authorization"
        prefix = self.config.token_prefix if self.config.token_prefix is not None else "Bearer"
        return build_token_header(token, header_name, prefix)

    def sessions_ready(self) -> bool:
        return bool(self.token_a and self.token_b)
