# requester.py
# Centralized HTTP request handler for ASTRA Framework
# All requests go through here for logging and control

import requests
import time
import json
from typing import Optional, Dict, Any


class Requester:
    """
    Handles all HTTP requests for the framework.
    Provides logging, retry logic, and evidence capture.
    """

    def __init__(self, base_url: str, timeout: int = 10, retry_attempts: int = 3,
                 token_header: str = "Authorization", token_prefix: str = "Bearer"):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        # Auth scheme used when a bare token is passed to send(): defaults to the
        # conventional Authorization: Bearer <t>, but is overridable per target so
        # ASTRA can test APIs that read the token from a custom header (e.g. token,
        # x-access-token) or expect the raw token with no prefix.
        self.token_header = token_header or "Authorization"
        self.token_prefix = token_prefix if token_prefix is not None else "Bearer"
        self.request_log = []

    def _build_url(self, endpoint: str) -> str:
        if endpoint.startswith("http"):
            return endpoint
        return self.base_url + endpoint

    def _log(self, method, url, headers, body, response, duration):
        """Captures request/response evidence for reporting."""
        _auth_key = getattr(self, "token_header", "Authorization").lower()
        safe_headers = {
            k: (v[:30] + "...") if k.lower() in ("authorization", _auth_key) and len(str(v)) > 30 else v
            for k, v in (headers or {}).items()
        }
        entry = {
            "method": method,
            "url": url,
            "request_headers": safe_headers,
            "request_body": body,
            "status_code": response.status_code if response else None,
            "response_body": self._safe_json(response),
            "response_headers": dict(response.headers) if response else {},
            "duration_ms": round(duration * 1000, 2),
        }
        self.request_log.append(entry)
        return entry

    def _safe_json(self, response):
        if response is None:
            return None
        try:
            return response.json()
        except Exception:
            return response.text[:500]

    def send(
        self,
        method: str,
        endpoint: str,
        token: Optional[str] = None,
        body: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None,
        raw_url: bool = False,
    ) -> Optional[requests.Response]:
        """
        Send an HTTP request with automatic retry and logging.
        """
        url = endpoint if raw_url else self._build_url(endpoint)
        req_headers = {"Content-Type": "application/json"}

        if token:
            from core.auth_handler import build_token_header
            req_headers.update(
                build_token_header(token, self.token_header, self.token_prefix)
            )
        if headers:
            req_headers.update(headers)

        last_response = None
        start = time.time()

        for attempt in range(self.retry_attempts):
            try:
                response = requests.request(
                    method=method.upper(),
                    url=url,
                    headers=req_headers,
                    json=body,
                    params=params,
                    timeout=self.timeout,
                    verify=False,
                )
                duration = time.time() - start
                self._log(method, url, req_headers, body, response, duration)
                return response

            except requests.exceptions.ConnectionError:
                if attempt == self.retry_attempts - 1:
                    print(f"    [!] Connection error: {url}")
                time.sleep(0.5)
            except requests.exceptions.Timeout:
                if attempt == self.retry_attempts - 1:
                    print(f"    [!] Timeout: {url}")
                time.sleep(0.5)
            except Exception as e:
                if attempt == self.retry_attempts - 1:
                    print(f"    [!] Request error: {e}")
                break

        duration = time.time() - start
        self._log(method, url, req_headers, body, None, duration)
        return None

    def get(self, endpoint, token=None, params=None, headers=None):
        return self.send("GET", endpoint, token=token, params=params, headers=headers)

    def post(self, endpoint, body=None, token=None, headers=None):
        return self.send("POST", endpoint, token=token, body=body, headers=headers)

    def put(self, endpoint, body=None, token=None, headers=None):
        return self.send("PUT", endpoint, token=token, body=body, headers=headers)

    def delete(self, endpoint, token=None, headers=None):
        return self.send("DELETE", endpoint, token=token, headers=headers)

    def get_last_log(self):
        return self.request_log[-1] if self.request_log else None

    def clear_log(self):
        self.request_log = []
