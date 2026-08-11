# core/config.py   Generalised Config Loader v2.0
# Supports any target via config.yaml

import yaml
import os
from dataclasses import dataclass, field
from typing import Optional, List, Dict


@dataclass
class UserConfig:
    email: str
    password: str
    role: str
    vin: Optional[str] = None


@dataclass
class TargetConfig:
    base_url: str
    auth_endpoint: str
    auth_body_template: str
    token_field: str
    token_prefix: str
    target_type: str
    openapi_paths: List[str]
    token_header: str = "Authorization"
    endpoints_file: Optional[str] = None
    user_a: Optional[UserConfig] = None
    user_b: Optional[UserConfig] = None
    user_c: Optional[UserConfig] = None
    admin:  Optional[UserConfig] = None


@dataclass
class ScanConfig:
    timeout: int = 10
    retry_attempts: int = 3
    rate_limit_delay: float = 0.5
    max_concurrent_requests: int = 5
    rate_limit_test_count: int = 50
    bola_test_ids: List[int] = field(default_factory=lambda: [1,2,3,4,5])
    ssrf_payloads: List[str] = field(default_factory=list)


@dataclass
class FrameworkConfig:
    target: TargetConfig
    scanning: ScanConfig
    output_dir: str = "./reports"
    target_name: str = ""


def load_config(config_path: str, target_name: str) -> FrameworkConfig:
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, "r") as f:
        raw = yaml.safe_load(f)

    targets = raw.get("targets", {})
    if target_name not in targets:
        available = list(targets.keys())
        raise ValueError(
            f"Target '{target_name}' not found in config.\n"
            f"Available targets: {available}\n"
            f"Add a new target block to config.yaml to scan any API."
        )

    t = targets[target_name]
    users = t.get("users", {})

    def build_user(key):
        u = users.get(key)
        if not u:
            return None
        # Identity field: prefer email, fall back to username (APIs that log in
        # by username rather than email). The AuthHandler substitutes this value
        # into both {email} and {username} placeholders, so either works.
        identity = u.get("email") or u.get("username")
        if identity is None:
            raise ValueError(
                f"User '{key}' must define either 'email' or 'username' in config.yaml"
            )
        return UserConfig(
            email=identity,
            password=u["password"],
            role=u.get("role", "user"),
            vin=u.get("vin"),
        )

    target_config = TargetConfig(
        base_url=t["base_url"].rstrip("/"),
        auth_endpoint=t["auth_endpoint"],
        auth_body_template=t.get(
            "auth_body_template",
            '{"email": "{email}", "password": "{password}"}'
        ),
        token_field=t.get("token_field", "token"),
        token_prefix=t.get("token_prefix", "Bearer"),
        token_header=t.get("token_header", "Authorization"),
        endpoints_file=t.get("endpoints_file"),
        target_type=t.get("type", "generic"),
        openapi_paths=t.get("openapi_paths", [
            "/openapi.json", "/api-docs", "/swagger.json",
            "/docs/openapi.json", "/api/openapi.json",
        ]),
        user_a=build_user("user_a"),
        user_b=build_user("user_b"),
        user_c=build_user("user_c"),
        admin=build_user("admin"),
    )

    s = raw.get("scanning", {})
    scan_config = ScanConfig(
        timeout=s.get("timeout", 10),
        retry_attempts=s.get("retry_attempts", 3),
        rate_limit_delay=s.get("rate_limit_delay", 0.5),
        max_concurrent_requests=s.get("max_concurrent_requests", 5),
        rate_limit_test_count=s.get("rate_limit_test_count", 50),
        bola_test_ids=s.get("bola_test_ids", [1,2,3,4,5]),
        ssrf_payloads=s.get("ssrf_payloads", [
            "https://www.google.com",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:80",
            "http://127.0.0.1:22",
        ]),
    )

    output_dir = raw.get("reporting", {}).get("output_dir", "./reports")

    return FrameworkConfig(
        target=target_config,
        scanning=scan_config,
        output_dir=output_dir,
        target_name=target_name,
    )


def build_config_from_args(
    url: str,
    auth_endpoint: str,
    email_a: str, pass_a: str,
    email_b: str, pass_b: str,
    email_admin: str = None, pass_admin: str = None,
    token_field: str = "token",
    token_prefix: str = "Bearer",
    token_header: str = "Authorization",
    auth_body_template: str = None,
) -> FrameworkConfig:
    """
    Build a FrameworkConfig directly from CLI arguments.
    Used when --url is passed instead of --target.
    Allows scanning ANY API without editing config.yaml.
    """
    if not auth_body_template:
        auth_body_template = '{"email": "{email}", "password": "{password}"}'

    target_config = TargetConfig(
        base_url=url.rstrip("/"),
        auth_endpoint=auth_endpoint,
        auth_body_template=auth_body_template,
        token_field=token_field,
        token_prefix=token_prefix,
        token_header=token_header,
        target_type="generic",
        openapi_paths=[
            "/openapi.json", "/api-docs", "/swagger.json",
            "/docs/openapi.json", "/api/openapi.json",
            "/api/v1/openapi.json",
        ],
        user_a=UserConfig(email=email_a, password=pass_a, role="user"),
        user_b=UserConfig(email=email_b, password=pass_b, role="user"),
        admin=UserConfig(email=email_admin, password=pass_admin, role="admin")
            if email_admin and pass_admin else None,
    )

    scan_config = ScanConfig(
        bola_test_ids=[1,2,3,4,5],
        ssrf_payloads=[
            "https://www.google.com",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:80",
            "http://127.0.0.1:22",
        ],
    )

    return FrameworkConfig(
        target=target_config,
        scanning=scan_config,
        output_dir="./reports",
        target_name="custom",
    )
