# core/endpoint_loader.py   User-Supplied Endpoint Loader v1.0
#
# Lets ASTRA test any API when no OpenAPI spec is served, by reading
# the real routes from a file the user provides at scan time.
#
# Supported inputs (auto-detected):
#   1. Plain text   (.txt)  one route per line
#         /add-product
#         POST /delete-product
#         GET /users/{id}
#   2. JSON simple  (.json)  a list of path strings
#         ["/add-product", "POST /delete-product", "/users/{id}"]
#   3. JSON rich    (.json)  a list of objects with per-endpoint detail
#         [{"path":"/delete-product","method":"POST","id_param":"id"}, ...]
#   4. Postman collection export (.json)  raw v2.1 collection; requests
#         are walked recursively and converted to endpoints.
#
# Every loader returns the SAME endpoint dict shape the rest of the
# framework already consumes (see discovery._parse_openapi_spec), so the
# detection modules need no changes.

import json
import os
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse

_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
_ID_WORDS = ["id", "uuid", "vid", "key", "guid", "_id", "objectid", "pk"]


def _looks_like_id(name: str) -> bool:
    n = (name or "").lower()
    return any(w in n for w in _ID_WORDS)


def _extract_path_params(path: str) -> List[str]:
    """Pull {id}, :id and <id> style path variables out of a route."""
    params = []
    params += re.findall(r"\{([^}/]+)\}", path)          # {id}
    params += re.findall(r":([A-Za-z_][A-Za-z0-9_]*)", path)  # :id
    params += re.findall(r"<([^>/]+)>", path)             # <id>
    # strip type hints like <int:id>
    cleaned = []
    for p in params:
        cleaned.append(p.split(":")[-1] if ":" in p else p)
    return cleaned


def _normalise_path(raw: str) -> str:
    """Accept a full URL or a bare path; always return a leading-slash path."""
    raw = raw.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        raw = urlparse(raw).path or "/"
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw


def _make_endpoint(path: str, method: str = "GET",
                   id_param: Optional[str] = None,
                   requires_auth: bool = True,
                   summary: str = "") -> Dict:
    path = _normalise_path(path)
    path_params = _extract_path_params(path)
    if id_param and id_param not in path_params:
        path_params.append(id_param)
    has_id = bool(id_param) or any(_looks_like_id(p) for p in path_params)
    return {
        "path": path,
        "method": (method or "GET").upper(),
        "operation_id": "",
        "summary": summary or "User-supplied endpoint",
        "tags": [],
        "path_params": path_params,
        "requires_auth": requires_auth,
        "has_id_param": has_id,
        "source": "user_file",
    }


def _parse_line(line: str) -> Optional[Dict]:
    """
    Parse one text line. Accepts:
        /add-product
        POST /delete-product
        GET  /users/{id}
        POST /delete-product   id      (3rd token = id param name)
    Blank lines and lines starting with # are ignored.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    method, path, id_param = "GET", None, None
    if parts[0].upper() in _METHODS:
        method = parts[0].upper()
        rest = parts[1:]
    else:
        rest = parts
    if not rest:
        return None
    path = rest[0]
    if len(rest) > 1:                 # optional explicit id-param name
        id_param = rest[1]
    return _make_endpoint(path, method, id_param)


def _from_text(text: str) -> List[Dict]:
    out = []
    for line in text.splitlines():
        ep = _parse_line(line)
        if ep:
            out.append(ep)
    return out


def _from_json_list(data: list) -> List[Dict]:
    out = []
    for item in data:
        if isinstance(item, str):
            # "POST /path" or "/path"
            ep = _parse_line(item)
            if ep:
                out.append(ep)
        elif isinstance(item, dict):
            path = item.get("path") or item.get("url") or item.get("endpoint")
            if not path:
                continue
            out.append(_make_endpoint(
                path,
                method=item.get("method", "GET"),
                id_param=item.get("id_param") or item.get("id"),
                requires_auth=item.get("requires_auth", True),
                summary=item.get("summary", "User-supplied endpoint"),
            ))
    return out


def _walk_postman(items, out):
    """Recursively walk a Postman v2.1 collection's item tree."""
    for it in items or []:
        if "item" in it:                       # folder
            _walk_postman(it["item"], out)
            continue
        req = it.get("request")
        if not req:
            continue
        method = req.get("method", "GET")
        url = req.get("url", {})
        if isinstance(url, str):
            path = url
        else:
            raw = url.get("raw", "")
            segs = url.get("path")
            if segs:
                path = "/" + "/".join(
                    s if isinstance(s, str) else s.get("value", "") for s in segs
                )
            else:
                path = raw
        # Postman marks variables as :var  keep them; _make_endpoint handles it
        out.append(_make_endpoint(path, method,
                                  summary=it.get("name", "Postman request")))


def _from_postman(data: dict) -> List[Dict]:
    out = []
    _walk_postman(data.get("item", []), out)
    return out


def load_endpoints_file(file_path: str) -> List[Dict]:
    """
    Auto-detect the format of a user endpoints file and return a list of
    endpoint dicts in the framework's standard shape.
    Raises FileNotFoundError / ValueError with clear messages on bad input.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Endpoints file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        raw = f.read()

    stripped = raw.strip()
    endpoints: List[Dict] = []

    # Try JSON first if it looks like JSON, regardless of extension
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as e:
            raise ValueError(f"File looks like JSON but failed to parse: {e}")
        if isinstance(data, list):
            endpoints = _from_json_list(data)
        elif isinstance(data, dict):
            # Postman collection?  (has "info" + "item")
            if "item" in data and ("info" in data or "variable" in data):
                endpoints = _from_postman(data)
            # An OpenAPI-ish object with "paths"?
            elif "paths" in data and isinstance(data["paths"], dict):
                for path, methods in data["paths"].items():
                    for method, details in (methods or {}).items():
                        if method.lower() in [m.lower() for m in _METHODS]:
                            det = details if isinstance(details, dict) else {}
                            pp = [p.get("name") for p in det.get("parameters", [])
                                  if p.get("in") == "path"]
                            ep = _make_endpoint(path, method,
                                                summary=det.get("summary", ""))
                            for p in pp:
                                if p and p not in ep["path_params"]:
                                    ep["path_params"].append(p)
                                    if _looks_like_id(p):
                                        ep["has_id_param"] = True
                            endpoints.append(ep)
            else:
                # a single endpoint object
                endpoints = _from_json_list([data])
        else:
            raise ValueError("Unsupported JSON structure for endpoints file.")
    else:
        # Plain text, one route per line
        endpoints = _from_text(stripped)

    # De-duplicate on (method, path)
    seen = set()
    unique = []
    for e in endpoints:
        key = (e["method"], e["path"])
        if key not in seen:
            seen.add(key)
            unique.append(e)

    if not unique:
        raise ValueError(
            "No endpoints could be read from the file. Expected one route "
            "per line (.txt) or a JSON list of paths/objects (.json)."
        )
    return unique


def merge_endpoints(*lists) -> List[Dict]:
    """Merge multiple endpoint lists, de-duplicating on (method, path).
    Earlier lists win on metadata (user file first, probing second)."""
    seen = set()
    merged = []
    for lst in lists:
        for e in lst or []:
            key = (e.get("method", "GET"), e.get("path"))
            if key not in seen:
                seen.add(key)
                merged.append(e)
    return merged
