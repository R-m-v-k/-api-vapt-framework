# comparison/burp_parser.py
# Parses Burp Suite XML report and extracts findings
# Maps Burp issue names to OWASP API Top 10 categories

import xml.etree.ElementTree as ET
import json
import os
from typing import List, Dict


class BurpParser:
    """
    Parses Burp Suite Community Edition report files.
    Maps Burp issue types to OWASP API Top 10 categories.

    Export from Burp Suite:
    Target -> Site Map -> Right-click -> Issues -> Report Issues
    Format: XML
    """

    BURP_TO_OWASP = {
        # API2 - Broken Authentication
        "authentication bypass":                        "API2:2023",
        "broken authentication":                        "API2:2023",
        "session token in url":                         "API2:2023",
        "weak session token":                           "API2:2023",
        "cleartext submission of password":             "API2:2023",
        "password field with autocomplete":             "API2:2023",
        "ssl certificate":                              "API2:2023",

        # API3 - Excessive Exposure
        "sensitive data in url":                        "API3:2023",
        "email addresses disclosed":                    "API3:2023",
        "private ip addresses disclosed":               "API3:2023",
        "credit card numbers disclosed":                "API3:2023",
        "social security numbers disclosed":            "API3:2023",

        # API7 - SSRF
        "server-side request forgery":                  "API7:2023",
        "ssrf":                                         "API7:2023",
        "out-of-band resource load":                    "API7:2023",

        # API8 - Security Misconfiguration
        "clickjacking":                                 "API8:2023",
        "frameable response":                           "API8:2023",
        "strict transport security not enforced":       "API8:2023",
        "content type incorrectly stated":              "API8:2023",
        "cross-origin resource sharing":                "API8:2023",
        "cors":                                         "API8:2023",
        "http trace method":                            "API8:2023",
        "http options":                                 "API8:2023",
        "verbose error message":                        "API8:2023",
        "directory listing":                            "API8:2023",
        "server-side template injection":               "API8:2023",

        # API10 - Unsafe Consumption
        "cross-site scripting":                         "API10:2023",
        "reflected xss":                                "API10:2023",
        "stored xss":                                   "API10:2023",
        "dom-based xss":                                "API10:2023",
        "sql injection":                                "API10:2023",
        "blind sql injection":                          "API10:2023",
        "xml injection":                                "API10:2023",
        "ldap injection":                               "API10:2023",
        "os command injection":                         "API10:2023",
        "path traversal":                               "API10:2023",
        "file path traversal":                          "API10:2023",
        "external service interaction":                 "API10:2023",
    }

    BURP_SEVERITY_MAP = {
        "High":          "High",
        "Medium":        "Medium",
        "Low":           "Low",
        "Information":   "Info",
        "Informational": "Info",
    }

    def parse(self, report_path: str) -> List[Dict]:
        """Parse a Burp Suite XML report."""
        if not os.path.exists(report_path):
            print(f"  [!] Burp report not found: {report_path}")
            return []

        ext = os.path.splitext(report_path)[1].lower()

        try:
            if ext == ".xml":
                return self._parse_xml(report_path)
            elif ext == ".json":
                return self._parse_json(report_path)
            else:
                return self._parse_xml(report_path)
        except Exception as e:
            print(f"  [!] Burp parse error: {e}")
            return []

    def _parse_xml(self, path: str) -> List[Dict]:
        """Parse Burp XML report."""
        findings = []
        try:
            tree = ET.parse(path)
            root = tree.getroot()

            # Burp XML structure: <issues><issue>...</issue></issues>
            issues = root.findall(".//issue") or root.findall("issue")

            for issue in issues:
                name = self._get_text(issue, "name") or self._get_text(issue, "type") or ""
                severity = self._get_text(issue, "severity") or "Low"
                confidence = self._get_text(issue, "confidence") or "Tentative"
                desc = self._get_text(issue, "issueDetail") or self._get_text(issue, "detail") or ""
                background = self._get_text(issue, "issueBackground") or ""
                remediation = self._get_text(issue, "remediationBackground") or ""
                url = self._get_text(issue, "url") or self._get_text(issue, "location") or ""
                host = self._get_text(issue, "host") or ""
                path_val = self._get_text(issue, "path") or ""

                # Build full URL if needed
                if host and path_val and not url:
                    url = host + path_val

                owasp_id = self._map_to_owasp(name, desc)
                sev = self.BURP_SEVERITY_MAP.get(severity, "Low")

                findings.append({
                    "tool": "Burp Suite Community",
                    "title": name,
                    "severity": sev,
                    "owasp_id": owasp_id,
                    "endpoint": url,
                    "method": "GET",
                    "description": (desc or background)[:300],
                    "solution": remediation[:200],
                    "evidence": "",
                    "burp_severity": severity,
                    "burp_confidence": confidence,
                })

        except Exception as e:
            print(f"  [!] Burp XML parse error: {e}")

        return findings

    def _parse_json(self, path: str) -> List[Dict]:
        """Parse Burp JSON export."""
        findings = []
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)

            issues = data if isinstance(data, list) else data.get("issues", [])

            for issue in issues:
                name = issue.get("issue_type", {}).get("name", "") or issue.get("name", "")
                severity = issue.get("severity", "Low")
                desc = issue.get("description", issue.get("detail", ""))
                url = issue.get("origin", "") + issue.get("path", "")

                owasp_id = self._map_to_owasp(name, desc)
                sev = self.BURP_SEVERITY_MAP.get(severity, "Low")

                findings.append({
                    "tool": "Burp Suite Community",
                    "title": name,
                    "severity": sev,
                    "owasp_id": owasp_id,
                    "endpoint": url,
                    "method": "GET",
                    "description": str(desc)[:300],
                    "solution": "",
                    "evidence": "",
                    "burp_severity": severity,
                })

        except Exception as e:
            print(f"  [!] Burp JSON parse error: {e}")

        return findings

    def _get_text(self, element, tag: str) -> str:
        child = element.find(tag)
        return child.text.strip() if child is not None and child.text else ""

    def _map_to_owasp(self, name: str, desc: str = "") -> str:
        """Map Burp issue name to OWASP API Top 10."""
        name_lower = name.lower()
        desc_lower = desc.lower()

        for issue_name, owasp_id in self.BURP_TO_OWASP.items():
            if issue_name in name_lower or issue_name in desc_lower:
                return owasp_id

        return "UNMAPPED"
