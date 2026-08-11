# comparison/zap_parser.py
# Parses OWASP ZAP XML/HTML report and extracts findings
# Maps ZAP alert names to OWASP API Top 10 categories

import xml.etree.ElementTree as ET
import json
import os
from typing import List, Dict, Optional


class ZAPParser:
    """
    Parses OWASP ZAP report files and maps findings
    to OWASP API Security Top 10 (2023) categories.

    Supports:
    - ZAP XML report (.xml)
    - ZAP JSON report (.json)
    """

    # ZAP alert name -> OWASP API Top 10 mapping
    ZAP_TO_OWASP = {
        # API2 - Broken Authentication
        "absence of anti-csrf tokens":              "API2:2023",
        "cookie no httponly flag":                  "API2:2023",
        "cookie without secure flag":               "API2:2023",
        "session id in url rewrite":                "API2:2023",
        "weak authentication method":               "API2:2023",
        "authentication credentials captured":      "API2:2023",
        "username hash found":                      "API2:2023",
        "password autocomplete in browser":         "API2:2023",

        # API3 - Broken Object Property Level Auth
        "information disclosure":                   "API3:2023",
        "information disclosure - debug error":     "API3:2023",
        "information disclosure - sensitive info":  "API3:2023",
        "private ip disclosure":                    "API3:2023",
        "email address found":                      "API3:2023",

        # API4 - Rate Limiting
        "absence of anti-automation controls":      "API4:2023",
        "re-examine cache-control directives":      "API4:2023",

        # API7 - SSRF
        "server side request forgery":              "API7:2023",
        "ssrf":                                     "API7:2023",

        # API8 - Security Misconfiguration
        "x-content-type-options header missing":    "API8:2023",
        "x-frame-options header not set":           "API8:2023",
        "content security policy header not set":   "API8:2023",
        "cross-domain misconfiguration":            "API8:2023",
        "cors misconfiguration":                    "API8:2023",
        "strict-transport-security header not set": "API8:2023",
        "server leaks information via http":        "API8:2023",
        "server leaks version info via http":       "API8:2023",
        "application error disclosure":             "API8:2023",
        "debug error message":                      "API8:2023",
        "directory browsing":                       "API8:2023",

        # API9 - Inventory
        "timestamp disclosure":                     "API9:2023",

        # API10 - Unsafe Consumption
        "cross site scripting":                     "API10:2023",
        "sql injection":                            "API10:2023",
        "injection":                                "API10:2023",

        # Risk-based mappings
        "high": "API8:2023",
    }

    ZAP_RISK_TO_SEVERITY = {
        "High":   "High",
        "Medium": "Medium",
        "Low":    "Low",
        "Informational": "Info",
        "3": "High",
        "2": "Medium",
        "1": "Low",
        "0": "Info",
    }

    def parse(self, report_path: str) -> List[Dict]:
        """
        Parse a ZAP report file and return structured findings.
        Auto-detects XML or JSON format.
        """
        if not os.path.exists(report_path):
            print(f"  [!] ZAP report not found: {report_path}")
            return []

        ext = os.path.splitext(report_path)[1].lower()

        if ext == ".xml":
            return self._parse_xml(report_path)
        elif ext == ".json":
            return self._parse_json(report_path)
        else:
            # Try XML first
            try:
                return self._parse_xml(report_path)
            except Exception:
                try:
                    return self._parse_json(report_path)
                except Exception as e:
                    print(f"  [!] Cannot parse ZAP report: {e}")
                    return []

    def _parse_xml(self, path: str) -> List[Dict]:
        """Parse ZAP XML report format."""
        findings = []
        try:
            tree = ET.parse(path)
            root = tree.getroot()

            # Handle both report formats
            alerts = root.findall(".//alertitem") or root.findall(".//alert")

            for alert in alerts:
                name = self._get_text(alert, "alert") or self._get_text(alert, "name") or ""
                risk = self._get_text(alert, "riskdesc") or self._get_text(alert, "risk") or "Low"
                desc = self._get_text(alert, "desc") or self._get_text(alert, "description") or ""
                solution = self._get_text(alert, "solution") or ""
                url = self._get_text(alert, "uri") or self._get_text(alert, "url") or ""
                method = self._get_text(alert, "method") or "GET"
                evidence = self._get_text(alert, "evidence") or ""
                cweid = self._get_text(alert, "cweid") or ""

                # Extract risk level
                risk_str = risk.split(" ")[0] if " " in risk else risk
                severity = self.ZAP_RISK_TO_SEVERITY.get(risk_str, "Low")

                # Map to OWASP API Top 10
                owasp_id = self._map_to_owasp(name, desc, cweid)

                findings.append({
                    "tool": "OWASP ZAP",
                    "title": name,
                    "severity": severity,
                    "owasp_id": owasp_id,
                    "endpoint": url,
                    "method": method,
                    "description": desc[:300],
                    "solution": solution[:200],
                    "evidence": evidence[:200],
                    "zap_risk": risk,
                    "cwe_id": cweid,
                })

        except Exception as e:
            print(f"  [!] ZAP XML parse error: {e}")

        return findings

    def _parse_json(self, path: str) -> List[Dict]:
        """Parse ZAP JSON report format."""
        findings = []
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)

            # Navigate ZAP JSON structure
            sites = data.get("site", [])
            if isinstance(sites, dict):
                sites = [sites]

            for site in sites:
                alerts = site.get("alerts", [])
                for alert in alerts:
                    name = alert.get("alert", alert.get("name", ""))
                    risk = alert.get("riskdesc", alert.get("risk", "Low"))
                    desc = alert.get("desc", alert.get("description", ""))
                    solution = alert.get("solution", "")
                    cweid = str(alert.get("cweid", ""))

                    risk_str = risk.split(" ")[0] if " " in str(risk) else str(risk)
                    severity = self.ZAP_RISK_TO_SEVERITY.get(risk_str, "Low")
                    owasp_id = self._map_to_owasp(name, desc, cweid)

                    # Get instances/URLs
                    instances = alert.get("instances", [{}])
                    url = instances[0].get("uri", "") if instances else ""
                    method = instances[0].get("method", "GET") if instances else "GET"

                    findings.append({
                        "tool": "OWASP ZAP",
                        "title": name,
                        "severity": severity,
                        "owasp_id": owasp_id,
                        "endpoint": url,
                        "method": method,
                        "description": str(desc)[:300],
                        "solution": str(solution)[:200],
                        "evidence": "",
                        "zap_risk": risk,
                        "cwe_id": cweid,
                    })

        except Exception as e:
            print(f"  [!] ZAP JSON parse error: {e}")

        return findings

    def _get_text(self, element, tag: str) -> str:
        child = element.find(tag)
        return child.text.strip() if child is not None and child.text else ""

    def _map_to_owasp(self, name: str, desc: str, cwe: str) -> str:
        """Map ZAP alert to OWASP API Top 10 category."""
        name_lower = name.lower()
        desc_lower = desc.lower()

        # Direct name match
        for alert_name, owasp_id in self.ZAP_TO_OWASP.items():
            if alert_name in name_lower:
                return owasp_id

        # Description match
        for alert_name, owasp_id in self.ZAP_TO_OWASP.items():
            if len(alert_name) > 5 and alert_name in desc_lower:
                return owasp_id

        # CWE-based mapping
        cwe_map = {
            "284": "API1:2023", "285": "API1:2023",  # Access Control
            "287": "API2:2023", "306": "API2:2023",  # Authentication
            "200": "API3:2023", "213": "API3:2023",  # Information Exposure
            "770": "API4:2023", "400": "API4:2023",  # Resource Consumption
            "269": "API5:2023",                       # Privilege Management
            "918": "API7:2023",                       # SSRF
            "16":  "API8:2023", "693": "API8:2023",  # Configuration
            "79":  "API10:2023", "89": "API10:2023", # Injection
        }
        if cwe in cwe_map:
            return cwe_map[cwe]

        return "UNMAPPED"
