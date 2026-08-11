# base_module.py
# Base class for all OWASP detection modules

from typing import List, Dict, Optional
from core.requester import Requester
from core.auth_handler import AuthHandler


class Finding:
    """Represents a single vulnerability finding."""

    SEVERITY_SCORES = {
        "Critical": 9.0,
        "High": 7.5,
        "Medium": 5.0,
        "Low": 3.0,
        "Info": 1.0,
    }

    def __init__(
        self,
        owasp_id: str,
        title: str,
        severity: str,
        endpoint: str,
        method: str,
        evidence: Dict,
        description: str,
        remediation: str,
        confidence: str = "High",
    ):
        self.owasp_id = owasp_id
        self.title = title
        self.severity = severity
        self.cvss_score = self.SEVERITY_SCORES.get(severity, 5.0)
        self.endpoint = endpoint
        self.method = method
        self.evidence = evidence
        self.description = description
        self.remediation = remediation
        self.confidence = confidence

    def to_dict(self) -> Dict:
        return {
            "owasp_id": self.owasp_id,
            "title": self.title,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "endpoint": self.endpoint,
            "method": self.method,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "confidence": self.confidence,
        }


class BaseModule:
    """
    Base class for all OWASP API Top 10 detection modules.
    Each module inherits from this and implements run().
    """

    OWASP_ID = ""
    OWASP_NAME = ""

    def __init__(self, requester: Requester, auth: AuthHandler, config):
        self.requester = requester
        self.auth = auth
        self.config = config
        self.findings: List[Finding] = []

    def add_finding(
        self,
        title: str,
        severity: str,
        endpoint: str,
        method: str,
        evidence: Dict,
        description: str,
        remediation: str,
        confidence: str = "High",
        owasp_id: str = None,
    ):
        finding = Finding(
            owasp_id=owasp_id or self.OWASP_ID,
            title=title,
            severity=severity,
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            description=description,
            remediation=remediation,
            confidence=confidence,
        )
        self.findings.append(finding)
        return finding

    def print_finding(self, finding: Finding):
        icons = {
            "Critical": "*",
            "High": "*",
            "Medium": "*",
            "Low": "*",
            "Info": "*",
        }
        icon = icons.get(finding.severity, "*")
        print(f"    {icon} [{finding.severity}] {finding.title}")
        print(f"       Endpoint : {finding.method} {finding.endpoint}")
        print(f"       CVSS     : {finding.cvss_score}")
        print(f"       Confidence: {finding.confidence}")

    def run(self, endpoints=None) -> List[Finding]:
        """Override in each module."""
        raise NotImplementedError

    def get_results(self) -> Dict:
        return {
            "owasp_id": self.OWASP_ID,
            "owasp_name": self.OWASP_NAME,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
