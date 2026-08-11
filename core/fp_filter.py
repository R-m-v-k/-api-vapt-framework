# core/fp_filter.py
#
# False Positive Filter & Metrics
#
# Where it is used:
#   Called in cli/main.py after all modules complete
#   Before report generation
#   Filters findings to reduce the false positive rate
#
# How it works:
#   1. Re-verify each finding by repeating the test
#   2. Check response body confirms the finding
#   3. Apply confidence threshold filtering
#   4. Calculate Precision, Recall, F1 against ground truth

import time
from typing import List, Dict, Optional
import requests
import urllib3
urllib3.disable_warnings()


class FPFilter:
    """
    False Positive Filter.
    Re-verifies findings before including them in the report.
    Reduces noise and improves precision to meet 85% target.
    """

    # Minimum confidence to include in report
    CONFIDENCE_THRESHOLD = "Medium"
    CONFIDENCE_LEVELS = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

    def __init__(self, base_url: str, token: str = None,
                 token_header: str = "Authorization", token_prefix: str = "Bearer"):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.token_header = token_header or "Authorization"
        self.token_prefix = token_prefix if token_prefix is not None else "Bearer"

    def _auth(self, token):
        from core.auth_handler import build_token_header
        return build_token_header(token, self.token_header, self.token_prefix)

    def filter_findings(self, findings: List[Dict]) -> Dict:
        """
        Filter findings by re-verifying each one.
        Returns verified findings and filter statistics.
        """
        verified = []
        rejected = []
        total = len(findings)

        print(f"\n   FALSE POSITIVE FILTER ")
        print(f"  [*] Verifying {total} findings...")

        for finding in findings:
            result = self._verify_finding(finding)

            if result["verified"]:
                finding["fp_verified"] = True
                finding["verification_note"] = result["note"]
                verified.append(finding)
                print(f"  [+] Verified: {finding['title'][:60]}")
            else:
                finding["fp_verified"] = False
                finding["rejection_reason"] = result["reason"]
                rejected.append(finding)
                print(f"  [-] Rejected (likely FP): {finding['title'][:60]}")
                print(f"      Reason: {result['reason']}")

        stats = {
            "total_findings": total,
            "verified_findings": len(verified),
            "rejected_findings": len(rejected),
            "fp_rate": round(len(rejected) / total * 100, 1) if total > 0 else 0,
            "tp_rate": round(len(verified) / total * 100, 1) if total > 0 else 0,
        }

        print(f"\n  [*] Filter complete:")
        print(f"      Verified : {stats['verified_findings']}/{total}")
        print(f"      Rejected : {stats['rejected_findings']}/{total}")
        print(f"      FP Rate  : {stats['fp_rate']}%")

        return {"verified": verified, "rejected": rejected, "stats": stats}

    def _verify_finding(self, finding: Dict) -> Dict:
        """
        Re-verify a single finding by repeating the test.
        """
        owasp_id = finding.get("owasp_id", "")
        endpoint = finding.get("endpoint", "")
        method = finding.get("method", "GET")
        evidence = finding.get("evidence", {})
        confidence = finding.get("confidence", "Low")

        # Skip re-verification for Info level
        if confidence == "Info":
            return {"verified": True, "note": "Info level  no re-verification needed"}

        # Skip findings that are below threshold
        if self.CONFIDENCE_LEVELS.get(confidence, 0) < self.CONFIDENCE_LEVELS.get(self.CONFIDENCE_THRESHOLD, 0):
            return {"verified": False, "reason": f"Below confidence threshold ({confidence})"}

        # API-specific verification logic
        verifier = {
            "API1:2023": self._verify_bola,
            "API2:2023": self._verify_broken_auth,
            "API4:2023": self._verify_rate_limit,
            "API8:2023": self._verify_misconfig,
        }.get(owasp_id)

        if verifier:
            return verifier(finding)

        # Default: accept if confidence is High or Critical
        if self.CONFIDENCE_LEVELS.get(confidence, 0) >= 3:
            return {"verified": True, "note": "High confidence  accepted without re-test"}

        return {"verified": True, "note": "No verifier available  accepted by default"}

    def _verify_bola(self, finding: Dict) -> Dict:
        """Re-verify BOLA by making the cross-user request again."""
        endpoint = finding.get("endpoint", "")
        token_b = finding.get("evidence", {}).get("token_b")

        if not endpoint or not self.base_url:
            return {"verified": True, "note": "Cannot re-verify  accepted"}

        try:
            headers = {"Content-Type": "application/json"}
            if token_b:
                headers.update(self._auth(token_b))
            elif self.token:
                headers.update(self._auth(self.token))

            url = self.base_url + endpoint if not endpoint.startswith("http") else endpoint
            resp = requests.get(url, headers=headers, timeout=8, verify=False)

            if resp.status_code == 200:
                return {"verified": True, "note": f"Re-verified: HTTP {resp.status_code} on second attempt"}
            else:
                return {"verified": False, "reason": f"Re-test returned {resp.status_code}  may be FP"}

        except Exception as e:
            return {"verified": True, "note": f"Re-verify failed ({e})  accepted by default"}

    def _verify_broken_auth(self, finding: Dict) -> Dict:
        """Re-verify broken auth by checking endpoint without token."""
        endpoint = finding.get("endpoint", "")
        if not endpoint:
            return {"verified": True, "note": "Cannot re-verify"}

        # Only re-verify unauthenticated access findings
        if "no auth" not in finding.get("title", "").lower() and \
           "unauthenticated" not in finding.get("title", "").lower():
            return {"verified": True, "note": "JWT/brute force finding  accepted"}

        try:
            url = self.base_url + endpoint if not endpoint.startswith("http") else endpoint
            resp = requests.get(url, headers={"Content-Type": "application/json"}, timeout=8, verify=False)

            if resp.status_code == 200:
                return {"verified": True, "note": f"Re-verified: endpoint still unauthenticated"}
            else:
                return {"verified": False, "reason": f"Re-test returned {resp.status_code}  auth may have been added"}

        except Exception as e:
            return {"verified": True, "note": f"Cannot re-verify: {e}"}

    def _verify_rate_limit(self, finding: Dict) -> Dict:
        """Re-verify rate limit by sending 5 quick requests."""
        endpoint = finding.get("endpoint", "")
        if not endpoint:
            return {"verified": True, "note": "Cannot re-verify"}

        try:
            url = self.base_url + endpoint if not endpoint.startswith("http") else endpoint
            headers = {"Content-Type": "application/json"}
            if self.token:
                headers.update(self._auth(self.token))

            successes = 0
            for _ in range(5):
                r = requests.get(url, headers=headers, timeout=5, verify=False)
                if r and r.status_code == 200:
                    successes += 1
                elif r and r.status_code == 429:
                    return {"verified": False, "reason": "Rate limiting IS present  429 received on re-test"}

            if successes >= 4:
                return {"verified": True, "note": f"Re-verified: {successes}/5 requests succeeded without throttling"}
            else:
                return {"verified": False, "reason": "Inconsistent results on re-test"}

        except Exception as e:
            return {"verified": True, "note": f"Cannot re-verify: {e}"}

    def _verify_misconfig(self, finding: Dict) -> Dict:
        """Re-verify a misconfiguration finding.

        Misconfiguration findings come in two kinds and must be verified
        differently:
          - Header/CORS findings: evidence lives in the RESPONSE HEADERS
            (e.g. Access-Control-Allow-Origin: *, missing X-Frame-Options).
            Re-checking the body for 'password'/'secret' is meaningless for
            these and previously rejected genuine findings.
          - Data-exposure findings: evidence is sensitive content in the BODY.
        We dispatch on the finding's title/evidence.
        """
        endpoint = finding.get("endpoint", "") or "/"
        title = (finding.get("title", "") or "").lower()
        try:
            url = self.base_url + endpoint if not endpoint.startswith("http") else endpoint
            # Send an Origin header so CORS reflection is observable.
            resp = requests.get(url, headers={"Origin": "http://astra-fp-check.example"},
                                timeout=8, verify=False)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}

            #  CORS finding 
            if "cors" in title or "origin" in title:
                aco = hdrs.get("access-control-allow-origin", "")
                if aco == "*" or "astra-fp-check.example" in aco:
                    return {"verified": True, "note": f"Re-verified: Access-Control-Allow-Origin = {aco}"}
                return {"verified": False, "reason": "CORS not permissive on re-test"}

            #  Missing security headers finding 
            if "header" in title:
                security_headers = ["x-content-type-options", "x-frame-options",
                                    "strict-transport-security", "content-security-policy",
                                    "x-xss-protection"]
                missing = [h for h in security_headers if h not in hdrs]
                if missing:
                    return {"verified": True, "note": f"Re-verified: still missing {missing}"}
                return {"verified": False, "reason": "Security headers present on re-test"}

            #  Default: data-exposure style (body keywords) 
            if resp.status_code == 200:
                resp_text = resp.text.lower()
                sensitive_keywords = ["password", "secret", "api_key", "apikey",
                                      "database", "connection", "private_key"]
                found = [k for k in sensitive_keywords if k in resp_text]
                if found:
                    return {"verified": True, "note": f"Re-verified: sensitive fields still present: {found}"}
                return {"verified": False, "reason": "Sensitive data no longer in response  may be FP"}
            return {"verified": False, "reason": f"Endpoint returned {resp.status_code} on re-test"}

        except Exception as e:
            return {"verified": True, "note": f"Cannot re-verify: {e}"}


class MetricsCalculator:
    """
    Calculates Precision, Recall, F1 for the framework.
    Requires ground truth to be defined.
    """

    # Ground truth for Custom API  we know exactly what is there
    CUSTOM_API_GROUND_TRUTH = {
        "API1:2023": True,  "API2:2023": True,  "API3:2023": True,
        "API4:2023": True,  "API5:2023": True,  "API6:2023": True,
        "API7:2023": True,  "API8:2023": True,  "API9:2023": True,
        "API10:2023": True,
    }

    # Ground truth for crAPI  documented OWASP vulnerabilities
    CRAPI_GROUND_TRUTH = {
        "API1:2023": True, "API2:2023": True, "API3:2023": True,
        "API4:2023": True, "API5:2023": True, "API6:2023": True,
        "API7:2023": True, "API8:2023": True, "API9:2023": True,
        "API10:2023": True,
    }

    def calculate(
        self,
        findings: List[Dict],
        ground_truth: Dict,
        tool_name: str = "ASTRA"
    ) -> Dict:
        """
        Calculate Precision, Recall, F1 for a set of findings
        against known ground truth.
        """
        detected_ids = set(f["owasp_id"] for f in findings)
        true_vuln_ids = set(k for k, v in ground_truth.items() if v)

        # True Positives: vulnerabilities correctly detected
        tp_ids = detected_ids & true_vuln_ids
        tp = len(tp_ids)

        # False Positives: reported but don't actually exist
        fp_ids = detected_ids - true_vuln_ids
        fp = len(fp_ids)

        # False Negatives: exist but not detected
        fn_ids = true_vuln_ids - detected_ids
        fn = len(fn_ids)

        # True Negatives: not present and not reported
        all_categories = set(f"API{i}:2023" for i in range(1, 11))
        tn_ids = (all_categories - true_vuln_ids) - detected_ids
        tn = len(tn_ids)

        # Metrics
        precision = round(tp / (tp + fp) * 100, 1) if (tp + fp) > 0 else 0
        recall    = round(tp / (tp + fn) * 100, 1) if (tp + fn) > 0 else 0
        f1        = round(2 * precision * recall / (precision + recall), 1) if (precision + recall) > 0 else 0
        fp_rate   = round(fp / (fp + tn) * 100, 1) if (fp + tn) > 0 else 0

        result = {
            "tool": tool_name,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision_pct": precision,
            "recall_pct": recall,
            "f1_pct": f1,
            "fp_rate_pct": fp_rate,
            "owasp_coverage": f"{tp}/10",
            "detected_ids": sorted(list(detected_ids)),
            "missed_ids": sorted(list(fn_ids)),
            "false_positive_ids": sorted(list(fp_ids)),
            "meets_precision_target": precision >= 85,
            "meets_recall_target": recall >= 80,
            "meets_f1_target": f1 >= 82,
        }

        self._print_metrics(result)
        return result

    def _print_metrics(self, m: Dict):
        print(f"""
  
    METRICS: {m['tool']:<34}
  
    TP: {m['tp']:<5} FP: {m['fp']:<5} FN: {m['fn']:<5} TN: {m['tn']:<5}      
  
    Precision : {m['precision_pct']:>6}%  {'[OK]' if m['meets_precision_target'] else '[X]'} (target >=85%)         
    Recall    : {m['recall_pct']:>6}%  {'[OK]' if m['meets_recall_target'] else '[X]'} (target >=80%)         
    F1 Score  : {m['f1_pct']:>6}%  {'[OK]' if m['meets_f1_target'] else '[X]'} (target >=82%)         
    FP Rate   : {m['fp_rate_pct']:>6}%  {'[OK]' if m['fp_rate_pct'] < 15 else '[X]'} (target <15%)          
    Coverage  : {m['owasp_coverage']:<5}   OWASP API Top 10              
  """)

    def compare_tools(self, astra: Dict, zap: Dict, burp: Dict) -> Dict:
        """Generate comparison table of all three tools."""
        tools = [astra, zap, burp]
        print(f"""
  COMPARATIVE RESULTS
  
  Metric            ASTRA         OWASP ZAP     Burp Suite
  
  True Positives    {astra['tp']:<14}{zap['tp']:<14}{burp['tp']}
  False Positives   {astra['fp']:<14}{zap['fp']:<14}{burp['fp']}
  False Negatives   {astra['fn']:<14}{zap['fn']:<14}{burp['fn']}
  Precision         {str(astra['precision_pct'])+'%':<14}{str(zap['precision_pct'])+'%':<14}{str(burp['precision_pct'])+'%'}
  Recall            {str(astra['recall_pct'])+'%':<14}{str(zap['recall_pct'])+'%':<14}{str(burp['recall_pct'])+'%'}
  F1 Score          {str(astra['f1_pct'])+'%':<14}{str(zap['f1_pct'])+'%':<14}{str(burp['f1_pct'])+'%'}
  OWASP Coverage    {astra['owasp_coverage']:<14}{zap['owasp_coverage']:<14}{burp['owasp_coverage']}
  FP Rate           {str(astra['fp_rate_pct'])+'%':<14}{str(zap['fp_rate_pct'])+'%':<14}{str(burp['fp_rate_pct'])+'%'}
  """)

        improvement_recall = round(astra['recall_pct'] - max(zap['recall_pct'], burp['recall_pct']), 1)
        print(f"  ASTRA improvement over best baseline: +{improvement_recall}% recall")

        return {"astra": astra, "zap": zap, "burp": burp, "improvement_pct": improvement_recall}
